package soidc.http4s.routes

import scala.concurrent.duration.*

import cats.effect.*
import cats.effect.std.Console
import cats.syntax.all.*

import com.comcast.ip4s.*
import org.http4s.*
import org.http4s.client.Client
import org.http4s.dsl.io.*
import org.http4s.ember.client.EmberClientBuilder
import org.http4s.ember.server.EmberServerBuilder
import org.http4s.implicits.*
import org.http4s.server.Router
import soidc.borer.given
import soidc.core.model.*
import soidc.core.{AuthorizationCodeFlow as ACF, *}
import soidc.http4s.client.ByteEntityDecoder.given
import soidc.http4s.client.Http4sClient
import soidc.jwt.{Uri as _, *}

object ExampleServer extends IOApp:
  // fixing types
  type LocalUserFlow = LocalFlow[IO, JoseHeader, SimpleClaims]
  type OpenIdFlow = AuthCodeFlow[IO, JoseHeader, SimpleClaims]
  type Authenticated = JwtContext.Authenticated[JoseHeader, SimpleClaims]
  type MaybeAuthenticated = JwtContext[JoseHeader, SimpleClaims]
  type ExampleAppRealm = Realm[IO, JoseHeader, SimpleClaims]

  // local users
  val localFlow: IO[LocalUserFlow] =
    JwkGenerate.symmetric[IO](16).map { key =>
      LocalFlow[IO, JoseHeader, SimpleClaims](
        LocalFlow.Config(
          issuer = StringOrUri("example-app-local"),
          secretKey = key,
          sessionValidTime = 10.minutes
        )
      )
    }
  //// Fa9PRaVrgBZ4DmmwReU7bNEycNyxqGRu
  // OpenID Auth-Code-Flow with keycloak
  def authCodeFlow(
      client: Client[IO],
      tokenStore: TokenStore[IO, JoseHeader, SimpleClaims]
  ): IO[OpenIdFlow] =
    for
      key <- JwkGenerate.symmetric[IO](16)
      cfg = AuthCodeFlow.Config(
        uri"http://localhost:8888/login/keycloak", // where login route is mounted
        "resume" // path segment to receive the openid redirect request
      )
      acfCfg = ACF.Config(
        ClientId("example"),
        ClientSecret("8CCr3yFDuMl3L0MgNSICXgELvuabi5si").some,
        cfg.redirectUri.asJwtUri, // redirect to this uri
        uri"http://soidccnt:8180/realms/master".asJwtUri, // keycloak realm
        key, // for checking state parameter
        Some(ScopeList(Scope.Email, Scope.Profile))
      )
      logger = Logger.stderr[IO]
      acf <- ACF(acfCfg, Http4sClient(client), tokenStore, logger)
      oid <- AuthCodeFlow[IO, JoseHeader, SimpleClaims](cfg, acf, logger)
    yield oid

  /** Builds a middleware for authenticating requests based on a provided JWT token
    * (either via cookie or the Authorization header).
    */
  def withAuth(realm: ExampleAppRealm) = JwtAuthMiddleware
    .builder[IO, JoseHeader, SimpleClaims]
    .withGeToken(GetToken.anyOf(GetToken.cookie("auth_cookie"), GetToken.bearer))
    .withOnInvalidToken(IO.println)
    .withValidator(realm.validator)
    .withRefresh(
      realm.jwtRefresh,
      _.updateCookie("auth_cookie", uri"http://localhost:8888")
    )

  final case class UserPass(user: String, pass: String)
  object UserPassParam {
    def unapply(params: Map[String, collection.Seq[String]]): Option[UserPass] =
      for
        un <- params.get("user").flatMap(_.headOption)
        pw <- params.get("pass").flatMap(_.headOption)
      yield UserPass(un, pw)
  }

  def loginRoute(codeFlow: OpenIdFlow, localFlow: LocalUserFlow): HttpRoutes[IO] =
    HttpRoutes.of {
      case req @ GET -> "keycloak" /: _ =>
        codeFlow.run(req) {
          case Left(err) => UnprocessableEntity(err.toString())
          case Right(AuthCodeFlow.Result.Success(at, tokenResp)) =>
            for
              resp <- Ok(at.toString)
              rr = resp
                .putHeaders("Auth-Token" -> at.compact)
                .addCookie(
                  JwtCookie
                    .create("auth_cookie", at.jws, uri"http://localhost:8888/")
                    .copy(maxAge = at.claims.expirationTime.map(_.toSeconds))
                )
            yield rr
        }

      case GET -> Root / "local" :? UserPassParam(name, pass) =>
        if (pass != "secret") BadRequest("login failed")
        else
          for
            token <- localFlow.createToken(
              JoseHeader.jwt,
              SimpleClaims.empty.withSubject(StringOrUri(name))
            )
            res <- Ok(s"welcome $name")
          yield res
            .putHeaders("Auth-Token" -> token.jws.compact)
            .addCookie(
              JwtCookie
                .create("auth_cookie", token.jws, uri"http://localhost:8888/")
                .copy(maxAge = token.claims.expirationTime.map(_.toSeconds))
            )
    }

  def memberRoutes = AuthedRoutes.of[Authenticated, IO] {
    case ContextRequest(token, GET -> Root / "test") =>
      Ok(
        s"welcome back, ${token.claims.subject}, valid until ${token.claims.expirationTime
            .map(_.asInstant)}"
      )
  }

  def maybeMember = AuthedRoutes.of[MaybeAuthenticated, IO] {
    case ContextRequest(ctx, req @ GET -> Root / "test") =>
      ctx.getToken.map(_.claims) match
        case Some(c) =>
          Ok(
            s"hello ${c.subject}!! You have time until ${c.expirationTime.map(_.asInstant)}"
          )
        case None => Ok("Hello anonymous stranger!")
  }

  def routes(openId: OpenIdFlow, local: LocalUserFlow) =
    val auth = withAuth(local.or(openId))
    Router(
      "login" -> loginRoute(openId, local),
      "member" -> auth.secured(memberRoutes),
      "open" -> auth.optional(maybeMember)
    )

  def run(args: List[String]): IO[ExitCode] =
    EmberClientBuilder.default[IO].build.use { client =>
      for
        tokenStore <- TokenStore.memory[IO, JoseHeader, SimpleClaims]
        openId <- authCodeFlow(client, tokenStore)
        local <- localFlow
        server <- EmberServerBuilder
          .default[IO]
          .withHost(host"0.0.0.0")
          .withPort(port"8888")
          .withHttpApp(routes(openId, local).orNotFound)
          .withShutdownTimeout(Duration.Zero)
          .withErrorHandler { ex =>
            IO.blocking(ex.printStackTrace())
              .as(Response(status = Status.InternalServerError))
          }
          .build
          .use(_ => Console[IO].readLine)
      yield ExitCode.Success
    }
