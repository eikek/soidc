package soidc.http4s.routes

import scala.concurrent.duration.*

import cats.effect.*
import cats.effect.std.Console
import cats.syntax.all.*

import com.comcast.ip4s.*
import org.http4s.*
import org.http4s.client.Client
import org.http4s.client.dsl.io.*
import org.http4s.dsl.io.*
import org.http4s.ember.client.EmberClientBuilder
import org.http4s.ember.server.EmberServerBuilder
import org.http4s.headers.Location
import org.http4s.headers.`Content-Type`
import org.http4s.implicits.*
import org.http4s.server.Router
import soidc.borer.given
import soidc.core.OpenIdConfig
import soidc.core.auth.*
import soidc.core.validate.{JwtValidator, OpenIdJwtValidator}
import soidc.http4s.client.ByteEntityDecoder.given
import soidc.http4s.client.Http4sClient
import soidc.jwt.{Uri as JwtUri, *}

object ExampleServer extends IOApp:
  val serverSecret =
    JWK.symmetric(Base64String.encodeString("server-secret"), Algorithm.HS256)
  val sessionValid = 2.minutes
  val localIssuer = "example-app"

  // keycloak
  val baseUri = uri"http://soidccnt:8180/realms/master"
  val redirectUri = JwtUri.unsafeFromString("http://localhost:8888/login/keycloak/resume")
  val clientId = ClientId("example")
  def keycloakValidator(client: Client[IO]) = JwtValidator
    .openId[IO, JoseHeader, SimpleClaims](
      OpenIdJwtValidator.Config(),
      Http4sClient(client)
    )
    .map(_.forIssuer(_.startsWith("http://soidccnt:8180")))

  val localValidator = JwtValidator
    .validateWithKey[IO, JoseHeader, SimpleClaims](
      serverSecret,
      Clock[IO],
      Duration.Zero
    )
    .forIssuer(_ == localIssuer)

  type Authenticated = JwtContext.Authenticated[JoseHeader, SimpleClaims]
  type MaybeAuthenticated = JwtContext.MaybeAuthenticated[JoseHeader, SimpleClaims]
  def withAuth(validator: JwtValidator[IO, JoseHeader, SimpleClaims]) = JwtAuthMiddleware
    .builder[IO, JoseHeader, SimpleClaims]
    .withGeToken(GetToken.anyOf(GetToken.cookie("auth_cookie"), GetToken.bearer))
    .withOnInvalidToken(IO.println)
    .withValidator(validator)

  final case class UserPass(user: String, pass: String)
  object UserPassParam {
    def unapply(params: Map[String, collection.Seq[String]]): Option[UserPass] =
      for
        un <- params.get("user").flatMap(_.headOption)
        pw <- params.get("pass").flatMap(_.headOption)
      yield UserPass(un, pw)
  }

  def loginRoute(client: Client[IO]): HttpRoutes[IO] = HttpRoutes.of {
    case GET -> Root / "keycloak" =>
      for
        cfg <- client
          .expect[OpenIdConfig](baseUri / ".well-known" / "openid-configuration")
        req = AuthorizationRequest(clientId, redirectUri, ResponseType.Code)
        uri = Uri
          .unsafeFromString(cfg.authorizationEndpoint.value)
          .copy(query = Query.fromPairs(req.asMap.toList*))
        res <- TemporaryRedirect(Location(uri))
      yield res

    case req @ GET -> Root / "keycloak" / "resume" =>
      AuthorizationCodeResponse.read(req.params) match
        case AuthorizationCodeResponse.Result.Success(code) =>
          val req = TokenRequest.code(
            code,
            redirectUri,
            clientId,
            ClientSecret("8CCr3yFDuMl3L0MgNSICXgELvuabi5si").some
          )

          for
            cfg <- client
              .expect[OpenIdConfig](baseUri / ".well-known" / "openid-configuration")
            uri = Uri.unsafeFromString(cfg.tokenEndpoint.value)
            post = POST(req.asUrlQuery, uri).withContentType(
              `Content-Type`(MediaType.application.`x-www-form-urlencoded`)
            )
            _ <- post.bodyText.compile.string.flatMap(IO.println)
            body <- client.expect[TokenResponse](post)
            _ <- IO.println(body)
            ok <- Ok(body.toString)
          yield ok
            .putHeaders("Auth-Token" -> body.accessToken.compact)
            .addCookie(
              JwtCookie
                .create("auth_cookie", body.accessToken, uri"http://localhost:8888/")
                .copy(maxAge = body.expiresIn.map(_.toSeconds))
            )

        case AuthorizationCodeResponse.Result.Failure(err) =>
          UnprocessableEntity(err.toString())

    case GET -> Root / "local" :? UserPassParam(name, pass) =>
      if (pass != "secret") BadRequest("login failed")
      else
        for
          token <- JwtCreate.default[IO](
            serverSecret,
            sessionValid,
            _.withIssuer(StringOrUri(localIssuer)).withSubject(StringOrUri(name))
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
      Ok(s"welcome back, ${token.claims.subject}")
  }

  def maybeMember = AuthedRoutes.of[MaybeAuthenticated, IO] {
    case ContextRequest(token, GET -> Root / "test") =>
      token.claims.flatMap(_.subject) match
        case Some(s) => Ok(s"hello $s!!")
        case None    => Ok("Hello anonymous stranger!")
  }

  def routes(client: Client[IO], validator: JwtValidator[IO, JoseHeader, SimpleClaims]) =
    val auth = withAuth(validator)
    Router(
      "login" -> loginRoute(client),
      "member" -> auth.secured(memberRoutes),
      "open" -> auth.optional(maybeMember)
    )

  def run(args: List[String]): IO[ExitCode] =
    EmberClientBuilder.default[IO].build.use { client =>
      keycloakValidator(client).map(ov => localValidator.orElse(ov)).flatMap {
        validator =>
          EmberServerBuilder
            .default[IO]
            .withHost(host"0.0.0.0")
            .withPort(port"8888")
            .withHttpApp(routes(client, validator).orNotFound)
            .withShutdownTimeout(Duration.Zero)
            .withErrorHandler { ex =>
              IO.blocking(ex.printStackTrace())
                .as(Response(status = Status.InternalServerError))
            }
            .build
            .use(_ => Console[IO].readLine)
            .as(ExitCode.Success)
      }
    }
