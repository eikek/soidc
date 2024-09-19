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
import scodec.bits.*
import soidc.borer.given
import soidc.core.OpenIdConfig
import soidc.core.auth.*
import soidc.core.validate.JwtValidator
import soidc.http4s.client.ByteEntityDecoder.given
import soidc.jwt.{Uri as _, *}

object ExampleServer extends IOApp:
  // local users
  val serverSecret =
    JWK.symmetric(Base64String.encodeString("server-secret"), Algorithm.HS256)
  val sessionValid = 2.minutes
  val localIssuer = "example-app"
  val localValidator = JwtValidator
    .validateWithKey[IO, JoseHeader, SimpleClaims](
      serverSecret,
      Clock[IO],
      Duration.Zero
    )
    .forIssuer(_ == localIssuer)

  // OpenID Auth-Code-Flow with keycloak
  def authCodeFlow(client: Client[IO]) = AuthCodeFlow[IO](
    AuthCodeFlow.Config[IO](
      ClientId("example"),
      uri"http://soidccnt:8180/realms/master", // keycloak realm
      uri"http://localhost:8888/login/keycloak", // where login route is mounted
      ClientSecret("8CCr3yFDuMl3L0MgNSICXgELvuabi5si").some,
      Some(Nonce(hex"caffee")),
      Some(ScopeList(Scope.Email, Scope.Profile)),
      IO.println
    ),
    client
  )

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

  def loginRoute(codeFlow: AuthCodeFlow[IO]): HttpRoutes[IO] = HttpRoutes.of {
    case req @ GET -> "keycloak" /: _ =>
      codeFlow.run(req) {
        case Left(err) => UnprocessableEntity(err.toString())
        case Right(token) =>
          val at = token.accessToken.decode[JoseHeader, SimpleClaims].map(_.claims)
          Ok(at.toString).map(
            _.putHeaders("Auth-Token" -> token.accessToken.compact)
              .addCookie(
                JwtCookie
                  .create("auth_cookie", token.accessToken, uri"http://localhost:8888/")
                  .copy(maxAge = token.expiresIn.map(_.toSeconds))
              )
          )
      }

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

  def routes(client: Client[IO], codeFlow: AuthCodeFlow[IO]) =
    val auth = withAuth(
      localValidator.orElse(codeFlow.validator[JoseHeader, SimpleClaims])
    )
    Router(
      "login" -> loginRoute(codeFlow),
      "member" -> auth.secured(memberRoutes),
      "open" -> auth.optional(maybeMember)
    )

  def run(args: List[String]): IO[ExitCode] =
    EmberClientBuilder.default[IO].build.use { client =>
      authCodeFlow(client).flatMap { codeFlow =>
        EmberServerBuilder
          .default[IO]
          .withHost(host"0.0.0.0")
          .withPort(port"8888")
          .withHttpApp(routes(client, codeFlow).orNotFound)
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
