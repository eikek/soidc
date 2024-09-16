package soidc.http4s.routes

import scala.concurrent.duration.*

import cats.effect.*
import cats.effect.std.Console

import com.comcast.ip4s.*
import org.http4s.*
import org.http4s.dsl.io.*
import org.http4s.ember.server.EmberServerBuilder
import org.http4s.implicits.*
import org.http4s.server.Router
import soidc.borer.given
import soidc.core.validate.JwtValidator
import soidc.jwt.*

object ExampleServer extends IOApp:
  val serverSecret =
    JWK.symmetric(Base64String.encodeString("server-secret"), Algorithm.HS256)
  val sessionValid = 2.minutes
  val localIssuer = "example-app"

  type Authenticated = JwtContext.Authenticated[JoseHeader, SimpleClaims]
  type MaybeAuthenticated = JwtContext.MaybeAuthenticated[JoseHeader, SimpleClaims]
  val withAuth = JwtAuthMiddleware
    .builder[IO, JoseHeader, SimpleClaims]
    .withGeToken(GetToken.anyOf(GetToken.cookie("auth_cookie"), GetToken.bearer))
    .withOnInvalidToken(IO.println)
    .withValidator(
      JwtValidator
        .validateWithKey[IO, JoseHeader, SimpleClaims](
          serverSecret,
          Clock[IO],
          Duration.Zero
        )
        .forIssuer(_ == localIssuer)
    )

  final case class UserPass(user: String, pass: String)
  object UserPassParam {
    def unapply(params: Map[String, collection.Seq[String]]): Option[UserPass] =
      for
        un <- params.get("user").flatMap(_.headOption)
        pw <- params.get("pass").flatMap(_.headOption)
      yield UserPass(un, pw)
  }

  def makeToken(user: String) =
    JwtCreate.default[IO](
      serverSecret,
      sessionValid,
      _.withIssuer(StringOrUri(localIssuer)).withSubject(StringOrUri(user))
    )

  def loginRoute: HttpRoutes[IO] = HttpRoutes.of {
    case GET -> Root :? UserPassParam(name, pass) =>
      if (pass != "secret") BadRequest("login failed")
      else
        for
          token <- makeToken(name)
          res <- Ok(s"welcome $name")
        yield res
          .putHeaders("Auth-Token" -> token.jws.compact)
          .addCookie(
            JwtCookie.create("auth_cookie", token.jws, uri"http://localhost:8888")
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

  def routes = Router(
    "login" -> loginRoute,
    "member" -> withAuth.secured(memberRoutes),
    "open" -> withAuth.optional(maybeMember)
  )

  def run(args: List[String]): IO[ExitCode] =
    EmberServerBuilder
      .default[IO]
      .withHost(host"0.0.0.0")
      .withPort(port"8888")
      .withHttpApp(routes.orNotFound)
      .withShutdownTimeout(Duration.Zero)
      .build
      .use(_ => Console[IO].readLine)
      .as(ExitCode.Success)
