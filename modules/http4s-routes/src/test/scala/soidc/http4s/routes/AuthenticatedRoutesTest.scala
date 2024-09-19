package soidc.http4s.routes

import cats.effect.*

import munit.*
import org.http4s.*
import org.http4s.dsl.io.*
import org.http4s.headers.Authorization
import org.http4s.implicits.*
import soidc.borer.given
import soidc.core.validate.JwtDecodingValidator.ValidateFailure
import soidc.core.validate.JwtValidator
import soidc.http4s.routes.JwtContext.*
import soidc.jwt.*

class AuthenticatedRoutesTest extends CatsEffectSuite:

  type Context = Authenticated[JoseHeader, SimpleClaims]

  val testRoutes = AuthedRoutes.of[Context, IO] {
    case ContextRequest(context, GET -> Root / "test") =>
      Ok(context.claims.subject.map(_.value).getOrElse(""))
  }

  val authBuilder = JwtAuthMiddleware.builder[IO, JoseHeader, SimpleClaims]

  test("valid token"):
    val jws =
      JWS(Base64String.encodeString("{}"), Base64String.encodeString("""{"sub":"me"}"""))
    val validator = JwtValidator.alwaysValid[IO, JoseHeader, SimpleClaims]
    val withAuth = authBuilder
      .withValidator(validator)
      .withBearerToken
      .withOnInvalidToken(IO.println)
      .secured

    val app = withAuth(testRoutes).orNotFound
    val req = Request[IO](uri = uri"/test").withHeaders(
      Authorization(Credentials.Token(AuthScheme.Bearer, jws.compact))
    )
    val res = app.run(req)
    res.map(_.status).assertEquals(Status.Ok)
    res.flatMap(_.bodyText.compile.string).assertEquals("me")

  test("invalid token"):
    val jws =
      JWS(Base64String.encodeString("{}"), Base64String.encodeString("""{"sub":"me"}"""))
    val validator = JwtValidator.invalid[IO, JoseHeader, SimpleClaims]()
    val error: Ref[IO, Option[ValidateFailure]] = Ref.unsafe(None)
    val withAuth = authBuilder
      .withValidator(validator)
      .withBearerToken
      .withOnInvalidToken(e => error.set(Some(e)))
      .secured

    val app = withAuth(testRoutes).orNotFound
    val req = Request[IO](uri = uri"/test").withHeaders(
      Authorization(Credentials.Token(AuthScheme.Bearer, jws.compact))
    )
    val res = app.run(req).unsafeRunSync()
    assertEquals(res.status, Status.Unauthorized)
    error.get.assert(_.isDefined)

  test("invalid token format"):
    val jws =
      JWS(
        Base64String.encodeString("not-json"),
        Base64String.encodeString("""{"sub":"me"}""")
      )
    val validator = JwtValidator.alwaysValid[IO, JoseHeader, SimpleClaims]
    val error: Ref[IO, Option[ValidateFailure]] = Ref.unsafe(None)
    val withAuth = authBuilder
      .withValidator(validator)
      .withBearerToken
      .withOnInvalidToken(e => error.set(Some(e)))
      .secured

    val app = withAuth(testRoutes).orNotFound
    val req = Request[IO](uri = uri"/test").withHeaders(
      Authorization(Credentials.Token(AuthScheme.Bearer, jws.compact))
    )
    val res = app.run(req).unsafeRunSync()
    assertEquals(res.status, Status.Unauthorized)
    error.get.assert(_.isDefined)

  // test("refresh cookie"):
  //   val jws =
  //     JWS(Base64String.encodeString("{}"), Base64String.encodeString("""{"sub":"me"}"""))
  //   val jwk = JWK.symmetric(Base64String.encodeString("hello"), Algorithm.HS256)
  //   val cookieUpdate =
  //     CookieUpdateMiddleware.default[IO]("auth-cookie", _ => uri"http://localhost", jwk)
  //   val validator = JwtValidator.alwaysValid[IO, JoseHeader, SimpleClaims]
  //   val withAuth = authBuilder
  //     .withValidator(validator)
  //     .withBearerToken
  //     .withOnInvalidToken(IO.println)
  //     .withAuthMiddleware(
  //       cookieUpdate
  //         .refresh[Authenticated[JoseHeader, SimpleClaims]](Clock[IO], 10.minutes)
  //     )
  //     .secured

  //   val app = withAuth(testRoutes).orNotFound
  //   val req = Request[IO](uri = uri"/test").withHeaders(
  //     Authorization(Credentials.Token(AuthScheme.Bearer, jws.compact))
  //   )
  //   val res = app.run(req)
  //   println(res.unsafeRunSync())
