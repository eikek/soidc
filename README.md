# soidc

A Scala 3 library for adding [OpenID
Connect](https://openid.net/specs/openid-connect-core-1_0.html)
support to your projects.

## Modules

### jwt

The `jwt` module is the center of this library. It only has one
(small) dependency to `scodec-bits`. It provides creating and
validating [JWT](https://datatracker.ietf.org/doc/html/rfc7519)s in
form of a [JWS](https://datatracker.ietf.org/doc/html/rfc7515) and
[JWE](https://datatracker.ietf.org/doc/html/rfc7516).

The header and claims structure are abstract and users need to provide
an implementation of `StandardHeader` and `StandardClaims`,
respectively, to use some features of this modue, like timing
validation. For a start, concrete types `JoseHeader` and
`SimpleClaims` are provided.

To not depend on a specific JSON library and being able to provide
some convenience, there is a small JSON AST subset defined and type
classes to decode and encode from this AST. This allows to provide a
simple bridge using a specific JSON library (as done in `soidc-borer`
module) to use the provided features. You can always choose your own
types and encoders/decodes to bypass this, though. Then these
decoder/encoder work on `ByteVector`, so tokens don't have to be in
JSON format in theory.

Keys are represented as
[JWK](https://datatracker.ietf.org/doc/html/rfc7517) that can enclose
all kind of keys. Obviously, for signing you need a private key and
for verifying the public key. Supported algorithms are:

```scala
import soidc.jwt.*

Algorithm.Sign.values.toList
// res0: List[Sign] = List(
//   HS256,
//   HS384,
//   HS512,
//   RS256,
//   RS384,
//   RS512,
//   ES256,
//   ES384,
//   ES512
// )
```

When using a JWE, supported algorithms for key and content encryption are:
```scala
import soidc.jwt.*

// key encryption
Algorithm.Encrypt.values.toList
// res1: List[Encrypt] = List(RSA_OAEP, RSA_OAEP_256, dir)

// content encryption
ContentEncryptionAlgorithm.values.toList
// res2: List[ContentEncryptionAlgorithm] = List(
//   A128GCM,
//   A192GCM,
//   A256GCM,
//   A128CBC_HS256,
//   A192CBC_HS384,
//   A256CBC_HS512
// )
```


A JWK can be created from a pkcs8 string or its JSON representation.

#### Example: Verify HMAC signature

To verify the JWT signature, no JSON decoding is necessary.

```scala
import soidc.jwt.*

val token = List(
  "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9",
  List(
    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQo",
    "gImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
  ).mkString,
  "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
).mkString(".")
// token: String = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
val secret = Base64String.unsafeOf("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow")
// secret: Base64String = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"

// create a JWS and a JWK
val jws = JWS.unsafeFromString(token)
// jws: JWS = JWS(
//   header = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9",
//   claims = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
//   signature = Some(value = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
// )
val jwk = JWK.symmetric(secret, Algorithm.Sign.HS256)
// jwk: JWK = JWK(
//   keyType = OCT,
//   keyUse = None,
//   keyOperation = List(),
//   keyId = None,
//   algorithm = Some(value = HS256),
//   values = Obj(
//     value = Map(
//       "k" -> Str(
//         value = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
//       ),
//       "alg" -> Str(value = "HS256")
//     )
//   )
// )

// verify signature
jws.verifySignature(jwk)
// res4: Either[VerifyError, Boolean] = Right(value = true)
```

#### Example: Creating a signed JWT

```scala
import soidc.jwt.*

val unsignedJws = JWS(
  Base64String.encodeString("""{"alg":"HS256"}"""),
  Base64String.encodeString("""{"iss":"myself"}""")
)
// unsignedJws: JWS = JWS(
//   header = "eyJhbGciOiJIUzI1NiJ9",
//   claims = "eyJpc3MiOiJteXNlbGYifQ",
//   signature = None
// )
val jwk = JWK.symmetric(Base64String.unsafeOf("dmVyeS1zZWNyZXQ"), Algorithm.Sign.HS256)
// jwk: JWK = JWK(
//   keyType = OCT,
//   keyUse = None,
//   keyOperation = List(),
//   keyId = None,
//   algorithm = Some(value = HS256),
//   values = Obj(
//     value = Map(
//       "k" -> Str(value = "dmVyeS1zZWNyZXQ"),
//       "alg" -> Str(value = "HS256")
//     )
//   )
// )
val Right(signedJws) = unsignedJws.signWith(jwk)
// signedJws: JWS = JWS(
//   header = "eyJhbGciOiJIUzI1NiJ9",
//   claims = "eyJpc3MiOiJteXNlbGYifQ",
//   signature = Some(value = "RISqPbLCm9YWIBEC90ZhoXZHuoem4_WM9T5_8NJAiwc")
// )
signedJws.verifySignature(jwk)
// res6: Either[VerifyError, Boolean] = Right(value = true)
```

#### Example: Validating a JWT

While signature verification can be done without knowing the payload,
validation requires to read the claims. When the `exp` (expiration
time) or `nbf` (not before) claims are present, they are used to
validate these against a given (current) time. This example uses the
`soidc-borer` module to parse the JSON payloads of the given JWT.

```scala
import soidc.jwt.*
import soidc.borer.given

val token = List(
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
  "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE2MDAwMTAwMDAsIm5iZiI6MTYwMDAwMDAwMH0",
  "-5CpNDe2NCAZfAYYCBgiHvZzFDNGpIX2pUmgJhfLqgA"
).mkString(".")
// token: String = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE2MDAwMTAwMDAsIm5iZiI6MTYwMDAwMDAwMH0.-5CpNDe2NCAZfAYYCBgiHvZzFDNGpIX2pUmgJhfLqgA"
val jwk = JWK.symmetric(Base64String.unsafeOf("dmVyeS1zZWNyZXQ"), Algorithm.Sign.HS256)
// jwk: JWK = JWK(
//   keyType = OCT,
//   keyUse = None,
//   keyOperation = List(),
//   keyId = None,
//   algorithm = Some(value = HS256),
//   values = Obj(
//     value = Map(
//       "k" -> Str(value = "dmVyeS1zZWNyZXQ"),
//       "alg" -> Str(value = "HS256")
//     )
//   )
// )
val jwt = JWSDecoded.unsafeFromString[JoseHeader, SimpleClaims](token)
// jwt: JWSDecoded[JoseHeader, SimpleClaims] = JWSDecoded(
//   jws = JWS(
//     header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
//     claims = "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE2MDAwMTAwMDAsIm5iZiI6MTYwMDAwMDAwMH0",
//     signature = Some(value = "-5CpNDe2NCAZfAYYCBgiHvZzFDNGpIX2pUmgJhfLqgA")
//   ),
//   header = JoseHeader(
//     algorithm = Some(value = HS256),
//     keyId = None,
//     contentType = None,
//     issuer = None,
//     subject = None,
//     audience = List(),
//     values = Obj(
//       value = Map("alg" -> Str(value = "HS256"), "typ" -> Str(value = "JWT"))
//     )
//   ),
//   claims = SimpleClaims(
//     issuer = None,
//     subject = Some(value = "1234567890"),
//     audience = List(),
//     expirationTime = Some(value = 1600010000L),
//     notBefore = Some(value = 1600000000L),
//     jwtId = None,
//     values = Obj(
//       value = HashMap(
//         "nbf" -> Num(value = 1600000000),
//         "name" -> Str(value = "John Doe"),
//         "exp" -> Num(value = 1600010000),
//         "iat" -> Num(value = 1516239022),
//         "sub" -> Str(value = "1234567890")
//       )
//     )
//   )
// )

val currentTime = java.time.Instant.ofEpochSecond(1600000500)
// currentTime: Instant = 2020-09-13T12:35:00Z
jwt.validate(jwk, currentTime).isValid
// res8: Boolean = true

val tooLate = java.time.Instant.ofEpochSecond(1603000500)
// tooLate: Instant = 2020-10-18T05:55:00Z
jwt.validate(jwk, tooLate).isValid
// res9: Boolean = false
```

### core

The `core` module provides a composable `JwtValidator`. It is based on
the `jwt` module and cats-effect. A `JwtValidator` defines a way to
validate a token (given as a `JWSDecoded` value). A `JwtValidator`
either returns whether the input is valid, or it may choose to not
process the input. This allows to chain multiple validators for a
specific use cases or stages (e.g. validating one issuer differently
than another).

#### `OpenIdJwtValidator`

The main implementation is the `OpenIdJwtValidator`. During
validation, it will fetch the `.well-known/openid-configuration` from
a provider (obtained via the issuer claim) to get the public key from
the `jwks` of that provider to verify the signature of the jwt. This
should be restricted to list a set of allowed/trusted issuers.

If validation fails for the first time, a new `JWKSet` is fetched and
verification is tried again for a second and last time (keys could
have been rotated).

Instead of obtaining the openid-config uri dynamically from the issuer
in the jwt, the uri can also be given at construction time.

The example demonstrates the use with a dummy http-client, the
`http4s-client` module provides an implementation based on http4s.
When using this config, you should restrict this validator to a
trusted set of issuer urls as done with `.forIssuer` in the example.

First some setup code:
```scala
import soidc.jwt.*
import soidc.jwt.codec.syntax.*
import soidc.borer.given
import soidc.core.{TestHttpClient, OpenIdConfig}
import soidc.core.*
import cats.effect.*
import cats.effect.unsafe.implicits.*

def createJWS(claims: SimpleClaims, kid: String = "key1"): (DefaultJWS, JWK) =
  val alg = Algorithm.Sign.HS256
  val jwk = JWK.symmetric(Base64String.encodeString("hello"), alg).withKeyId(kid.keyId)
  val jws = JWSDecoded.createSigned(
    JoseHeader.jwt.withAlgorithm(alg).withKeyId(kid.keyId),
    claims,
    jwk
  )
  jws.fold(throw _, (_, jwk))

extension (self: String)
  def uri = Uri.unsafeFromString(self)
  def keyId = KeyId.unsafeFromString(self)

val issuer = "http://issuer".uri
val (jws, jwk) = createJWS(SimpleClaims.empty.withIssuer(StringOrUri(issuer.value)))
val jwksUri = "http://jwkb".uri
val oidUri = "http://issuer/.well-known/openid-configuration".uri
val dummyUri = "dummy:none".uri
val client = TestHttpClient.fromMap[IO](
  Map(
    jwksUri -> JWKSet(jwk).toJsonValue,
    oidUri -> OpenIdConfig(
      dummyUri,
      dummyUri,
      dummyUri,
      dummyUri,
      jwksUri
    ).toJsonValue
  )
)
```

Create a validator with the default config that looks up an open-id
configuration by appending the `.well-known/openid-configuration` path
to the value of the `issuer` property in the JWT. For this it is
important to restrict the issuers to some trusted values.

```scala
val cfg = OpenIdJwtValidator.Config()
// cfg: Config = Config(
//   minRequestDelay = 5 seconds,
//   timingLeeway = 30 seconds,
//   jwksProvider = FromIssuer(path = ".well-known/openid-configuration")
// )
val validator = JwtValidator
  .openId[IO, JoseHeader, SimpleClaims](cfg, client)
  .map(_.forIssuer(_.startsWith("http://issuer"))) // restrict this to the a known issuer
  .unsafeRunSync()
// validator: JwtValidator[[A >: Nothing <: Any] =>> IO[A], JoseHeader, SimpleClaims] = soidc.core.JwtValidator$$anon$1@1b6a99e5

validator.validate(jws).unsafeRunSync() == Some(Validate.Result.success)
// res11: Boolean = true

val (otherJws, _) = createJWS(SimpleClaims.empty.withIssuer(StringOrUri("http://other")))
// otherJws: JWSDecoded[JoseHeader, SimpleClaims] = JWSDecoded(
//   jws = JWS(
//     header = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6ImtleTEifQ",
//     claims = "eyJpc3MiOiJodHRwOi8vb3RoZXIifQ",
//     signature = Some(value = "_1GHiyBB-SdzXJBXygfttbD09u9hOJ09m9Mjo5Nf-eg")
//   ),
//   header = JoseHeader(
//     algorithm = Some(value = HS256),
//     keyId = Some(value = "key1"),
//     contentType = None,
//     issuer = None,
//     subject = None,
//     audience = List(),
//     values = Obj(
//       value = Map(
//         "typ" -> Str(value = "JWT"),
//         "alg" -> Str(value = "HS256"),
//         "kid" -> Str(value = "key1")
//       )
//     )
//   ),
//   claims = SimpleClaims(
//     issuer = Some(value = "http://other"),
//     subject = None,
//     audience = List(),
//     expirationTime = None,
//     notBefore = None,
//     jwtId = None,
//     values = Obj(value = Map("iss" -> Str(value = "http://other")))
//   )
// )
validator.validate(otherJws).unsafeRunSync() == None
// res12: Boolean = true
```

#### AuthorizationCodeFlow

This supports doing the OpenID Connect "Authorization Code Flow".
Since the core module doesn't contain a http library, this provides
the necessary parts separately. It can create the URI for redirecting
the user agent and getting the access token with the response data
from the OP. The `http4s-routes` module can do the full cycle based on
`http4s`.


#### DeviceCodeFlow

OAuth2 defines the "Device Code Flow" for devices that aren't browsers
(like cli tools). This is not part of OpenID Connect, but often
needed. The `DeviceCodeFlow` trait provides this.

In needs the token endpoint as used with OpenID Connect, and also a
`deviceAuthorizationEndpoint`. The latter can be obtained from the
OpenId well-known configuration.

Example:
```scala
import cats.effect.*
import cats.data.Kleisli
import soidc.core.model.*
import soidc.jwt.Uri
import soidc.borer.given
import soidc.core.*
import soidc.http4s.client.Http4sClient

val config = DeviceCodeFlow.Config(
  deviceAuthorizationEndpoint = Uri.unsafeFromString(
    "http://soidccnt:8180/realms/master/protocol/openid-connect/auth/device"
  ),
  tokenEndpoint = Uri.unsafeFromString(
    "http://soidccnt:8180/realms/master/protocol/openid-connect/token"
  )
)

val req = DeviceCodeRequest(
  ClientId("example"),
  Some(ClientSecret("8CCr3yFDuMl3L0MgNSICXgELvuabi5si"))
)
val logger = Logger.stdout[IO]
val onPending = Kleisli(err => logger.debug(s"Authentication pending $err"))
```

With this setup, the flow can be created and "run":
```scala
val flow = Http4sClient.default[IO].map(c => DeviceCodeFlow[IO](config, c))
// flow: Resource[[A >: Nothing <: Any] =>> IO[A], DeviceCodeFlow[[A >: Nothing <: Any] =>> IO[A]]] = Bind(
//   source = Bind(
//     source = Bind(
//       source = Eval(fa = Pure(value = ())),
//       fs = org.http4s.ember.client.EmberClientBuilder$$Lambda$3729/0x00007fe908abe7a8@28b8ef94
//     ),
//     fs = cats.effect.kernel.Resource$$Lambda$3731/0x00007fe908abf9e8@46e9effd
//   ),
//   fs = cats.effect.kernel.Resource$$Lambda$3731/0x00007fe908abf9e8@1953d8e4
// )
flow.use { f =>
  f.run(req, onPending).flatMap {
    case Left(err) => sys.error(err.toString())
    case Right((dev, poll)) =>
      for
        _ <- IO.println(
          s"Visit ${dev.verificationUri} and enter code ${dev.userCode}, or go to ${dev.verificationUriComplete}"
        )
        at <- poll
        _ <- IO.println(s"Token is: $at")
      yield ()
  }
}
// res14: IO[Unit] = FlatMap(
//   ioe = Pure(value = ()),
//   f = cats.effect.kernel.Resource$$Lambda$3735/0x00007fe908ac0ef0@7a0dfef,
//   event = cats.effect.tracing.TracingEvent$StackTrace
// )
```

The result is either returning an error from the device code request
or a success response from that request which then contains the code
and verification uri to present to the user. Additionally, there is a
`F[TokenResponse]` that will periodically poll for the token (when
evaluated).

### http4s-routes

This module provides routes for doing an OpenID code flow and a
middleware for verifying JWT tokens.

#### Authenticated Requests

The `JwtAuth` object can be used to create code extracting and
validating JWTs for http4s `AuthMiddleware`. Just define routes
requiring a specific `JwtContext` and apply it to the
`AuthMiddleware`.

```scala
import cats.effect.*
import org.http4s.*
import org.http4s.dsl.io.*
import org.http4s.server.AuthMiddleware

import soidc.borer.given
import soidc.core.JwtValidator
import soidc.http4s.routes.JwtAuthMiddleware
import soidc.http4s.routes.JwtContext.*
import soidc.jwt.*

// pick a validator, here just for testing
val validator = JwtValidator.alwaysValid[IO, JoseHeader, SimpleClaims]

// create the middleware that does token validation
val withAuth = JwtAuthMiddleware.builder[IO, JoseHeader, SimpleClaims] // capture types here
  .withBearerToken  // get the token from "Authorization Bearer …"
  .withValidator(validator) // use this validator
  .withOnFailure(Response(status = Status.Unauthorized)) // response on validation failure
  .secured  // valid token must exist, use .securedOrAnonymous to allow non-authenticated requests
```

Now, `withAuth` can be used to turn the `testRoutes` into a normal
`HttpRoutes[F]` to be finally served:

```scala
import cats.effect.unsafe.implicits.*

import org.http4s.implicits.*
import org.http4s.headers.Authorization

type Context = Authenticated[JoseHeader, SimpleClaims]

// your routes requiring authenticated requests
val testRoutes = AuthedRoutes.of[Context, IO] {
  case ContextRequest(context, GET -> Root / "test") =>
    Ok(context.claims.subject.map(_.value).getOrElse(""))
}

// apply authentication code to testRoutes
val httpApp = withAuth(testRoutes).orNotFound

// create sample request
val jws =
  JWS(Base64String.encodeString("{}"), Base64String.encodeString("""{"sub":"me"}"""))
val badReq = Request[IO](uri = uri"/test")
val goodReq = badReq.withHeaders(
  Authorization(Credentials.Token(AuthScheme.Bearer, jws.compact))
)
```

```scala
val res1 = httpApp.run(badReq).unsafeRunSync()
// res1: Response[[A >: Nothing <: Any] =>> IO[A]] = (
//    = Status(code = 401),
//    = HttpVersion(major = 1, minor = 1),
//    = Headers(),
//    = Stream(..),
//    = org.typelevel.vault.Vault@54367e3e
// )
val res2 = httpApp.run(goodReq).unsafeRunSync()
// res2: Response[[A >: Nothing <: Any] =>> IO[A]] = (
//    = Status(code = 200),
//    = HttpVersion(major = 1, minor = 1),
//    = Headers(Content-Type: text/plain; charset=UTF-8, Content-Length: 2),
//    = Stream(..),
//    = org.typelevel.vault.Vault@3a35fbda
// )
```

For a more complete example, take a look at the
[`ExampleServer`](/modules/http4s-routes/src/test/scala/soidc/http4s/routes/ExampleServer.scala)
class.

## RFCs

Just a list of related RFCs for reference:

- OAuth https://datatracker.ietf.org/doc/html/rfc6749
  - Device Flow https://datatracker.ietf.org/doc/html/rfc8628
- OpenID
  - https://openid.net/specs/openid-connect-core-1_0.html
  - https://openid.net/specs/openid-connect-basic-1_0.html
  - https://openid.net/specs/openid-connect-rpinitiated-1_0.html
- JWS https://datatracker.ietf.org/doc/html/rfc7515
- JWE https://datatracker.ietf.org/doc/html/rfc7516
- JWK https://datatracker.ietf.org/doc/html/rfc7517
- JWA https://datatracker.ietf.org/doc/html/rfc7518
- JWT https://datatracker.ietf.org/doc/html/rfc7519
