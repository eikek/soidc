# soidc

A Scala 3 library for adding OpenID support to your projects.


## Modules

### jwt

The `jwt` module is the center of this library. It only has one
(small) dependency to `scodec-bits`. It provides creating and
validating [JWT](https://datatracker.ietf.org/doc/html/rfc7519)s in
form of a [JWS](https://datatracker.ietf.org/doc/html/rfc7515).

The header and claims structure are abstract and users need to provide
an implementation of `StandardHeader` and `StandardClaims`,
respectively, to use some features of this modue, like timing
validation. For a start, concrete types `JoseHeader` and
`SimpleClaims` are provided.

To not depend on a specific JSON library while being able to provide
some convenience, there is a small JSON AST subset defined and type
classes to decode and encode from this AST. This allows to provide a
very simple bridge using a specific JSON library to use the provided
features (as done in `soidc-borer` module). You can always choose your
own types and encoders/decodes to bypass this, though.

Keys are represented as
[JWK](https://datatracker.ietf.org/doc/html/rfc7517) that can enclose
all kind of keys. Obviously, for signing you need a private key and
for verifying the public key. Supported algorithms are:

```scala mdoc
import soidc.jwt.*

Algorithm.values.toList
```


#### Example: Verify HMAC signature

To verify the JWT signature, no JSON decoding is necessary.

```scala mdoc:reset
import soidc.jwt.*

val token = List(
  "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9",
  List(
    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQo",
    "gImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
  ).mkString,
  "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
).mkString(".")
val secret = Base64String.unsafeOf("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow")

// create a JWS and a JWK
val jws = JWS.unsafeFromString(token)
val jwk = JWK.symmetric(secret, Algorithm.HS256)

// verify signature
jws.verifySignature(jwk)
```

#### Example: Creating a signed JWT

```scala mdoc:reset
import soidc.jwt.*

val unsignedJws = JWS(
  Base64String.encodeString("""{"alg":"HS256"}"""),
  Base64String.encodeString("""{"iss":"myself"}""")
)
val jwk = JWK.symmetric(Base64String.unsafeOf("dmVyeS1zZWNyZXQ"), Algorithm.HS256)
val Right(signedJws) = unsignedJws.signWith(jwk)
signedJws.verifySignature(jwk)
```

#### Example: Validating a JWT

While signature verification can be done without knowing the payload,
validation requires to read the claims. When the `exp` (expiration
time) or `nbf` (not before) claims are present, they are used to
validate these against a given (current) time. This example uses the
`soidc-borer` module to parse the JSON payloads of the given JWT.

```scala mdoc:reset
import soidc.jwt.*
import soidc.borer.given

val token = List(
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
  "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE2MDAwMTAwMDAsIm5iZiI6MTYwMDAwMDAwMH0",
  "-5CpNDe2NCAZfAYYCBgiHvZzFDNGpIX2pUmgJhfLqgA"
).mkString(".")
val jwk = JWK.symmetric(Base64String.unsafeOf("dmVyeS1zZWNyZXQ"), Algorithm.HS256)
val jwt = JWSDecoded.unsafeFromString[JoseHeader, SimpleClaims](token)

val currentTime = java.time.Instant.ofEpochSecond(1600000500)
jwt.validate(jwk, currentTime).isValid

val tooLate = java.time.Instant.ofEpochSecond(1603000500)
jwt.validate(jwk, tooLate).isValid
```

### core

The `core` module provides a composable `JwtValidator`. It is based on
the `jwt` module cats-effect. A `JwtValidator` defines a way to
validate a token (given as a `JWSDecoded` value). A `JwtValidator`
either returns whether the input is valid, or it may choose to not
process the input. This allows to chain multiple validators each for a
specific JWT (like per issuer).

#### `OpenIdJwtValidator`

The main implementation is the `OpenIdJwtValidator`. During
validation, it will fetch the `.well-known/openid-configuration` from
a provider (obtained via the issuer claim) to get the `jwks` for
verifying the signature using the public key from the providers JWK
set. This requires to list a set of allowed issuers via its
configuration!

If validation fails for the first time, a new `JWKSet` is tried to
fetch and then tried again (keys could have been rotated).

Instead of obtaining the openid-config uri from the issuer in the jwt,
the uri can also be given at construction time.

The example demonstrates the use with a dummy http-client, the
`http4s-client` module provides an implementation based on http4s.
When using this config, you should restrict this validator to a
trusted set of issuer urls as done with `.forIssuer` in the example.

```scala mdoc:reset
import soidc.jwt.*
import soidc.jwt.json.syntax.*
import soidc.borer.given
import soidc.core.*
import cats.effect.*
import cats.effect.unsafe.implicits.*

def createJWS(claims: SimpleClaims, kid: String = "key1"): (DefaultJWS, JWK) =
  val alg = Algorithm.HS256
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
val dummyUri = "dummy:".uri
val client = HttpClient.fromMap[IO](
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

// create validator with default config that looks up an openid-configuration
// by appending '.well-known/openid-configuration' to the issuer url of the jwt
val cfg = OpenIdJwtValidator.Config()
val validator = JwtValidator
  .openId[IO, JoseHeader, SimpleClaims](cfg, client)
  .map(_.forIssuer(_.startsWith("http://issuer"))) // restrict this to the a known issuer
  .unsafeRunSync()

validator.validate(jws).unsafeRunSync() == Some(Validate.Result.success)

val (otherJws, _) = createJWS(SimpleClaims.empty.withIssuer(StringOrUri("http://other")))
validator.validate(otherJws).unsafeRunSync() == None
```

### http4s-routes

This module provides routes for doing an OpenID code flow and a
middleware for verifying JWT tokens.

```scala mdoc:reset
import cats.effect.*
import cats.effect.unsafe.implicits.*

import org.http4s.*
import org.http4s.implicits.*
import org.http4s.dsl.io.*
import org.http4s.headers.Authorization
import org.http4s.server.AuthMiddleware

import soidc.borer.given
import soidc.core.JwtValidator
import soidc.http4s.routes.JwtAuth
import soidc.http4s.routes.JwtContext.*
import soidc.jwt.*


type Context = Authenticated[JoseHeader, SimpleClaims]

val testRoutes = AuthedRoutes.of[Context, IO] {
  case ContextRequest(context, GET -> Root / "test") =>
    Ok(context.token.claims.subject.map(_.value).getOrElse(""))
}

val validator = JwtValidator.alwaysValid[IO, JoseHeader, SimpleClaims]
val withAuth = AuthMiddleware(
  JwtAuth.builder[IO, JoseHeader, SimpleClaims] // capture types here
    .withBearerToken  // get the token from "Authorization Bearer …"
    .withValidator(validator) // use this validator
    .withOnInvalidToken(IO.println) // print to stdout in case of error
    .secured  // valid token must exist and, use .optional to allow non-authenticated requests
)
val httpApp = withAuth(testRoutes).orNotFound

// create sample request
val jws =
  JWS(Base64String.encodeString("{}"), Base64String.encodeString("""{"sub":"me"}"""))
val req = Request[IO](uri = uri"/test").withHeaders(
  Authorization(Credentials.Token(AuthScheme.Bearer, jws.compact))
)

val res = httpApp.run(req).unsafeRunSync()


```

## Links / Literature

- Jwa (JSON Web Algorithms) https://datatracker.ietf.org/doc/html/rfc7518
