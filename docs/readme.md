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
respectively, to use the interesting features of this modue, like
signature validation. For a simple start, concrete types `JoseHeader`
and `SimpleClaims` are provided.

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
validate these against a given (current) time.

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
jwt.validate(jwk, tooLate)
```

### http4s-routes

This module provides routes for doing an OpenID code flow and a
middleware for verifying JWT tokens.


## Links / Literature

- Jwk (JSON Web Key) https://datatracker.ietf.org/doc/html/rfc7517
- Jwt (JSON Web Token) https://datatracker.ietf.org/doc/html/rfc7519
- Jws (JSON Web Signature) https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.1
- Jwa (JSON Web Algorithms) https://datatracker.ietf.org/doc/html/rfc7518
