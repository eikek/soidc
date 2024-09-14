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

```scala
import soidc.jwt.*

Algorithm.values.toList
// res0: List[Algorithm] = List(
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
val jwk = JWK.symmetric(secret, Algorithm.HS256)
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
// res2: Either[VerifyError, Boolean] = Right(value = true)
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
val jwk = JWK.symmetric(Base64String.unsafeOf("dmVyeS1zZWNyZXQ"), Algorithm.HS256)
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
// res4: Either[VerifyError, Boolean] = Right(value = true)
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
val jwk = JWK.symmetric(Base64String.unsafeOf("dmVyeS1zZWNyZXQ"), Algorithm.HS256)
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
// res6: Boolean = true

val tooLate = java.time.Instant.ofEpochSecond(1603000500)
// tooLate: Instant = 2020-10-18T05:55:00Z
jwt.validate(jwk, tooLate).isValid
// res7: Boolean = false
```

### http4s-routes

This module provides routes for doing an OpenID code flow and a
middleware for verifying JWT tokens.


## Links / Literature

- Jwk (JSON Web Key) https://datatracker.ietf.org/doc/html/rfc7517
- Jwt (JSON Web Token) https://datatracker.ietf.org/doc/html/rfc7519
- Jws (JSON Web Signature) https://datatracker.ietf.org/doc/html/rfc7515#appendix-A.1
- Jwa (JSON Web Algorithms) https://datatracker.ietf.org/doc/html/rfc7518
