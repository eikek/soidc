package soidc.jwt

import munit.*
import scodec.bits.{ByteVector, hex}
import soidc.jwt.OidcError.DecodeError
import soidc.jwt.json.JsonDecoder

class JWSTest extends FunSuite:

  test("split token"):
    val token =
      "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    val parts = JWS.unsafeFromString(token)
    assertEquals(parts.header.decodedUtf8.noWhitespace, """{"typ":"JWT","alg":"HS256"}""")
    assertEquals(
      parts.claims.decodedUtf8.noWhitespace,
      """{"iss":"joe","exp":1300819380,"http://example.com/is_root":true}"""
    )
    assertEquals(
      parts.signature.get.decoded,
      hex"7418dfb49799e0254ffa607dd8adbbba16d4254d69d6bff05b58055853848d79"
    )

  test("split token, no signature"):
    val token =
      "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    val parts = JWS.unsafeFromString(token)
    assertEquals(parts.header.decodedUtf8.noWhitespace, """{"typ":"JWT","alg":"HS256"}""")
    assertEquals(
      parts.claims.decodedUtf8.noWhitespace,
      """{"iss":"joe","exp":1300819380,"http://example.com/is_root":true}"""
    )

  test("fail when no base64"):
    val token = "1.2.3"
    assert(JWS.fromString(token).isLeft)

  test("fail if no dot"):
    assert(JWS.fromString("uiaeuaieu").isLeft)

  test("decode value"):
    val header = JoseHeader.empty.withAlgorithm(Algorithm.HS256)
    given JsonDecoder[JoseHeader] = JsonDecoder.instance(bv =>
      Either.cond(
        bv == ByteVector.fromValidBase64("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"),
        header,
        DecodeError("wrong")
      )
    )
    val token =
      "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    val parts = JWS.unsafeFromString(token)
    val result = parts.header.as[JoseHeader].fold(throw _, identity)
    assertEquals(result, header)

  test("Create JWS with symmetric signature"):
    val jws = JWS(
      Base64String.unsafeOf("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"),
      Base64String.unsafeOf(
        "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
      ),
      None
    )
    val jwk = JWK(KeyType.OCT).withValue(
      ParameterName.of("k"),
      Base64String.unsafeOf(
        "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
      )
    )

    val secret = jwk.getSymmetricHmacKey(Algorithm.HS256).fold(throw _, identity)
    val mac = javax.crypto.Mac.getInstance(secret.getAlgorithm())
    mac.init(secret)
    mac.update(jws.compact.getBytes())
    val sig = Base64String.encode(ByteVector.view(mac.doFinal()))
    assertEquals(
      sig,
      Base64String.unsafeOf("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
    )

  extension (self: String) def noWhitespace = self.replaceAll("\\s+", "")
