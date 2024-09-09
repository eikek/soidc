package soidc.core

import munit.*
import scodec.bits.{ByteVector, hex}
import soidc.core.OidcError.DecodeError
import soidc.core.json.JsonDecoder

class JwtPartTest extends FunSuite:

  test("split token"):
    val token =
      "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    val parts = JwtParts.unsafeFromString(token)
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
    val parts = JwtParts.unsafeFromString(token)
    assertEquals(parts.header.decodedUtf8.noWhitespace, """{"typ":"JWT","alg":"HS256"}""")
    assertEquals(
      parts.claims.decodedUtf8.noWhitespace,
      """{"iss":"joe","exp":1300819380,"http://example.com/is_root":true}"""
    )

  test("fail when no base64"):
    val token = "1.2.3"
    assert(JwtParts.fromString(token).isLeft)

  test("fail if no dot"):
    assert(JwtParts.fromString("uiaeuaieu").isLeft)

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
    val parts = JwtParts.unsafeFromString(token)
    val result = parts.header.as[JoseHeader].fold(throw _, identity)
    assertEquals(result, header)

  extension (self: String) def noWhitespace = self.replaceAll("\\s+", "")
