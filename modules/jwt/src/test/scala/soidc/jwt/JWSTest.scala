package soidc.jwt

import soidc.jwt.JwtError.DecodeError
import soidc.jwt.codec.ByteDecoder

import munit.*
import pdi.jwt.JwtAlgorithm
import pdi.jwt.JwtUtils
import scodec.bits.{ByteVector, hex}

class JWSTest extends FunSuite with Syntax:

  test("split token"):
    val token = List(
      "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9",
      "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
      "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    ).mkString(".")
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
    assert(parts.signature.isEmpty)

  test("split with two dots, no signature"):
    val token =
      "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
    val parts = JWS.unsafeFromString(token)
    assertEquals(parts.header.decodedUtf8.noWhitespace, """{"typ":"JWT","alg":"HS256"}""")
    assertEquals(
      parts.claims.decodedUtf8.noWhitespace,
      """{"iss":"joe","exp":1300819380,"http://example.com/is_root":true}"""
    )
    assert(parts.signature.isEmpty)

  test("fail when no base64"):
    val token = "1.2.3"
    assert(JWS.fromString(token).isLeft)

  test("fail if no dot"):
    assert(JWS.fromString("uiaeuaieu").isLeft)

  test("decode value"):
    val header = JoseHeader.empty.withAlgorithm(Algorithm.Sign.HS256)
    given ByteDecoder[JoseHeader] = ByteDecoder.instance(bv =>
      Either.cond(
        bv == ByteVector.fromValidBase64("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9"),
        header,
        DecodeError("wrong")
      )
    )
    val token = List(
      "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9",
      "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ"
    ).mkString(".")
    val parts = JWS.unsafeFromString(token)
    val result = parts.header.as[JoseHeader].value
    assertEquals(result, header)

  test("JWS with HMAC signature"):
    val data = Rfc7515.Appendix1
    val jws = JWS(data.header64, data.claim64).unsafeSignWith(data.symmetricKey)
    assertEquals(jws.signature, Some(data.signature))
    assert(
      JwtUtils.verify(
        jws.payload.toArray,
        jws.signature.get.decoded.toArray,
        data.symmetricKey.getSymmetricHmacKey.value,
        JwtAlgorithm.HS256
      )
    )
    assert(
      jws
        .verifySignature(data.symmetricKey)
        .value
    )

  test("JWS with RSA signature"):
    val data = Rfc7515.Appendix2
    val jws = JWS(data.header64, data.claim64).unsafeSignWith(data.rsaKey)
    assertEquals(jws.signature, Some(data.signature))
    assert(jws.verifySignature(data.rsaKey).value)

  test("JWS with EC signature ES256"):
    val data = Rfc7515.Appendix3
    val jws = JWS(data.header64, data.claim64).unsafeSignWith(data.ecKey)
    assert(
      JwtUtils.verify(
        jws.payload.toArray,
        jws.signature.get.decoded.toArray,
        data.ecKey.getPublicKey.value,
        JwtAlgorithm.ES256
      )
    )
    assert(
      JwtUtils.verify(
        jws.payload.toArray,
        data.signature.decoded.toArray,
        data.ecKey.getPublicKey.value,
        JwtAlgorithm.ES256
      )
    )
    assert(jws.verifySignature(data.ecKey).value)

  test("JWS with EC signature ES512"):
    val data = Rfc7515.Appendix4
    val jws = JWS(data.header64, data.claim64).unsafeSignWith(data.ecKey)
    assert(
      JwtUtils.verify(
        jws.removeSignature.compact.getBytes(),
        jws.signature.get.decoded.toArray,
        data.ecKey.getPublicKey.value,
        JwtAlgorithm.ES512
      )
    )
    assert(
      JwtUtils.verify(
        jws.removeSignature.compact.getBytes(),
        data.signature.decoded.toArray,
        data.ecKey.getPublicKey.value,
        JwtAlgorithm.ES512
      )
    )
    assert(jws.verifySignature(data.ecKey).value)

  test("imported rsa private key"):
    val jwk = JWK.rsaPrivate(KeyData.rsaPem, Algorithm.Sign.RS256).value
    val jws = JWS(
      // {"typ":"JWT","alg":"RS256"}
      Base64String.unsafeOf("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9"),
      // {"iss":"me myself"}
      Base64String.unsafeOf("eyJpc3MiOiJtZSBteXNlbGYifQ")
    ).signWith(jwk).value
    assert(jws.verifySignature(jwk).value)

  test("imported rsa public key"):
    val jwk = JWK.rsaPrivate(KeyData.rsaPem, Algorithm.Sign.RS256).value
    val jws = JWS(
      // {"typ":"JWT","alg":"RS256"}
      Base64String.unsafeOf("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9"),
      // {"iss":"me myself"}
      Base64String.unsafeOf("eyJpc3MiOiJtZSBteXNlbGYifQ")
    ).signWith(jwk).value
    assert(jws.verifySignature(jwk).value)
    val pk = JWK.rsaKey(KeyData.rsaPub, Algorithm.Sign.RS256).value
    assert(jws.verifySignature(pk).value)

  test("imported ec key".only):
    val jwk =
      JWK.ecKeyPair(KeyData.ecPrivate, KeyData.ecPublic, Algorithm.Sign.ES256).value
    val jws = JWS(
      // {"typ":"JWT","alg":"ES256"}
      Base64String.unsafeOf("eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9"),
      // {"iss":"me myself"}
      Base64String.unsafeOf("eyJpc3MiOiJtZSBteXNlbGYifQ")
    ).signWith(jwk).value
    assert(jws.verifySignature(jwk).value, "EC signature check failed")
