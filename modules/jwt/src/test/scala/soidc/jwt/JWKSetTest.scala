package soidc.jwt

import munit.FunSuite
import soidc.jwt.codec.JsonValue
import soidc.jwt.codec.syntax.*

class JWKSetTest extends FunSuite:

  test("toJson"):
    val jwks = JWKSet(Rfc7515.Appendix1.symmetricKey, Rfc7515.Appendix2.rsaKey)
    val json = jwks.toJsonValue
    val expect = JsonValue.obj(
      "keys" -> JsonValue.arr(
        Rfc7515.Appendix1.symmetricKey,
        Rfc7515.Appendix2.rsaKey
      )
    )
    assertEquals(json, expect)

  test("fromJson"):
    val jwks = JWKSet(Rfc7515.Appendix1.symmetricKey, Rfc7515.Appendix2.rsaKey)
    val expect = JsonValue
      .obj(
        "keys" -> JsonValue.arr(
          Rfc7515.Appendix1.symmetricKey,
          Rfc7515.Appendix2.rsaKey
        )
      )
      .unsafeAs[JWKSet]
    assertEquals(jwks, expect)
