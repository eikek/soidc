package soidc.core

import munit.*
import soidc.core.json.JsonValue
import soidc.core.json.ToJson.syntax.*

class JoseHeaderTest extends FunSuite:

  test("create header literal"):
    val header =
      JoseHeader.empty.withValue("typ", "JWT".toJsonValue).withAlgorithm(Algorithm.HS256)
    assertEquals(
      header.toJsonValue,
      JsonValue.obj("typ" -> JsonValue.str("JWT"), "alg" -> JsonValue.str("HS256"))
    )
    assertEquals(header.get[Algorithm]("alg"), Right(Some(Algorithm.HS256)))

  test("create header from obj"):
    val header = JoseHeader
      .fromObj(JsonValue.Obj(List("alg" -> JsonValue.str("HS256"))))
      .fold(throw _, identity)
    assertEquals(header.get[Algorithm]("alg"), Right(Some(Algorithm.HS256)))
    assertEquals(header, JoseHeader.empty.withAlgorithm(Algorithm.HS256))
