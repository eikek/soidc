package soidc.jwt

import munit.*
import soidc.jwt.json.JsonValue
import soidc.jwt.json.ToJson.syntax.*
import soidc.jwt.RegisteredParameterName as P

class JoseHeaderTest extends FunSuite:

  test("create header literal"):
    val header = JoseHeader.jwt.withAlgorithm(Algorithm.HS256)
    assertEquals(
      header.toJsonValue,
      JsonValue.obj("typ" -> JsonValue.str("JWT"), "alg" -> JsonValue.str("HS256"))
    )
    assertEquals(header.get[Algorithm](P.Alg), Right(Some(Algorithm.HS256)))

  test("create header from obj"):
    val header = JoseHeader
      .fromObj(JsonValue.Obj(Map("alg" -> JsonValue.str("HS256"))))
      .fold(throw _, identity)
    assertEquals(header.get[Algorithm](P.Alg), Right(Some(Algorithm.HS256)))
    assertEquals(header, JoseHeader.empty.withAlgorithm(Algorithm.HS256))
