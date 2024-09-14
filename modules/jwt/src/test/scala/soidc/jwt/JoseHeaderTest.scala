package soidc.jwt

import munit.*
import soidc.jwt.RegisteredParameterName as P
import soidc.jwt.json.JsonValue
import soidc.jwt.json.ToJson.syntax.*

class JoseHeaderTest extends FunSuite:

  test("create header literal"):
    val header = JoseHeader.jwt.withAlgorithm(Algorithm.HS256)
    assertEquals(
      header.toJsonValue,
      JsonValue.obj("typ" -> JsonValue.str("JWT"), "alg" -> JsonValue.str("HS256"))
    )
    assertEquals(header.algorithm, Some(Algorithm.HS256))
    assertEquals(header.values.requireAs[Algorithm](P.Alg), Right(Algorithm.HS256))

  test("create header from obj"):
    val header = JoseHeader
      .fromObj(JsonValue.Obj(Map("alg" -> JsonValue.str("HS256"))))
      .fold(throw _, identity)
    assertEquals(header.values.requireAs[Algorithm](P.Alg), Right(Algorithm.HS256))
    assertEquals(header, JoseHeader.empty.withAlgorithm(Algorithm.HS256))

  test("remove values"):
    val header =
      JoseHeader.jwt.withAlgorithm(Algorithm.ES256).withIssuer(StringOrUri("myself"))
    assertEquals(header.algorithm, Some(Algorithm.ES256))
    assertEquals(header.issuer, Some(StringOrUri("myself")))
    val algRemoved = header.remove(P.Alg)
    val issRemoved = header.remove(P.Iss)
    assertEquals(algRemoved.algorithm, None)
    assertEquals(algRemoved.values.getAs[Algorithm](P.Alg), Right(None))
    assertEquals(algRemoved.issuer, Some(StringOrUri("myself")))
    assertEquals(issRemoved.algorithm, Some(Algorithm.ES256))
    assertEquals(issRemoved.issuer, None)
    assertEquals(issRemoved.values.getAs[StringOrUri](P.Iss), Right(None))
