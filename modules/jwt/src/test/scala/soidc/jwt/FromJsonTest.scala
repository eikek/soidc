package soidc.jwt

import munit.*
import soidc.jwt.json.FromJson.syntax.*
import soidc.jwt.json.JsonValue

class FromJsonTest extends FunSuite:

  test("decode array[json]"):
    val value = JsonValue.arr(JsonValue.str("one"), JsonValue.str("two"))
    val result = value.unsafeAs[List[String]]
    assertEquals(result, List("one", "two"))

  test("decode double"):
    val value = JsonValue.num(BigDecimal(15.654))
    assertEquals(value.unsafeAs[Double], 15.654)
