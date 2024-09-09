package soidc.core

import munit.*
import soidc.core.json.JsonValue
import soidc.core.json.FromJson.syntax.*

class FromJsonTest extends FunSuite:

  test("decode array[json]"):
    val value = JsonValue.arr(JsonValue.str("one"), JsonValue.str("two"))
    val result = value.unsafeAs[List[String]]
    assertEquals(result, List("one", "two"))

  test("decode double"):
    val value = JsonValue.num(BigDecimal(15.654))
    assertEquals(value.unsafeAs[Double], 15.654)
