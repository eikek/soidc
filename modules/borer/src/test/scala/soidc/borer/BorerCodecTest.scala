package soidc.borer

import munit.*
import soidc.borer.given
import soidc.core.*
import soidc.core.json.syntax.*
import java.time.Instant
import scodec.bits.ByteVector
import soidc.core.json.JsonValue

class BorerCodecTest extends FunSuite:

  test("decode jwt header"):
    val token =
      "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    val parts = JwtParts.unsafeFromString(token)
    val header = parts.header.as[JoseHeader].fold(throw _, identity)
    val expect =
      JoseHeader.empty.withValue("typ", "JWT".toJsonValue).withAlgorithm(Algorithm.HS256)
    assertEquals(header, expect)

  test("encode jwt header"):
    val header =
      JoseHeader.empty.withValue("typ", "JWT".toJsonValue).withAlgorithm(Algorithm.HS256)
    val json = header.toJsonUtf8
    assertEquals(json, """{"typ":"JWT","alg":"HS256"}""")

  test("decode jwt claim"):
    val token =
      "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    val parts = JwtParts.unsafeFromString(token)
    val claims = parts.claims.as[SimpleClaims].fold(throw _, identity)
    val expect = SimpleClaims.empty
      .withIssuer(StringOrUri("joe"))
      .withExpirationTime(NumericDate.instant(Instant.parse("2011-03-22T18:43:00Z")))
      .withValue("http://example.com/is_root", true.toJsonValue)
    assertEquals(claims, expect)

  test("encode claim"):
    val claim = SimpleClaims.empty
      .withIssuer(StringOrUri("joe"))
      .withExpirationTime(NumericDate.instant(Instant.parse("2011-03-22T18:43:00Z")))
      .withValue("http://example.com/is_root", true.toJsonValue)
    val expect = Base64String.unsafeOf("eyJpc3MiOiJqb2UiLCJleHAiOjEzMDA4MTkzODAsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ")
    assertEquals(Base64String.encode(claim.toJsonBytes), expect)

  test("decode obj{}"):
    val value = ByteVector.view("""{"one":1,"two":"none","flag":false}""".getBytes)
    val result = value.unsafeAs[JsonValue]
    val expect = JsonValue.obj(
      "one" -> 1.toJsonValue,
      "two" -> "none".toJsonValue,
      "flag" -> false.toJsonValue
    )
    assertEquals(result, expect)

  test("decode array[string]"):
    val value = ByteVector.view("""["one", "two"]""".getBytes)
    val result = value.unsafeAs[List[String]]
    assertEquals(result, List("one", "two"))

  test("decode double"):
    val value = ByteVector.view("15.654".getBytes)
    assertEquals(value.unsafeAs[Double], 15.654)
