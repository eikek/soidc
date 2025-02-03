package soidc.jwt

import munit.FunSuite

class UriTest extends FunSuite:
  extension (self: String) def toUri: Uri = Uri.unsafeFromString(self)

  test("addPath normalizes slashes"):
    val uris = List(
      Uri.unsafeFromString("http://test.com/"),
      Uri.unsafeFromString("http://test.com")
    )
    val paths = List("a/b", "/a/b")
    for {
      u <- uris
      p <- paths
    }
      assertEquals(u.addPath(p), Uri.unsafeFromString("http://test.com/a/b"))

  test("fail on invaid"):
    val uris = List("", "_ __", "  ", "caffee:", "//", "1m://test")
    uris.foreach(u => assert(Uri.fromString(u).isLeft, s"Unexpected valid uri: $u"))

  test("success on valid"):
    val uris = List("abc:test", "a:hello", "a-0-9://localhost")
    uris.foreach(u => assert(Uri.fromString(u).isRight, s"Unexpected invalid uri: $u"))

  test("add query params"):
    val uri = "http://abc.com".toUri
    assertEquals(uri.appendQuery(Map.empty), uri)
    assertEquals(
      uri.appendQuery(Map("state" -> "1")),
      s"${uri.value}?state=1".toUri
    )
    assertEquals(
      uri.appendQuery(Map("state" -> "a b")),
      s"${uri.value}?state=a+b".toUri
    )
    assertEquals(
      uri.appendQuery(Map("redirect_uri" -> uri.value)),
      s"${uri.value}?redirect_uri=http%3A%2F%2Fabc.com".toUri
    )
    assertEquals(
      uri.appendQuery(Map("state" -> "a b", "name" -> "jörg")),
      s"${uri.value}?state=a+b&name=j%C3%B6rg".toUri
    )
