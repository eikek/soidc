package soidc.jwt

import munit.FunSuite

class UriTest extends FunSuite:

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
    val uris = List("", "___", "  ", "caffee", "////", "1m://test")
    uris.foreach(u => assert(Uri.fromString(u).isLeft, s"Unexpected valid uri: $u"))

  test("success on valid"):
    val uris = List("abc:test", "a:hello", "a-0-9://localhost")
    uris.foreach(u => assert(Uri.fromString(u).isRight, s"Unexpected invalid uri: $u"))
