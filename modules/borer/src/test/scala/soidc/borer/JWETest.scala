package soidc.borer

import soidc.borer.given
import soidc.jwt.*

import munit.FunSuite
import scodec.bits.ByteVector

class JWETest extends FunSuite with Syntax:
  val data = Rfc7516.AppendixA

  List(Algorithm.Encrypt.RSA_OAEP, Algorithm.Encrypt.RSA_OAEP_256).foreach { alg =>
    ContentEncryptionAlgorithm.values.foreach { ce =>
      test(s"encrypt data to jwe: $alg / $ce") {
        val clearText = ByteVector.view("Hello world".getBytes)
        val jwe = JWE.encrypt(alg, ce, clearText, data.rsaKey).value
        val dec = jwe.decrypt[JoseHeader](data.rsaKey).value
        assertEquals(dec.decodeAsciiLenient, "Hello world")
      }
    }
  }

  test("decrypt rfc example 1"):
    val dec = data.finalJWE.decrypt[JoseHeader](data.rsaKey).value
    assertEquals(dec.decodeUtf8Lenient, data.plainText)

  ContentEncryptionAlgorithm.values.foreach { ce =>
    test(s"encrypt direct: $ce"):
      val clearText = ByteVector.view("Hello world".getBytes)
      val jwk = JWK.symmetric(ce.generateKey, Algorithm.Encrypt.dir)
      val jwe = JWE.encrypt(Algorithm.Encrypt.dir, ce, clearText, jwk).value
      val dec = jwe.decrypt[JoseHeader](jwk).value
      assertEquals(dec.decodeAsciiLenient, "Hello world")
  }
