package soidc.borer

import munit.FunSuite
import scodec.bits.ByteVector
import soidc.jwt.*
import soidc.borer.given

class JWETest extends FunSuite with Syntax:
  val data = Rfc7516.AppendixA

  Algorithm.Encrypt.values.foreach { alg =>
    ContentEncryptionAlgorithm.values.foreach { ce =>

      test(s"encrypt data to jwe: $alg / $ce") {
        val clearText = ByteVector.view("Hello world".getBytes)
        val jwe = JWE.encrypt(alg, ce, clearText, data.rsaKey).value
//        println(jwe.compact)

        val dec = jwe.decrypt(data.rsaKey).value
//        println(dec.decodeUtf8Lenient)
        assertEquals(dec.decodeAsciiLenient, "Hello world")
      }
    }
  }
