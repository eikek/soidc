package soidc.borer

import munit.FunSuite
import scodec.bits.ByteVector
import soidc.jwt.*

class JWETest extends FunSuite with Syntax:
  val data = Rfc7516.AppendixA

  test("encrypt data to jwe"):
    val clearText = ByteVector.view("Hello world".getBytes)
    val jwe = JWE.encrypt(
      Algorithm.Encrypt.RSA_OAEP,
      ContentEncryptionAlgorithm.A256GCM,
      clearText,
      data.rsaKey
    ).value
    println(jwe.compact)

    val dec = jwe.decrypt(data.rsaKey).value
    println(dec.decodeUtf8Lenient)
