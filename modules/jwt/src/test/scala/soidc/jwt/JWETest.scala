package soidc.jwt

import munit.*
import RegisteredParameterName as P

class JWETest extends FunSuite with Syntax:
  val data = Rfc7516.AppendixA

  test("check header"):
    assertEquals(data.joseHeader.algorithm, Some(Algorithm.Encrypt.RSA_OAEP))
    assertEquals(
      data.joseHeader.values.getAs[ContentEncryptionAlgorithm](P.Enc),
      Right(Some(ContentEncryptionAlgorithm.A256GCM))
    )

  test("init vector"):
    assertEquals(
      Base64String.encode(data.initVector),
      Base64String.unsafeOf("48V1_ALb6US04U3b")
    )

  test("encrypt/decrypt cek"):
    val decRfc = RsaOaep
      .decryptCEK1(data.contentEncKeyEncrypted.decoded.toArray, data.privateKey)
      .value
    assertEquals(decRfc, data.contentEncKeySpec)
    val encBytes = RsaOaep.encryptCEK256(data.contentEncKeySpec, data.publicKey).value
    val decKey = RsaOaep.decryptCEK256(encBytes.toArray, data.privateKey).value
    assertEquals(decKey, data.contentEncKeySpec)
