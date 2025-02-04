package soidc.jwt

import soidc.jwt.ContentEncryptionAlgorithm as CEA
import soidc.jwt.JwtError.DecodeError
import soidc.jwt.codec.ByteEncoder

import scodec.bits.ByteVector

private[jwt] object Encrypt:

  def encrypt[H](
      header: H,
      clearText: ByteVector,
      key: JWK
  )(using henc: ByteEncoder[H], h: EncryptionHeader[H]): Either[JwtError, JWE] = {
    val headerEncoded = Base64String.encode(henc.encode(header))
    for
      alg <- h.algorithm(header).toRight(DecodeError("Missing alg parameter"))
      enc <- h.encryptionAlgorithm(header).toRight(DecodeError("Missing enc parameter"))

      (cek, iv) <- enc match
        case a: CEA.GCM =>
          val k =
            if (alg == Algorithm.Encrypt.dir) SymmetricKey.asAESSecretKey(key)
            else Right(AesGcm.generateKey(a.gcmBits))
          k.map(_ -> AesGcm.generateIV)

        case a: CEA.CBC =>
          val k =
            if (alg == Algorithm.Encrypt.dir) SymmetricKey.asAESSecretKey(key)
            else Right(AesCbc.generateKey(a.cbcBits).raw)
          k.map(_ -> AesCbc.generateIV)

      cekEncrypted <- alg match
        case Algorithm.Encrypt.dir =>
          Right(ByteVector.empty)
        case Algorithm.Encrypt.RSA_OAEP =>
          RsaKey.createPublicKey(key).flatMap(pk => RsaOaep.encryptCEK1(cek, pk))
        case Algorithm.Encrypt.RSA_OAEP_256 =>
          RsaKey.createPublicKey(key).flatMap(pk => RsaOaep.encryptCEK256(cek, pk))

      res <- enc match
        case _: CEA.GCM =>
          AesGcm.encrypt(
            cek,
            iv,
            clearText,
            ByteVector.view(headerEncoded.value.getBytes())
          )
        case _: CEA.CBC =>
          AesCbc.encryptAuthenticated(
            cek,
            iv,
            clearText,
            ByteVector.view(headerEncoded.value.getBytes())
          )
    yield JWE(
      header = headerEncoded,
      encryptedKey = Base64String.encode(cekEncrypted),
      iv = Base64String.encode(res.iv),
      cipherText = Base64String.encode(res.cipherText),
      authTag = Base64String.encode(res.authTag)
    )
  }
