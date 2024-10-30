package soidc.jwt

import scodec.bits.ByteVector
import soidc.jwt.codec.ByteEncoder
import soidc.jwt.{ContentEncryptionAlgorithm as CEA, RegisteredParameterName as P}

private[jwt] object Encrypt:

  def encrypt(
      header: JoseHeader,
      clearText: ByteVector,
      key: JWK
  )(using henc: ByteEncoder[JoseHeader]): Either[JwtError, JWE] = {
    val headerEncoded = Base64String.encode(henc.encode(header))
    for
      alg <- header.values.requireAs[Algorithm.Encrypt](P.Alg)
      enc <- header.values.requireAs[CEA](P.Enc)

      (cek, iv) = enc match
        case a: CEA.GCM =>
          (AesGcm.generateKey(a.gcmBits), AesGcm.generateIV)
        case a: CEA.CBC =>
          (AesCbc.generateKey(a.cbcBits).raw, AesCbc.generateIV)

      cekEncrypted <- alg match
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
