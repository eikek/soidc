package soidc.jwt

import scodec.bits.ByteVector
import soidc.jwt.ContentEncryptionAlgorithm as CEA
import soidc.jwt.JwtError.DecodeError
import soidc.jwt.codec.ByteDecoder

private[jwt] object Decrypt:

  def decrypt[H](key: JWK, jwe: JWE)(using
      hdec: ByteDecoder[H],
      h: EncryptionHeader[H]
  ): Either[JwtError, ByteVector] =
    for
      header <- hdec.decode(jwe.header.decoded)

      cek <- h.algorithm(header).toRight(DecodeError("Missing alg parameter")).flatMap {
        case Algorithm.Encrypt.dir =>
          SymmetricKey.asAESSecretKey(key)

        case Algorithm.Encrypt.RSA_OAEP =>
          RsaKey
            .createPrivateKey(key)
            .flatMap(pk => RsaOaep.decryptCEK1(jwe.encryptedKey.decoded.toArray, pk))

        case Algorithm.Encrypt.RSA_OAEP_256 =>
          RsaKey
            .createPrivateKey(key)
            .flatMap(pk => RsaOaep.decryptCEK256(jwe.encryptedKey.decoded.toArray, pk))
      }
      enc <- h.encryptionAlgorithm(header).toRight(DecodeError("Missing enc parameter"))
      out <- enc match
        case _: CEA.GCM =>
          AesGcm.decrypt(
            cek,
            jwe.iv.decoded,
            jwe.cipherText.decoded,
            ByteVector.view(jwe.header.value.getBytes()),
            jwe.authTag.decoded
          )

        case _: CEA.CBC =>
          AesCbc.decryptAuthenticated(
            cek,
            jwe.iv.decoded,
            jwe.cipherText.decoded,
            ByteVector.view(jwe.header.value.getBytes()),
            jwe.authTag.decoded
          )
    yield out
