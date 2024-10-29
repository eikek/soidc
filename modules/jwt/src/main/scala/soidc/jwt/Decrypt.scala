package soidc.jwt

import scodec.bits.ByteVector
import soidc.jwt.codec.ByteDecoder

private[jwt] object Decrypt:

  def decrypt(key: JWK, jwe: JWE)(using
      hdec: ByteDecoder[JoseHeader]
  ): Either[JwtError, ByteVector] =
    for
      header <- hdec.decode(jwe.header.decoded)

      cek <- header.algorithm match {
        case Some(Algorithm.Encrypt.RSA_OAEP) =>
          RsaKey
            .createPrivateKey(key)
            .flatMap(pk => RsaOaep.decryptCEK1(jwe.encryptedKey.decoded.toArray, pk))

        case Some(Algorithm.Encrypt.RSA_OAEP_256) =>
          RsaKey
            .createPrivateKey(key)
            .flatMap(pk => RsaOaep.decryptCEK256(jwe.encryptedKey.decoded.toArray, pk))

        case _ => ???
      }

      out <- AesGcm.decrypt(
        cek,
        jwe.iv.decoded,
        jwe.cipherText.decoded,
        ByteVector.view(jwe.header.value.getBytes()),
        jwe.authTag.decoded
      )
    yield out
