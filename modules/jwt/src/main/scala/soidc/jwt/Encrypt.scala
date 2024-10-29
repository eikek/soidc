package soidc.jwt

import scodec.bits.ByteVector
import soidc.jwt.codec.ByteEncoder

private[jwt] object Encrypt:

  def encrypt(
      alg: Algorithm.Encrypt,
      enc: ContentEncryptionAlgorithm,
      clearText: ByteVector,
      key: JWK
  )(using henc: ByteEncoder[JoseHeader]): Either[JwtError, JWE] = {

    val header = JoseHeader.jwe(alg, enc)
    val headerEncoded = Base64String.encode(henc.encode(header))

    val (cek, iv) =
      enc match
        case a: ContentEncryptionAlgorithm.GCM =>
          (AesGcm.generateKey(a.bits), AesGcm.generateIV)
        case _: ContentEncryptionAlgorithm.CBC =>
          ???

    val cekEncrypted = alg match
      case Algorithm.Encrypt.RSA_OAEP =>
        RsaKey.createPublicKey(key).flatMap(pk => RsaOaep.encryptCEK1(cek, pk))
      case Algorithm.Encrypt.RSA_OAEP_256 =>
        RsaKey.createPublicKey(key).flatMap(pk => RsaOaep.encryptCEK256(cek, pk))

    val result =
      AesGcm.encrypt(cek, iv, clearText, ByteVector.view(headerEncoded.value.getBytes()))

    for
      cenc <- cekEncrypted
      res <- result
    yield JWE(
      header = headerEncoded,
      encryptedKey = Base64String.encode(cenc),
      iv = Base64String.encode(res.iv),
      cipherText = Base64String.encode(res.cipherText),
      authTag = Base64String.encode(res.authTag)
    )
  }
