package soidc.jwt

import scodec.bits.ByteVector
import soidc.jwt.codec.ByteEncoder
import soidc.jwt.codec.ByteDecoder

final case class JWE(
    header: Base64String,
    encryptedKey: Base64String,
    iv: Base64String,
    cipherText: Base64String,
    authTag: Base64String
):

  def compact: String =
    s"${header.value}.${encryptedKey.value}.${iv.value}.${cipherText.value}.${authTag.value}"

  def decrypt(key: JWK)(using ByteDecoder[JoseHeader]): Either[JwtError, ByteVector] =
    Decrypt.decrypt(key, this)

object JWE:

  def fromString(str: String): Either[String, JWE] =
    str.split('.') match {
      case Array(h, ek, iv, ct, tag) =>
        for
          h64 <- Base64String.of(h)
          ek64 <- Base64String.of(ek)
          iv64 <- Base64String.of(iv)
          txt64 <- Base64String.of(ct)
          atag64 <- Base64String.of(tag)
        yield JWE(h64, ek64, iv64, txt64, atag64)
      case _ =>
        Left(s"Invalid JWE: $str")
    }

  def encrypt(
      alg: Algorithm.Encrypt,
      enc: ContentEncryptionAlgorithm,
      clearText: ByteVector,
      key: JWK
  )(using ByteEncoder[JoseHeader]): Either[JwtError, JWE] =
    Encrypt.encrypt(JoseHeader.jwe(alg, enc), clearText, key)

  def encrypt(header: JoseHeader, clearText: ByteVector, key: JWK)(using
      ByteEncoder[JoseHeader]
  ): Either[JwtError, JWE] =
    Encrypt.encrypt(header, clearText, key)
