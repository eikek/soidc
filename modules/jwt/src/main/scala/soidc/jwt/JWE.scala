package soidc.jwt

import java.nio.charset.StandardCharsets

import scodec.bits.ByteVector
import soidc.jwt.codec.ByteDecoder
import soidc.jwt.codec.ByteEncoder

final case class JWE(
    header: Base64String,
    encryptedKey: Base64String,
    iv: Base64String,
    cipherText: Base64String,
    authTag: Base64String
):
  def compact: String =
    s"${header.value}.${encryptedKey.value}.${iv.value}.${cipherText.value}.${authTag.value}"

  def decrypt[H](
      key: JWK
  )(using ByteDecoder[H], EncryptionHeader[H]): Either[JwtError, ByteVector] =
    Decrypt.decrypt(key, this)

  def decryptToJWS[H, C](
      key: JWK
  )(using
      ByteDecoder[H],
      ByteDecoder[C],
      EncryptionHeader[H]
  ): Either[JwtError, JWSDecoded[H, C]] =
    for
      tokenRaw <- decrypt[H](key)
      jws <- JWS.fromString(tokenRaw.decodeUtf8Lenient)
      jwsd <- jws.decode[H, C]
    yield jwsd

object JWE:
  def fromString(str: String): Either[JwtError.DecodeError, JWE] =
    (str.split('.') match {
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
    }).left.map(JwtError.DecodeError(_))

  def decryptString[H](str: String, key: JWK)(using
      ByteDecoder[H],
      EncryptionHeader[H]
  ): Either[JwtError, ByteVector] =
    fromString(str).flatMap(_.decrypt[H](key))

  def decryptStringToJWS[H, C](str: String, key: JWK)(using
      ByteDecoder[H],
      ByteDecoder[C],
      EncryptionHeader[H]
  ): Either[JwtError, JWSDecoded[H, C]] =
    fromString(str).flatMap(_.decryptToJWS[H, C](key))

  def encrypt(
      alg: Algorithm.Encrypt,
      enc: ContentEncryptionAlgorithm,
      clearText: ByteVector,
      key: JWK
  )(using ByteEncoder[JoseHeader]): Either[JwtError, JWE] =
    Encrypt.encrypt(JoseHeader.jwe(alg, enc), clearText, key)

  def encrypt[H](header: H, clearText: ByteVector, key: JWK)(using
      ByteEncoder[H],
      EncryptionHeader[H]
  ): Either[JwtError, JWE] =
    Encrypt.encrypt(header, clearText, key)

  def encryptJWS[H](header: H, jws: JWS, key: JWK)(using
      ByteEncoder[H],
      EncryptionHeader[H]
  ): Either[JwtError, JWE] =
    Encrypt.encrypt(
      header,
      ByteVector.view(jws.compact.getBytes(StandardCharsets.UTF_8)),
      key
    )
