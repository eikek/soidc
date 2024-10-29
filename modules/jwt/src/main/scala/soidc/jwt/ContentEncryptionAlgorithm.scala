package soidc.jwt

import soidc.jwt.codec.{FromJson, ToJson}
import soidc.jwt.JwtError.DecodeError

/** See https://datatracker.ietf.org/doc/html/rfc7518#section-5 */
enum ContentEncryptionAlgorithm(val id: String, val bits: 128 | 192 | 256):
  case A128GCM
      extends ContentEncryptionAlgorithm("AES/GCM/NoPadding", 128)
      with ContentEncryptionAlgorithm.GCM
  case A192GCM
      extends ContentEncryptionAlgorithm("AES/GCM/NoPadding", 192)
      with ContentEncryptionAlgorithm.GCM
  case A256GCM
      extends ContentEncryptionAlgorithm("AES/GCM/NoPadding", 256)
      with ContentEncryptionAlgorithm.GCM
  case A128CBC_HS256
      extends ContentEncryptionAlgorithm("AES/CBC/PKCS5Padding", 128)
      with ContentEncryptionAlgorithm.CBC
  case A192CBC_HS384
      extends ContentEncryptionAlgorithm("AES/CBC/PKCS5Padding", 192)
      with ContentEncryptionAlgorithm.CBC
  case A256CBC_HS512
      extends ContentEncryptionAlgorithm("AES/CBC/PKCS5Padding", 256)
      with ContentEncryptionAlgorithm.CBC

  lazy val name: String = productPrefix.replace('-', '_')

object ContentEncryptionAlgorithm:
  sealed trait GCM
  sealed trait CBC

  def fromString(str: String): Either[String, ContentEncryptionAlgorithm] =
    ContentEncryptionAlgorithm.values
      .find(_.name.equalsIgnoreCase(str))
      .toRight(s"Invalid content encryption algorthim: $str")

  given FromJson[ContentEncryptionAlgorithm] =
    FromJson.str(s => fromString(s).left.map(DecodeError(_)))
  given ToJson[ContentEncryptionAlgorithm] = ToJson[String].contramap(_.name)
