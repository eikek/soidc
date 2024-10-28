package soidc.jwt

import soidc.jwt.codec.{FromJson, ToJson}
import soidc.jwt.JwtError.DecodeError

enum ContentEncryptionAlgorithm:
  case A256GCM

  def name: String = productPrefix

object ContentEncryptionAlgorithm:

  def fromString(str: String): Either[String, ContentEncryptionAlgorithm] =
    ContentEncryptionAlgorithm.values
      .find(_.name.equalsIgnoreCase(str))
      .toRight(s"Invalid content encryption algorthim: $str")

  given FromJson[ContentEncryptionAlgorithm] =
    FromJson.str(s => fromString(s).left.map(DecodeError(_)))
  given ToJson[ContentEncryptionAlgorithm] = ToJson[String].contramap(_.name)
