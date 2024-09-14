package soidc.jwt

import soidc.jwt.JwtError.DecodeError
import soidc.jwt.json.{FromJson, ToJson}

opaque type KeyId = String

object KeyId:
  def fromString(str: String): Either[String, KeyId] =
    if (str.trim.isEmpty()) Left(s"Empty key-id not allowed")
    else Right(str)

  def unsafeFromString(str: String): KeyId =
    fromString(str).fold(sys.error, identity)

  given FromJson[KeyId] = FromJson.str(s => fromString(s).left.map(DecodeError(_)))
  given ToJson[KeyId] = ToJson.forString

  extension (self: KeyId) def value: String = self
