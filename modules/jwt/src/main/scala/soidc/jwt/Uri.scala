package soidc.jwt

import soidc.jwt.OidcError.DecodeError
import soidc.jwt.json.{FromJson, ToJson}

opaque type Uri = String

object Uri:
  private val schemeRegex = "^[a-zA-Z][a-zA-Z0-9\\+\\-\\.]*:.*".r

  def fromString(s: String): Either[String, Uri] =
    if (s.isEmpty() || schemeRegex.matches(s)) Right(s.trim)
    else Left(s"Invalid uri: $s")

  def unsafeFromString(s: String): Uri =
    fromString(s).fold(sys.error, identity)

  given FromJson[Uri] = FromJson.str(s => fromString(s).left.map(DecodeError(_)))
  given ToJson[Uri] = ToJson.forString

  extension (self: Uri)
    def value: String = self
    def isEmpty: Boolean = self.isEmpty()
