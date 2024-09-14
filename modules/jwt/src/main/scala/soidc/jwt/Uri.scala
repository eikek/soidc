package soidc.jwt

import soidc.jwt.JwtError.DecodeError
import soidc.jwt.json.{FromJson, ToJson}

opaque type Uri = String

object Uri:
  private val schemeRegex = "^[a-zA-Z][a-zA-Z0-9\\+\\-\\.]*:.*".r

  def fromString(s: String): Either[String, Uri] =
    if (schemeRegex.matches(s.trim)) Right(s.trim)
    else Left(s"Invalid uri: $s")

  def unsafeFromString(s: String): Uri =
    fromString(s).fold(sys.error, identity)

  given FromJson[Uri] = FromJson.str(s => fromString(s).left.map(DecodeError(_)))
  given ToJson[Uri] = ToJson.forString

  extension (self: Uri)
    def value: String = self

    def addPath(path: String): Uri =
      val p = if (path.startsWith("/")) path.drop(1) else path
      val u = if (self.endsWith("/")) self.dropRight(1) else self
      s"${u}/${p}"
