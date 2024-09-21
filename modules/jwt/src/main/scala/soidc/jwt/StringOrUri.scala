package soidc.jwt

import soidc.jwt.codec.{FromJson, ToJson}

// https://datatracker.ietf.org/doc/html/rfc7519#page-5
opaque type StringOrUri = String

object StringOrUri:
  def apply(str: String): StringOrUri = str

  given FromJson[StringOrUri] = FromJson.str(Right(_))
  given ToJson[StringOrUri] = ToJson.forString

  extension (self: StringOrUri)
    def value: String = self
    def isUri: Boolean = toUri.isDefined
    def toUri: Option[Uri] =
      if (self.exists(_ == ':')) Uri.fromString(self).toOption
      else None
