package soidc.core

import soidc.core.json.{FromJson, ToJson}

// https://datatracker.ietf.org/doc/html/rfc7519#page-5
opaque type StringOrUri = String

object StringOrUri:

  def apply(str: String): StringOrUri = str

  given FromJson[StringOrUri] = FromJson.str(Right(_))
  given ToJson[StringOrUri] = ToJson.forString

  extension (self: StringOrUri)
    def value: String = self
    def isURI: Boolean = self.contains(':')
