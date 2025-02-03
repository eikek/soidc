package soidc.core.model

import soidc.jwt.codec.{FromJson, ToJson}

opaque type UserCode = String

object UserCode:
  def apply(s: String): UserCode = s

  given FromJson[UserCode] = FromJson.str(Right(_))
  given ToJson[UserCode] = ToJson.forString

  extension (self: UserCode) def value: String = self
