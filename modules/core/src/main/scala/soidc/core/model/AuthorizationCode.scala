package soidc.core.model

opaque type AuthorizationCode = String

object AuthorizationCode:
  def apply(s: String): AuthorizationCode = s

  extension (self: AuthorizationCode) def value: String = self
