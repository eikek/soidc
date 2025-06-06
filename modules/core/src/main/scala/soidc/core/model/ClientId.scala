package soidc.core.model

opaque type ClientId = String

object ClientId:
  def apply(id: String): ClientId = id

  extension (self: ClientId) def value: String = self
