package soidc.core.model

final case class ClientSecret(secret: String):
  override def toString(): String = "***"
