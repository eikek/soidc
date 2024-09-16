package soidc.core.auth

final case class ClientSecret(secret: String):
  override def toString(): String = "***"
