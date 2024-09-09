package soidc.core

import soidc.core.json.*

final case class JWKSet(keys: List[JWK]):
  def get(id: KeyId): Option[JWK] =
    keys.find(_.keyId.exists(_ == id))

object JWKSet:

  def apply(k: JWK*): JWKSet = JWKSet(k.toList)

  given FromJson[JWKSet] = FromJson[List[JWK]].map(JWKSet.apply)
  given ToJson[JWKSet] = ToJson[List[JWK]].contramap(_.keys)
