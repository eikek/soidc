package soidc.jwt

import soidc.jwt.codec.*
import soidc.jwt.codec.syntax.*

final case class JWKSet(keys: List[JWK]):
  def get(id: KeyId): Option[JWK] =
    keys.find(_.keyId.exists(_ == id))

object JWKSet:
  val empty: JWKSet = JWKSet(Nil)

  def apply(k: JWK*): JWKSet = JWKSet(k.toList)

  private val parameter: ParameterName = ParameterName.of("keys")
  given FromJson[JWKSet] =
    FromJson.obj {
      _.get(parameter) match
        case None    => Right(empty)
        case Some(v) => v.as[List[JWK]].map(JWKSet.apply)
    }

  given ToJson[JWKSet] =
    ToJson.instance(a => JsonValue.emptyObj.replace(parameter, a.keys))
