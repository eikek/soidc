package soidc.core

import soidc.core.OidcError.DecodeError
import soidc.core.json.*
import java.security.PublicKey

final case class JWK(
    keyType: KeyType,
    keyUse: Option[KeyUse] = None,
    keyOperation: List[KeyOperation] = Nil,
    keyId: Option[KeyId] = None,
    algorithm: Option[Algorithm] = None,
    values: JsonValue.Obj = JsonValue.emptyObj
):
  def get[A: FromJson](key: String): Either[DecodeError, Option[A]] =
    values.get(key).traverseConvert[A]

  def toPublicKey: Either[OidcError, PublicKey] =
    keyType match
      case KeyType.RSA => RsaPublicKey.create(this)
      case KeyType.EC  => EcPublicKey.create(this)
      case KeyType.OCT => Left(OidcError.UnsupportedPublicKey(keyType))

object JWK:
  def fromObj(values: JsonValue.Obj): Either[DecodeError, JWK] =
    for
      ktyo <- values.get("kty").traverseConvert[KeyType]
      kty <- ktyo.toRight(DecodeError(s"key-type is missing in JWK: $values"))
      kid <- values.get("kid").traverseConvert[KeyId]
      us <- values.get("use").traverseConvert[KeyUse]
      keyop <- values.get("key_ops").traverseConvert[List[KeyOperation]]
      alg <- values.get("alg").traverseConvert[Algorithm]
    yield JWK(kty, us, keyop.getOrElse(Nil), kid, alg, values)

  given FromJson[JWK] = FromJson.obj(fromObj)
  given ToJson[JWK] = ToJson.instance(_.values)
