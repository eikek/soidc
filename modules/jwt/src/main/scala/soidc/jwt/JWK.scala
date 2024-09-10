package soidc.jwt

import soidc.jwt.OidcError.DecodeError
import soidc.jwt.json.*
import soidc.jwt.RegisteredParameterName as P
import java.security.PublicKey
import scodec.bits.ByteVector
import javax.crypto.spec.SecretKeySpec

final case class JWK(
    keyType: KeyType,
    keyUse: Option[KeyUse] = None,
    keyOperation: List[KeyOperation] = Nil,
    keyId: Option[KeyId] = None,
    algorithm: Option[Algorithm] = None,
    values: JsonValue.Obj = JsonValue.emptyObj
):
  def get[A: FromJson](name: ParameterName): Either[DecodeError, Option[A]] =
    values.get(name).traverseConvert[A]

  def withValue[V: ToJson](param: ParameterName, value: V): JWK =
    copy(values = values.replace(param, value))

  def getPublicKey: Either[OidcError, PublicKey] =
    keyType match
      case KeyType.RSA => RsaPublicKey.create(this)
      case KeyType.EC  => EcPublicKey.create(this)
      case KeyType.OCT => Left(OidcError.UnsupportedPublicKey(keyType))
      case KeyType.OKP => Left(OidcError.UnsupportedPublicKey(keyType))

  def getSymmetricKey: Either[OidcError, ByteVector] =
    keyType match
      case KeyType.OCT => SymmetricKey.create(this)
      case _           => Left(OidcError.UnsupportedSymmetricKey(keyType))

  def getSymmetricHmacKey(alg: Algorithm): Either[OidcError, SecretKeySpec] =
    for
      bv <- getSymmetricKey
      alg <- SymmetricKey.hmacName(alg)
    yield SecretKeySpec(bv.toArray, alg)

object JWK:
  def fromObj(values: JsonValue.Obj): Either[DecodeError, JWK] =
    for
      ktyo <- values.get(P.Kty).traverseConvert[KeyType]
      kty <- ktyo.toRight(DecodeError(s"key-type is missing in JWK: $values"))
      kid <- values.get(P.Kid).traverseConvert[KeyId]
      us <- values.get(P.Use).traverseConvert[KeyUse]
      keyop <- values.get(P.KeyOps).traverseConvert[List[KeyOperation]]
      alg <- values.get(P.Alg).traverseConvert[Algorithm]
    yield JWK(kty, us, keyop.getOrElse(Nil), kid, alg, values)

  given FromJson[JWK] = FromJson.obj(fromObj)
  given ToJson[JWK] = ToJson.instance(_.values)
