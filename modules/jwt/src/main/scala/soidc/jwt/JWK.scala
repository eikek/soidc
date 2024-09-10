package soidc.jwt

import soidc.jwt.OidcError.DecodeError
import soidc.jwt.json.*
import soidc.jwt.RegisteredParameterName as P
import java.security.PublicKey
import scodec.bits.ByteVector
import javax.crypto.spec.SecretKeySpec
import java.security.PrivateKey

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

  def withAlgorithm(alg: Algorithm): JWK =
    copy(algorithm = Some(alg), values = values.replace(P.Alg, alg))

  def withKeyType(kty: KeyType): JWK =
    copy(keyType = kty, values = values.replace(P.Kty, kty))

  def getPublicKey: Either[OidcError, PublicKey] =
    keyType match
      case KeyType.RSA => RsaKey.createPublicKey(this)
      case KeyType.EC  => EcKey.createPublicKey(this)
      case KeyType.OCT => Left(OidcError.UnsupportedPublicKey(keyType))
      case KeyType.OKP => Left(OidcError.UnsupportedPublicKey(keyType))

  def getPrivateKey: Either[OidcError, PrivateKey] =
    keyType match
      case KeyType.RSA => RsaKey.createPrivateKey(this)
      case KeyType.EC  => EcKey.createPrivateKey(this)
      case KeyType.OCT => Left(OidcError.UnsupportedPrivateKey(keyType))
      case KeyType.OKP => Left(OidcError.UnsupportedPrivateKey(keyType))

  def getSymmetricKey: Either[OidcError, ByteVector] =
    keyType match
      case KeyType.OCT => SymmetricKey.create(this)
      case _           => Left(OidcError.UnsupportedSymmetricKey(keyType))

  def getSymmetricHmacKey: Either[OidcError, SecretKeySpec] =
    for
      bv <- getSymmetricKey
      algOpt <- Right(algorithm).orElse(get[Algorithm](P.Alg))
      alg <- algOpt.toRight(DecodeError("no algorithm"))
      name <- SymmetricKey.hmacName(alg)
    yield SecretKeySpec(bv.toArray, name)

object JWK:
  def symmetric(key: ByteVector, alg: Algorithm = Algorithm.HS256): JWK =
    symmetric(Base64String.encode(key), alg)

  def symmetric(key: Base64String, alg: Algorithm): JWK =
    JWK(KeyType.OCT).withValue(SymmetricKey.Param.K, key).withAlgorithm(alg)

  def rsaPrivate(pkcs8PrivateKey: String, alg: Algorithm): Either[OidcError, JWK] =
    RsaKey.fromPkcs8PrivateKey(pkcs8PrivateKey, alg)

  def ecPrivate(pkcs8PrivateKey: String, alg: Algorithm): Either[OidcError, JWK] =
    EcKey.fromPkcs8PrivateKey(pkcs8PrivateKey, alg)

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
