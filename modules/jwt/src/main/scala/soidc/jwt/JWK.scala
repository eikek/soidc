package soidc.jwt

import java.security.PrivateKey
import java.security.PublicKey
import javax.crypto.spec.SecretKeySpec

import scodec.bits.ByteVector
import soidc.jwt.JwtError.DecodeError
import soidc.jwt.RegisteredParameterName as P
import soidc.jwt.json.*

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

  def getPublicKey: Either[JwtError, PublicKey] =
    keyType match
      case KeyType.RSA => RsaKey.createPublicKey(this)
      case KeyType.EC  => EcKey.createPublicKey(this)
      case KeyType.OCT => Left(JwtError.UnsupportedPublicKey(keyType))
      case KeyType.OKP => Left(JwtError.UnsupportedPublicKey(keyType))

  def getPrivateKey: Either[JwtError, PrivateKey] =
    keyType match
      case KeyType.RSA => RsaKey.createPrivateKey(this)
      case KeyType.EC  => EcKey.createPrivateKey(this)
      case KeyType.OCT => Left(JwtError.UnsupportedPrivateKey(keyType))
      case KeyType.OKP => Left(JwtError.UnsupportedPrivateKey(keyType))

  def getSymmetricKey: Either[JwtError, ByteVector] =
    keyType match
      case KeyType.OCT => SymmetricKey.create(this)
      case _           => Left(JwtError.UnsupportedSymmetricKey(keyType))

  def getSymmetricHmacKey: Either[JwtError, SecretKeySpec] =
    for
      bv <- getSymmetricKey
      algOpt <- Right(algorithm).orElse(get[Algorithm](P.Alg))
      alg <- algOpt.toRight(DecodeError("no algorithm"))
      name <- SymmetricKey.hmacName(alg)
    yield SecretKeySpec(bv.toArray, name)

object JWK:
  def symmetric(key: ByteVector, alg: Algorithm): JWK =
    symmetric(Base64String.encode(key), alg)

  def symmetric(key: Base64String, alg: Algorithm): JWK =
    JWK(KeyType.OCT).withValue(SymmetricKey.Param.K, key).withAlgorithm(alg)

  def rsaPrivate(pkcs8PrivateKey: String, alg: Algorithm): Either[JwtError, JWK] =
    RsaKey.fromPkcs8PrivateKey(pkcs8PrivateKey, alg)

  def ecPrivate(
      pkcs8PrivateKey: String,
      pkcs8PublicKey: String,
      alg: Algorithm
  ): Either[JwtError, JWK] =
    EcKey.fromPkcs8PrivateKey(pkcs8PrivateKey, pkcs8PublicKey, alg)

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
