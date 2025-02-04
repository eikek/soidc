package soidc.jwt

import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateCrtKey
import javax.crypto.spec.SecretKeySpec

import soidc.jwt.JwtError.DecodeError
import soidc.jwt.RegisteredParameterName as P
import soidc.jwt.codec.*

import scodec.bits.ByteVector

final case class JWK(
    keyType: KeyType,
    keyUse: Option[KeyUse] = None,
    keyOperation: List[KeyOperation] = Nil,
    keyId: Option[KeyId] = None,
    algorithm: Option[Algorithm] = None,
    values: JsonValue.Obj = JsonValue.emptyObj
):
  def withValue[V: ToJson](param: ParameterName, value: V): JWK =
    copy(values = values.replace(param, value))

  def withAlgorithm(alg: Algorithm): JWK =
    withKeyType(alg.keyType)
      .copy(algorithm = Some(alg), values = values.replace(P.Alg, alg))

  def withKeyType(kty: KeyType): JWK =
    copy(keyType = kty, values = values.replace(P.Kty, kty))

  def withKeyId(kid: KeyId): JWK =
    copy(keyId = Some(kid), values = values.replace(P.Kid, kid))

  def withKeyUse(us: KeyUse): JWK =
    copy(keyUse = Some(us), values = values.replace(P.Use, us))

  def withKeyOperation(op: KeyOperation*): JWK =
    copy(keyOperation = op.toList, values = values.replace(P.KeyOps, op.toList))

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
      alg <- algorithm.map(Right(_)).getOrElse(values.requireAs[Algorithm](P.Alg))
      hm <- SymmetricKey.hmacAlg(alg)
    yield SecretKeySpec(bv.toArray, hm.id)

object JWK:
  def symmetric(key: ByteVector, alg: Algorithm): JWK =
    symmetric(Base64String.encode(key), alg)

  def symmetric(key: Base64String, alg: Algorithm): JWK =
    JWK(KeyType.OCT).withValue(SymmetricKey.Param.K, key).withAlgorithm(alg)

  def rsaPrivate(pkcs8PrivateKey: String, alg: Algorithm): Either[JwtError, JWK] =
    RsaKey.fromPkcs8PrivateKey(pkcs8PrivateKey, alg)

  def rsaDerPrivate(der: Array[Byte], alg: Algorithm): Either[JwtError, JWK] =
    RsaKey.fromDerPrivate(der, alg)

  def rsaPrivate(key: RSAPrivateCrtKey, alg: Algorithm): JWK =
    RsaKey.fromPrivateKey(key, alg)

  def rsaPublic(pkcs8: String, alg: Algorithm): Either[JwtError, JWK] =
    RsaKey.fromPkcs8PubKey(pkcs8, alg)

  def rsaKey(pkcs8: String, alg: Algorithm): Either[JwtError, JWK] =
    if (pkcs8.contains("BEGIN PRIVATE KEY")) rsaPrivate(pkcs8, alg)
    else rsaPublic(pkcs8, alg)

  def ecPrivate(
      pkcs8PrivateKey: String,
      alg: Algorithm
  ): Either[JwtError, JWK] =
    EcKey.fromPkcs8PrivateKey(pkcs8PrivateKey, alg)

  def ecPublic(
      pkcs8PublicKey: String,
      alg: Algorithm
  ): Either[JwtError, JWK] =
    EcKey.fromPkcs8PubKey(pkcs8PublicKey, alg)

  def ecKey(pkcs8: String, alg: Algorithm): Either[JwtError, JWK] =
    if (pkcs8.contains("BEGIN PRIVATE KEY")) ecPrivate(pkcs8, alg)
    else ecPublic(pkcs8, alg)

  def ecKeyPair(priv: String, pub: String, alg: Algorithm): Either[JwtError, JWK] =
    EcKey.fromPkcs8KeyPair(priv, pub, alg)

  def ecKeyPair(
      priv: ECPrivateKey,
      pub: ECPublicKey,
      alg: Algorithm
  ): Either[JwtError, JWK] =
    EcKey.fromKeyPair(priv, pub, alg)

  def fromObj(values: JsonValue.Obj): Either[DecodeError, JWK] =
    for
      kid <- values.getAs[KeyId](P.Kid)
      us <- values.getAs[KeyUse](P.Use)
      keyop <- values.getAs[List[KeyOperation]](P.KeyOps)
      alg <- Right(values.getAs[Algorithm](P.Alg).toOption.flatten)
      kty <- alg match
        case None    => values.requireAs[KeyType](P.Kty)
        case Some(a) => values.getAs[KeyType](P.Kty).map(_.getOrElse(a.keyType))
    yield JWK(kty, us, keyop.getOrElse(Nil), kid, alg, values)

  given FromJson[JWK] = FromJson.obj(fromObj)
  given ToJson[JWK] = ToJson.instance(_.values)
