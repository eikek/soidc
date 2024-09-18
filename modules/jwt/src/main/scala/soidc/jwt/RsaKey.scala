package soidc.jwt

import java.security.KeyFactory
import java.security.interfaces.RSAPrivateCrtKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAPrivateKeySpec
import java.security.spec.RSAPublicKeySpec
import java.security.spec.X509EncodedKeySpec
import java.security.{PrivateKey, PublicKey}

import scala.util.Try

import scodec.bits.Bases.Alphabets
import scodec.bits.ByteVector
import soidc.jwt.JwtError.DecodeError

private[jwt] object RsaKey:

  enum Param(val key: String, val description: String) extends ParameterName:
    case N extends Param("n", "Modulus")
    case E extends Param("e", "Exponent")
    case D extends Param("d", "Private Exponent")
    case P extends Param("p", "First Prime Factor")
    case Q extends Param("q", "Second Prime Factor")

  def createPublicKey(key: JWK): Either[JwtError, PublicKey] =
    for
      mod64 <- key.values.requireAs[Base64String](Param.N)
      mod = mod64.decodeBigInt
      exp64 <- key.values.requireAs[Base64String](Param.E)
      exp = exp64.decodeBigInt
      kf <- Try(KeyFactory.getInstance("RSA")).toEither.left
        .map(JwtError.SecurityApiError.apply)

      key <- Try(
        kf.generatePublic(RSAPublicKeySpec(mod.underlying, exp.underlying))
      ).toEither.left
        .map(JwtError.SecurityApiError.apply)
    yield key

  def createPrivateKey(key: JWK): Either[JwtError, PrivateKey] =
    for
      mod64 <- key.values.requireAs[Base64String](Param.N)
      mod = mod64.decodeBigInt
      exp64 <- key.values.requireAs[Base64String](Param.D)
      exp = exp64.decodeBigInt

      kf <- Try(KeyFactory.getInstance("RSA")).toEither.left
        .map(JwtError.SecurityApiError.apply)

      ppk <- Try(
        kf.generatePrivate(RSAPrivateKeySpec(mod.underlying, exp.underlying))
      ).toEither.left
        .map(JwtError.SecurityApiError.apply)
    yield ppk

  def fromPkcs8PrivateKey(key: String, alg: Algorithm): Either[JwtError, JWK] =
    for
      _ <- signAlgoName(alg)
      b64 <- ByteVector
        .fromBase64Descriptive(
          key
            .replace("-----BEGIN PRIVATE KEY-----\n", "")
            .replace("-----END PRIVATE KEY-----", ""),
          Alphabets.Base64
        )
        .left
        .map(err => DecodeError(err))

      jwk <- fromDerPrivate(b64.toArray, alg)
    yield jwk

  def fromDerPrivate(key: Array[Byte], alg: Algorithm): Either[JwtError, JWK] =
    for
      kf <- Try(KeyFactory.getInstance("RSA")).toEither.left
        .map(JwtError.SecurityApiError.apply)

      kspec = PKCS8EncodedKeySpec(key)

      ppk <- Try(kf.generatePrivate(kspec)).toEither.left
        .map(JwtError.SecurityApiError.apply)
        .map(_.asInstanceOf[RSAPrivateCrtKey])

      jwk = fromPrivateKey(ppk, alg)
    yield jwk

  def fromPrivateKey(ppk: RSAPrivateCrtKey, alg: Algorithm): JWK =
    JWK(KeyType.RSA)
      .withAlgorithm(alg)
      .withValue(Param.D, Base64String.encode(ppk.getPrivateExponent()))
      .withValue(Param.N, Base64String.encode(ppk.getModulus()))
      .withValue(Param.E, Base64String.encode(ppk.getPublicExponent()))
      .withValue(Param.P, Base64String.encode(ppk.getPrimeP()))
      .withValue(Param.Q, Base64String.encode(ppk.getPrimeQ()))

  def fromPkcs8PubKey(key: String, alg: Algorithm): Either[JwtError, JWK] =
    for
      _ <- signAlgoName(alg)
      b64 <- ByteVector
        .fromBase64Descriptive(
          key
            .replace("-----BEGIN PUBLIC KEY-----\n", "")
            .replace("-----END PUBLIC KEY-----", ""),
          Alphabets.Base64
        )
        .left
        .map(err => DecodeError(err))
      kf <- Try(KeyFactory.getInstance("RSA")).toEither.left
        .map(JwtError.SecurityApiError.apply)

      kspec = X509EncodedKeySpec(b64.toArray)

      ppk <- Try(kf.generatePublic(kspec)).toEither.left
        .map(JwtError.SecurityApiError.apply)
        .map(_.asInstanceOf[RSAPublicKey])

      jwk = JWK(KeyType.RSA)
        .withAlgorithm(alg)
        .withValue(Param.N, Base64String.encode(ppk.getModulus()))
        .withValue(Param.E, Base64String.encode(ppk.getPublicExponent()))
    yield jwk

  private[jwt] def signAlgoName(
      alg: Algorithm
  ): Either[JwtError.UnsupportedSignatureAlgorithm, String] =
    alg match
      case Algorithm.RS256 => Right("SHA256withRSA")
      case Algorithm.RS384 => Right("SHA384withRSA")
      case Algorithm.RS512 => Right("SHA512withRSA")
      case _               => Left(JwtError.UnsupportedSignatureAlgorithm(alg))
