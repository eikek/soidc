package soidc.jwt

import java.security.KeyFactory
import java.security.{PrivateKey, PublicKey}
import java.security.spec.RSAPublicKeySpec

import soidc.jwt.OidcError.DecodeError
import scala.util.Try
import java.security.spec.RSAPrivateKeySpec
import java.security.spec.PKCS8EncodedKeySpec
import scodec.bits.ByteVector
import scodec.bits.Bases.Alphabets
import java.security.interfaces.RSAPrivateCrtKey

private[jwt] object RsaKey:

  enum Param(val key: String, val description: String) extends ParameterName:
    case N extends Param("n", "Modulus")
    case E extends Param("e", "Exponent")
    case D extends Param("d", "Private Exponent")
    case P extends Param("p", "First Prime Factor")
    case Q extends Param("q", "Second Prime Factor")

  def createPublicKey(key: JWK): Either[OidcError, PublicKey] =
    for
      mod64 <- key
        .get[Base64String](Param.N)
        .flatMap(_.toRight(DecodeError("modulus parameter missing")))
      mod = mod64.decodeBigInt
      exp64 <- key
        .get[Base64String](Param.E)
        .flatMap(_.toRight(DecodeError("exponent parameter missing")))
      exp = exp64.decodeBigInt
      kf <- Try(KeyFactory.getInstance("RSA")).toEither.left
        .map(OidcError.SecurityApiError.apply)

      key <- Try(
        kf.generatePublic(RSAPublicKeySpec(mod.underlying, exp.underlying))
      ).toEither.left
        .map(OidcError.SecurityApiError.apply)
    yield key

  def createPrivateKey(key: JWK): Either[OidcError, PrivateKey] =
    for
      mod64 <- key
        .get[Base64String](Param.N)
        .flatMap(_.toRight(DecodeError("modulus parameter missing")))
      mod = mod64.decodeBigInt
      exp64 <- key
        .get[Base64String](Param.D)
        .flatMap(_.toRight(DecodeError("private exponent parameter missing")))
      exp = exp64.decodeBigInt

      kf <- Try(KeyFactory.getInstance("RSA")).toEither.left
        .map(OidcError.SecurityApiError.apply)

      ppk <- Try(
        kf.generatePrivate(RSAPrivateKeySpec(mod.underlying, exp.underlying))
      ).toEither.left
        .map(OidcError.SecurityApiError.apply)
    yield ppk

  def fromPkcs8PrivateKey(key: String, alg: Algorithm): Either[OidcError, JWK] =
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
      kf <- Try(KeyFactory.getInstance("RSA")).toEither.left
        .map(OidcError.SecurityApiError.apply)

      kspec = PKCS8EncodedKeySpec(b64.toArray)

      ppk <- Try(kf.generatePrivate(kspec)).toEither.left
        .map(OidcError.SecurityApiError.apply)
        .map(_.asInstanceOf[RSAPrivateCrtKey])

      jwk = JWK(KeyType.RSA)
        .withAlgorithm(alg)
        .withValue(Param.D, Base64String.encode(ppk.getPrivateExponent()))
        .withValue(Param.N, Base64String.encode(ppk.getModulus()))
        .withValue(Param.E, Base64String.encode(ppk.getPublicExponent()))
        .withValue(Param.P, Base64String.encode(ppk.getPrimeP()))
        .withValue(Param.Q, Base64String.encode(ppk.getPrimeQ()))
    yield jwk

  private[jwt] def signAlgoName(alg: Algorithm): Either[OidcError, String] =
    alg match
      case Algorithm.RS256 => Right("SHA256withRSA")
      case Algorithm.RS384 => Right("SHA384withRSA")
      case Algorithm.RS512 => Right("SHA512withRSA")
      case _               => Left(OidcError.UnsupportedSignatureAlgorithm(alg))
