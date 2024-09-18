package soidc.jwt

import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

import scodec.bits.Bases.Alphabets
import scodec.bits.ByteVector
import soidc.jwt.JwtError.DecodeError

private object EcKey:

  enum ECParam(val key: String) extends ParameterName:
    case X extends ECParam("x")
    case Y extends ECParam("y")
    case Crv extends ECParam("crv")
    case D extends ECParam("d")
    def description = ""

  def createPublicKey(key: JWK): Either[JwtError, PublicKey] =
    for
      xn64 <- key.values.requireAs[Base64String](ECParam.X)
      xn = xn64.decodeBigInt
      yn64 <- key.values.requireAs[Base64String](ECParam.Y)
      yn = yn64.decodeBigInt
      crv <- key.values.requireAs[Curve](ECParam.Crv)
      point = ECPoint(xn.underlying, yn.underlying)
      params <- wrapSecurityApi {
        val p = AlgorithmParameters.getInstance("EC")
        p.init(new ECGenParameterSpec(crv.name))
        p.getParameterSpec(classOf[ECParameterSpec])
      }
      pubspec = ECPublicKeySpec(point, params)
      kf <- wrapSecurityApi(KeyFactory.getInstance("EC"))
      k <- wrapSecurityApi(kf.generatePublic(pubspec))
    yield k

  def createPrivateKey(key: JWK): Either[JwtError, PrivateKey] =
    for
      s64 <- key.values.requireAs[Base64String](ECParam.D)
      crv <- key.values.requireAs[Curve](ECParam.Crv)
      params <- wrapSecurityApi {
        val p = AlgorithmParameters.getInstance("EC")
        p.init(new ECGenParameterSpec(crv.name))
        p.getParameterSpec(classOf[ECParameterSpec])
      }

      kf <- wrapSecurityApi(KeyFactory.getInstance("EC"))

      pspec = ECPrivateKeySpec(s64.decodeBigInt.underlying(), params)
      ppk <- wrapSecurityApi(kf.generatePrivate(pspec))
    yield ppk

  def fromPkcs8KeyPair(
      privateKey: String,
      publicKey: String,
      alg: Algorithm
  ): Either[JwtError, JWK] =
    for
      _ <- signAlgoName(alg)

      jwkpp <- fromPkcs8PrivateKey(privateKey, alg)
      jwkpl <- fromPkcs8PubKey(publicKey, alg)

      d <- jwkpp.values.requireAs[Base64String](ECParam.D)

      jwk = jwkpl.withValue(ECParam.D, d)
    yield jwk

  def fromDerKeyPair(
      privateKey: Array[Byte],
      publicKey: Array[Byte],
      alg: Algorithm
  ): Either[JwtError, JWK] =
    for
      ppkey <- readDerPrivate(privateKey)
      plkey <- readDerPublic(publicKey)
      jwk <- fromKeyPair(ppkey, plkey, alg)
    yield jwk

  def fromKeyPair(
      privateKey: ECPrivateKey,
      publicKey: ECPublicKey,
      alg: Algorithm
  ): Either[JwtError, JWK] =
    for
      jwkpp <- fromECPrivateKey(privateKey, alg)
      jwkpl <- fromECPublicKey(publicKey, alg)
      d <- jwkpp.values.requireAs[Base64String](ECParam.D)
      jwk = jwkpl.withValue(ECParam.D, d)
    yield jwk

  def fromPkcs8PrivateKey(
      privateKey: String,
      alg: Algorithm
  ): Either[JwtError, JWK] =
    for
      _ <- signAlgoName(alg)
      ppkey <- readEcPrivateKey(privateKey)
      jwk <- fromECPrivateKey(ppkey, alg)
    yield jwk

  def fromECPrivateKey(ppkey: ECPrivateKey, alg: Algorithm): Either[JwtError, JWK] =
    for
      curveOid <- wrapSecurityApi {
        val params = AlgorithmParameters.getInstance("EC")
        params.init(ppkey.getParams())
        params.getParameterSpec(classOf[ECGenParameterSpec]).getName()
      }

      crv <- Curve.fromString(curveOid).left.map(DecodeError(_))

      jwk = JWK(KeyType.EC)
        .withAlgorithm(alg)
        .withValue(ECParam.D, Base64String.encode(ppkey.getS()))
        .withValue(ECParam.Crv, crv)
    yield jwk

  def fromPkcs8PubKey(
      publicKey: String,
      alg: Algorithm
  ): Either[JwtError, JWK] =
    for
      _ <- signAlgoName(alg)
      plkey <- readEcPubliceKey(publicKey)
      jwk <- fromECPublicKey(plkey, alg)
    yield jwk

  def fromECPublicKey(plkey: ECPublicKey, alg: Algorithm): Either[JwtError, JWK] =
    for
      curveOid <- wrapSecurityApi {
        val params = AlgorithmParameters.getInstance("EC")
        params.init(plkey.getParams())
        params.getParameterSpec(classOf[ECGenParameterSpec]).getName()
      }

      crv <- Curve.fromString(curveOid).left.map(DecodeError(_))
      x = plkey.getW().getAffineX()
      y = plkey.getW().getAffineY()

      jwk = JWK(KeyType.EC)
        .withAlgorithm(alg)
        .withValue(
          ECParam.X,
          Base64String.encode(x)
        )
        .withValue(
          ECParam.Y,
          Base64String.encode(y)
        )
        .withValue(ECParam.Crv, crv)
    yield jwk

  private[jwt] def signAlgoName(
      alg: Algorithm
  ): Either[JwtError.UnsupportedSignatureAlgorithm, String] =
    alg match
      case Algorithm.ES256 => Right("SHA256withECDSA")
      case Algorithm.ES384 => Right("SHA384withECDSA")
      case Algorithm.ES512 => Right("SHA512withECDSA")
      case _               => Left(JwtError.UnsupportedSignatureAlgorithm(alg))

  private def readEcPrivateKey(key: String): Either[JwtError, ECPrivateKey] =
    for
      ppk <- ByteVector
        .fromBase64Descriptive(
          key
            .replace("-----BEGIN PRIVATE KEY-----\n", "")
            .replace("-----END PRIVATE KEY-----", ""),
          Alphabets.Base64
        )
        .left
        .map(err => DecodeError(err))

      ppkey <- readDerPrivate(ppk.toArray)
    yield ppkey

  private def readDerPrivate(der: Array[Byte]): Either[JwtError, ECPrivateKey] =
    for
      kf <- wrapSecurityApi(KeyFactory.getInstance("EC"))
      ppkspec = PKCS8EncodedKeySpec(der)
      ppkey <- wrapSecurityApi(kf.generatePrivate(ppkspec))
        .map(_.asInstanceOf[ECPrivateKey])
    yield ppkey

  private def readEcPubliceKey(key: String): Either[JwtError, ECPublicKey] =
    for
      ppk <- ByteVector
        .fromBase64Descriptive(
          key
            .replace("-----BEGIN PUBLIC KEY-----\n", "")
            .replace("-----END PUBLIC KEY-----", ""),
          Alphabets.Base64
        )
        .left
        .map(err => DecodeError(err))

      ppkey <- readDerPublic(ppk.toArray)
    yield ppkey

  private def readDerPublic(der: Array[Byte]): Either[JwtError, ECPublicKey] =
    for
      kf <- wrapSecurityApi(KeyFactory.getInstance("EC"))
      ppkspec = X509EncodedKeySpec(der)
      ppkey <- wrapSecurityApi(kf.generatePublic(ppkspec))
        .map(_.asInstanceOf[ECPublicKey])
    yield ppkey
