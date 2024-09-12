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

  def fromPkcs8PrivateKey(
      privateKey: String,
      publicKey: String,
      alg: Algorithm
  ): Either[JwtError, JWK] =
    for
      _ <- signAlgoName(alg)

      ppkey <- readEcPrivateKey(privateKey)
      plkey <- readEcPubliceKey(publicKey)

      x = plkey.getW().getAffineX()
      y = plkey.getW().getAffineY()
      curveOid = {
        val params = AlgorithmParameters.getInstance("EC")
        params.init(ppkey.getParams())
        params.getParameterSpec(classOf[ECGenParameterSpec]).getName()
      }

      crv <- Curve.fromString(curveOid).left.map(DecodeError(_))

      jwk = JWK(KeyType.EC)
        .withAlgorithm(alg)
        .withValue(ECParam.D, Base64String.encode(ppkey.getS()))
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

      kf <- wrapSecurityApi(KeyFactory.getInstance("EC"))

      ppkspec = PKCS8EncodedKeySpec(ppk.toArray)

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

      kf <- wrapSecurityApi(KeyFactory.getInstance("EC"))

      ppkspec = X509EncodedKeySpec(ppk.toArray)

      ppkey <- wrapSecurityApi(kf.generatePublic(ppkspec))
        .map(_.asInstanceOf[ECPublicKey])
    yield ppkey
