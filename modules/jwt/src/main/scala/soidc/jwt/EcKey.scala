package soidc.jwt

import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import soidc.jwt.OidcError.DecodeError
import scala.util.Try
import java.security.PrivateKey
import java.security.spec.ECPrivateKeySpec
import scodec.bits.ByteVector
import scodec.bits.Bases.Alphabets
import java.security.spec.PKCS8EncodedKeySpec
import java.security.interfaces.ECPrivateKey

private object EcKey:

  enum ECParam(val key: String) extends ParameterName:
    case X extends ECParam("x")
    case Y extends ECParam("y")
    case Crv extends ECParam("crv")
    case D extends ECParam("d")
    def description = ""

  def createPublicKey(key: JWK): Either[OidcError, PublicKey] =
    for
      xn64 <- key
        .get[Base64String](ECParam.X)
        .flatMap(_.toRight(DecodeError("missing x value")))
      xn = xn64.decodeBigInt
      yn64 <- key
        .get[Base64String](ECParam.Y)
        .flatMap(_.toRight(DecodeError("missing y value")))
      yn = yn64.decodeBigInt
      crv <- key
        .get[Curve](ECParam.Crv)
        .flatMap(_.toRight(DecodeError("missing crv value")))

      point = ECPoint(xn.underlying, yn.underlying)
      params <- Try {
        val p = AlgorithmParameters.getInstance("EC")
        p.init(new ECGenParameterSpec(crv.name))
        p.getParameterSpec(classOf[ECParameterSpec])
      }.toEither.left.map(OidcError.SecurityApiError.apply)
      pubspec = ECPublicKeySpec(point, params)
      kf <- Try(KeyFactory.getInstance("EC")).toEither.left
        .map(OidcError.SecurityApiError.apply)
      k <- Try(kf.generatePublic(pubspec)).toEither.left
        .map(OidcError.SecurityApiError.apply)
    yield k

  def createPrivateKey(key: JWK): Either[OidcError, PrivateKey] =
    for
      s64 <- key
        .get[Base64String](ECParam.D)
        .flatMap(_.toRight(DecodeError("missing d value")))
      crv <- key
        .get[Curve](ECParam.Crv)
        .flatMap(_.toRight(DecodeError("missing crv value")))

      params <- Try {
        val p = AlgorithmParameters.getInstance("EC")
        p.init(new ECGenParameterSpec(crv.name))
        p.getParameterSpec(classOf[ECParameterSpec])
      }.toEither.left.map(OidcError.SecurityApiError.apply)

      kf <- Try(KeyFactory.getInstance("EC")).toEither.left
        .map(OidcError.SecurityApiError.apply)

      pspec = ECPrivateKeySpec(s64.decodeBigInt.underlying(), params)
      ppk <- Try(kf.generatePrivate(pspec)).toEither.left
        .map(OidcError.SecurityApiError.apply)

    yield ppk

  def fromPkcs8PrivateKey(privateKey: String, alg: Algorithm): Either[OidcError, JWK] =
    for
      _ <- signAlgoName(alg)
      ppk <- ByteVector
        .fromBase64Descriptive(
          privateKey
            .replace("-----BEGIN PRIVATE KEY-----\n", "")
            .replace("-----END PRIVATE KEY-----", ""),
          Alphabets.Base64
        )
        .left
        .map(err => DecodeError(err))

      kf <- Try(KeyFactory.getInstance("EC")).toEither.left
        .map(OidcError.SecurityApiError.apply)

      ppkspec = PKCS8EncodedKeySpec(ppk.toArray)

      ppkey <- Try(kf.generatePrivate(ppkspec)).toEither.left
        .map(OidcError.SecurityApiError.apply)
        .map(_.asInstanceOf[ECPrivateKey])

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
          Base64String.encode(ppkey.getParams().getGenerator().getAffineX())
        )
        .withValue(
          ECParam.Y,
          Base64String.encode(ppkey.getParams().getGenerator().getAffineY())
        )
        .withValue(ECParam.Crv, crv)
    yield jwk

  private[jwt] def signAlgoName(alg: Algorithm): Either[OidcError, String] =
    alg match
      case Algorithm.ES256 => Right("SHA256withECDSA")
      case Algorithm.ES384 => Right("SHA384withECDSA")
      case Algorithm.ES512 => Right("SHA512withECDSA")
      case _               => Left(OidcError.UnsupportedSignatureAlgorithm(alg))
