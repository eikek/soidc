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

private object EcPublicKey:

  enum ECParam(val key: String) extends ParameterName:
    case X extends ECParam("x")
    case Y extends ECParam("y")
    case Crv extends ECParam("crv")
    def description = ""

  def create(key: JWK): Either[OidcError, PublicKey] =
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
      // might need bc to support this properly?
      kf <- Try(KeyFactory.getInstance("EC")).toEither.left
        .map(OidcError.SecurityApiError.apply)
      k <- Try(kf.generatePublic(pubspec)).toEither.left
        .map(OidcError.SecurityApiError.apply)
    yield k
