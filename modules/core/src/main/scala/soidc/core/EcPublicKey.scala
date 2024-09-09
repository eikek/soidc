package soidc.core

import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import soidc.core.OidcError.DecodeError
import scala.util.Try

private object EcPublicKey:

  def create(key: JWK): Either[OidcError, PublicKey] =
    for
      xn64 <- key
        .get[Base64String]("x")
        .flatMap(_.toRight(DecodeError("missing x value")))
      xn = xn64.decodeBigInt
      yn64 <- key
        .get[Base64String]("y")
        .flatMap(_.toRight(DecodeError("missing y value")))
      yn = yn64.decodeBigInt
      crv <- key.get[Curve]("crv").flatMap(_.toRight(DecodeError("missing crv value")))

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
