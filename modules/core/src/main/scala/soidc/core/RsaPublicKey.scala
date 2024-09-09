package soidc.core

import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.RSAPublicKeySpec

import soidc.core.OidcError.DecodeError
import scala.util.Try

private object RsaPublicKey:

  def create(key: JWK): Either[OidcError, PublicKey] =
    for
      mod64 <- key
        .get[Base64String]("n")
        .flatMap(_.toRight(DecodeError("modulus parameter missing")))
      mod = mod64.decodeBigInt
      exp64 <- key
        .get[Base64String]("e")
        .flatMap(_.toRight(DecodeError("exponent parameter missing")))
      exp = exp64.decodeBigInt
      kf <- Try(KeyFactory.getInstance("RSA")).toEither.left
        .map(OidcError.SecurityApiError.apply)

      key <- Try(
        kf.generatePublic(RSAPublicKeySpec(mod.underlying, exp.underlying))
      ).toEither.left
        .map(OidcError.SecurityApiError.apply)
    yield key
