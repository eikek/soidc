package soidc.jwt

import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.RSAPublicKeySpec

import soidc.jwt.OidcError.DecodeError
import scala.util.Try

private object RsaPublicKey:

  enum RSAParam(val key: String) extends ParameterName:
    case N extends RSAParam("n")
    case E extends RSAParam("e")

    def description: String = ""

  def create(key: JWK): Either[OidcError, PublicKey] =
    for
      mod64 <- key
        .get[Base64String](RSAParam.N)
        .flatMap(_.toRight(DecodeError("modulus parameter missing")))
      mod = mod64.decodeBigInt
      exp64 <- key
        .get[Base64String](RSAParam.E)
        .flatMap(_.toRight(DecodeError("exponent parameter missing")))
      exp = exp64.decodeBigInt
      kf <- Try(KeyFactory.getInstance("RSA")).toEither.left
        .map(OidcError.SecurityApiError.apply)

      key <- Try(
        kf.generatePublic(RSAPublicKeySpec(mod.underlying, exp.underlying))
      ).toEither.left
        .map(OidcError.SecurityApiError.apply)
    yield key
