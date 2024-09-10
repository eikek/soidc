package soidc.jwt

import soidc.jwt.OidcError.DecodeError
import scodec.bits.ByteVector
import javax.crypto.spec.SecretKeySpec

private object SymmetricKey:

  enum Param(val key: String, val description: String) extends ParameterName:
    case K extends Param("k", "Key Value")

  def create(key: JWK): Either[OidcError, ByteVector] =
    for
      k64 <- key
        .get[Base64String](Param.K)
        .flatMap(_.toRight(DecodeError("Missing 'k' value in")))
      k = k64.decoded
    yield k

  private[jwt] def hmacName(alg: Algorithm): Either[OidcError, String] =
    alg match
      case Algorithm.HS256 => Right("HmacSHA256")
      case Algorithm.HS384 => Right("HmacSHA384")
      case Algorithm.HS512 => Right("HmacSHA512")
      case _               => Left(OidcError.UnsupportedHmacAlgorithm(alg))

  def asHmacSecretKey(key: JWK, alg: Algorithm): Either[OidcError, SecretKeySpec] =
    for
      k <- create(key)
      name <- hmacName(alg)
      ks = SecretKeySpec(k.toArray, name)
    yield ks
