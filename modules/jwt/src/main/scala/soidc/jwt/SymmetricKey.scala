package soidc.jwt

import javax.crypto.spec.SecretKeySpec

import scodec.bits.ByteVector
import soidc.jwt.JwtError.DecodeError

private object SymmetricKey:

  enum Param(val key: String, val description: String) extends ParameterName:
    case K extends Param("k", "Key Value")

  def create(key: JWK): Either[JwtError, ByteVector] =
    for
      k64 <- key
        .get[Base64String](Param.K)
        .flatMap(_.toRight(DecodeError("Missing 'k' value in")))
      k = k64.decoded
    yield k

  private[jwt] def hmacName(alg: Algorithm): Either[JwtError, String] =
    alg match
      case Algorithm.HS256 => Right("HmacSHA256")
      case Algorithm.HS384 => Right("HmacSHA384")
      case Algorithm.HS512 => Right("HmacSHA512")
      case _               => Left(JwtError.UnsupportedHmacAlgorithm(alg))

  def asHmacSecretKey(key: JWK, alg: Algorithm): Either[JwtError, SecretKeySpec] =
    for
      k <- create(key)
      name <- hmacName(alg)
      ks = SecretKeySpec(k.toArray, name)
    yield ks
