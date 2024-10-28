package soidc.jwt

import javax.crypto.spec.SecretKeySpec

import scodec.bits.ByteVector

private object SymmetricKey:

  enum Param(val key: String, val description: String) extends ParameterName:
    case K extends Param("k", "Key Value")

  def create(key: JWK): Either[JwtError, ByteVector] =
    for
      k64 <- key.values.requireAs[Base64String](Param.K)
      k = k64.decoded
    yield k

  private[jwt] def hmacAlg(alg: Algorithm): Either[JwtError, Algorithm.Sign] =
    alg.mapBoth(
      {
        case a @ Algorithm.Sign.HS256 => Right(a)
        case a @ Algorithm.Sign.HS384 => Right(a)
        case a @ Algorithm.Sign.HS512 => Right(a)
        case _                        => Left(JwtError.UnsupportedHmacAlgorithm(alg))
      },
      _ => Left(JwtError.UnsupportedHmacAlgorithm(alg))
    )

  def asHmacSecretKey(key: JWK, alg: Algorithm): Either[JwtError, SecretKeySpec] =
    for
      k <- create(key)
      hm <- hmacAlg(alg)
      ks = SecretKeySpec(k.toArray, hm.id)
    yield ks
