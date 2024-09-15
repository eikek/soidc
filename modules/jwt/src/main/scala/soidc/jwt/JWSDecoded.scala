package soidc.jwt

import java.time.Instant

import scala.concurrent.duration.Duration

import soidc.jwt.codec.*

final case class JWSDecoded[H, C](
    jws: JWS,
    header: H,
    claims: C
):
  export jws.{compact, payload, verifySignature}

  def validate(key: JWK, currentTime: Instant, timingLeeway: Duration = Duration.Zero)(
      using
      StandardClaims[C],
      StandardHeader[H]
  ): Validate.Result =
    Validate.validateSignature(key, this) + Validate.validateTime(timingLeeway)(
      claims,
      currentTime
    )

  def validateWithoutSignature(
      currentTime: Instant,
      timingLeeway: Duration = Duration.Zero
  )(using
      StandardClaims[C]
  ): Validate.Result = Validate.validateTime(timingLeeway)(claims, currentTime)

object JWSDecoded:
  def fromString[H, C](
      token: String
  )(using
      ByteDecoder[H],
      ByteDecoder[C]
  ): Either[JwtError.DecodeError, JWSDecoded[H, C]] =
    for
      jws <- JWS.fromString(token).left.map(JwtError.DecodeError(_))
      h <- jws.header.as[H]
      c <- jws.claims.as[C]
    yield JWSDecoded(jws, h, c)

  def unsafeFromString[H, C](
      token: String
  )(using ByteDecoder[H], ByteDecoder[C]): JWSDecoded[H, C] =
    fromString[H, C](token).fold(throw _, identity)

  def createUnsigned[H, C](header: H, claims: C)(using
      ByteEncoder[H],
      ByteEncoder[C]
  ): JWSDecoded[H, C] =
    JWSDecoded(JWS.unsigned(header, claims), header, claims)

  def createSigned[H, C](header: H, claims: C, key: JWK)(using
      ByteEncoder[H],
      ByteEncoder[C]
  ): Either[JwtError.SignError, JWSDecoded[H, C]] =
    JWS.signed(header, claims, key).map(jws => JWSDecoded(jws, header, claims))

type DefaultJWS = JWSDecoded[JoseHeader, SimpleClaims]
