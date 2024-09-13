package soidc.jwt

import java.time.Instant

import scala.concurrent.duration.Duration

final case class JWSDecoded[H, C](
    jws: JWS,
    header: H,
    claims: C
):
  export jws.{compact, payload, verifySignature}

  def validate(key: JWK, currentTime: Instant, timingLeeway: Duration = Duration.Zero)(
      using StandardClaims[C]
  ): Validate.Result =
    Validate.validateSignature(key, jws) + Validate.validateTime(timingLeeway)(
      claims,
      currentTime
    )

  def validateWithoutSignature(
      currentTime: Instant,
      timingLeeway: Duration = Duration.Zero
  )(using
      StandardClaims[C]
  ): Validate.Result = Validate.validateTime(timingLeeway)(claims, currentTime)

type DefaultJWS = JWSDecoded[JoseHeader, SimpleClaims]
