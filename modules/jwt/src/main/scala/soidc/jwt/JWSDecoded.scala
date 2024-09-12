package soidc.jwt

import java.time.Instant

import scala.concurrent.duration.Duration

final case class JWSDecoded[H, C](
    jws: JWS,
    header: H,
    claims: C
):
  export jws.{compact, payload, verify}

  def validate(key: JWK, currentTime: Instant, timingLeeway: Duration = Duration.Zero)(
      using StandardClaims[C]
  ) =
    verify(key).map(_ && Validate.validateTime(timingLeeway)(claims, currentTime))

  def validateWithoutSignature(
      currentTime: Instant,
      timingLeeway: Duration = Duration.Zero
  )(using
      StandardClaims[C]
  ) = Validate.validateTime(timingLeeway)(claims, currentTime)

type DefaultJWS = JWSDecoded[JoseHeader, SimpleClaims]
