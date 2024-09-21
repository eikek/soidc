package soidc.core

import scala.concurrent.duration.FiniteDuration

import soidc.jwt.*
import soidc.jwt.codec.ByteDecoder

trait LocalFlow[F[_], H, C]:
  /** Return a validator that can verify tokens from this provider. */
  def validator(using
      StandardClaims[C],
      StandardHeader[H],
      ByteDecoder[JWKSet]
  ): JwtValidator[F, H, C]

  /** Return a refresher to obtain new access tokens. */
  def jwtRefresh(using
      StandardClaims[C],
      ByteDecoder[H],
      ByteDecoder[C]
  ): JwtRefresh[F, H, C]

object LocalFlow:

  final case class Config(
      issuer: String,
      secretKey: JWK,
      sessionValidTime: FiniteDuration
  )
