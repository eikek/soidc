package soidc.core

import scala.concurrent.duration.Duration
import scala.concurrent.duration.FiniteDuration

import cats.MonadThrow
import cats.effect.*

import soidc.jwt.*
import soidc.jwt.codec.ByteEncoder

/** Combines functionality for supporting a local user database for convenience. */
trait LocalFlow[F[_], H, C] extends Realm[F, H, C]:
  /** Return a validator that can verify tokens from this provider. */
  def validator: JwtValidator[F, H, C]

  /** Return a refresher to obtain new access tokens. */
  def jwtRefresh: JwtRefresh[F, H, C]

  /** Creates a now token for the given data */
  def createToken(header: H, claims: C): F[JWSDecoded[H, C]]

object LocalFlow:

  final case class Config(
      issuer: StringOrUri,
      secretKey: JWK,
      sessionValidTime: FiniteDuration
  )

  def apply[F[_]: Clock: MonadThrow, H, C](cfg: Config)(using
      StandardHeaderRead[H],
      StandardHeaderWrite[H],
      StandardClaimsRead[C],
      StandardClaimsWrite[C],
      ByteEncoder[H],
      ByteEncoder[C]
  ): LocalFlow[F, H, C] = new Impl[F, H, C](cfg)

  private class Impl[F[_]: Clock: MonadThrow, H, C](cfg: Config)(using
      StandardHeaderRead[H],
      StandardHeaderWrite[H],
      StandardClaimsRead[C],
      StandardClaimsWrite[C],
      ByteEncoder[H],
      ByteEncoder[C]
  ) extends LocalFlow[F, H, C] {
    def validator: JwtValidator[F, H, C] =
      JwtValidator
        .validateWithKey[F, H, C](
          cfg.secretKey,
          Clock[F],
          Duration.Zero
        )
        .forIssuer(_ == cfg.issuer.value)

    def jwtRefresh: JwtRefresh[F, H, C] =
      JwtRefresh
        .extend[F, H, C](cfg.secretKey)(cfg.sessionValidTime)
        .forIssuer(_ == cfg.issuer.value)

    def createToken(header: H, claims: C): F[JWSDecoded[H, C]] =
      JwtCreate.default[F, H, C](
        cfg.secretKey,
        cfg.sessionValidTime,
        header,
        StandardClaimsWrite[C].setIssuer(claims, cfg.issuer)
      )
  }
