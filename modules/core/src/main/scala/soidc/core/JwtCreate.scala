package soidc.core

import scala.concurrent.duration.FiniteDuration

import cats.MonadThrow
import cats.effect.*
import cats.syntax.all.*

import soidc.jwt.*
import soidc.jwt.codec.ByteEncoder

/** Utility functions to create JWTs. It assumes signing errors to be fatal and rethrows
  * them into the `F`.
  */
object JwtCreate:
  /** Modify and sign a given JWS with the current time. */
  def modify[F[_]: Clock: MonadThrow, H, C](key: JWK, jws: JWSDecoded[H, C])(
      modifyHeader: (NumericDate, H) => H,
      modifyClaims: (NumericDate, C) => C
  )(using ByteEncoder[H], ByteEncoder[C]): F[JWSDecoded[H, C]] =
    Clock[F].realTimeInstant.map { now =>
      val date = NumericDate.instant(now)
      val h = modifyHeader(date, jws.header)
      val c = modifyClaims(date, jws.claims)
      JWSDecoded.createSigned[H, C](h, c, key)
    }.rethrow

  def of[F[_]: Clock: MonadThrow, H, C](
      key: JWK,
      header: NumericDate => H,
      mkClaim: NumericDate => C
  )(using ByteEncoder[H], ByteEncoder[C]): F[JWSDecoded[H, C]] =
    Clock[F].realTimeInstant
      .map(NumericDate.instant)
      .map { now =>
        JWSDecoded.createSigned[H, C](
          header(now),
          mkClaim(now),
          key
        )
      }
      .rethrow

  def default[F[_]: Clock: MonadThrow, H, C](
      key: JWK,
      validity: FiniteDuration,
      header: H,
      claims: C
  )(using
      ByteEncoder[H],
      ByteEncoder[C],
      StandardHeaderWrite[H],
      StandardClaimsWrite[C]
  ): F[JWSDecoded[H, C]] =
    of[F, H, C](
      key,
      now =>
        key.algorithm
          .map(StandardHeaderWrite[H].setAlgorithm(header, _))
          .getOrElse(header),
      now => StandardClaimsWrite[C].setExpirationTime(claims, now + validity)
    )
