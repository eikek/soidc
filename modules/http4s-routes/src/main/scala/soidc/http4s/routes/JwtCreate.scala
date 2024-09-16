package soidc.http4s.routes

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
  def refresh[F[_]: Clock: MonadThrow, H, C](key: JWK, jws: JWSDecoded[H, C])(
      modifyHeader: H => H,
      modifyClaims: (NumericDate, C) => C
  )(using ByteEncoder[H], ByteEncoder[C]): F[JWSDecoded[H, C]] =
    Clock[F].realTimeInstant.map { now =>
      val h = modifyHeader(jws.header)
      val c = modifyClaims(NumericDate.instant(now), jws.claims)
      JWSDecoded.createSigned[H, C](h, c, key)
    }.rethrow

  def of[F[_]: Clock: MonadThrow, H, C](
      key: JWK,
      header: H,
      mkClaim: NumericDate => C
  )(using ByteEncoder[H], ByteEncoder[C]): F[JWSDecoded[H, C]] =
    Clock[F].realTimeInstant.map { now =>
      JWSDecoded.createSigned[H, C](
        header,
        mkClaim(NumericDate.instant(now)),
        key
      )
    }.rethrow

  def default[F[_]: Clock: MonadThrow](
      key: JWK,
      validity: FiniteDuration,
      modify: SimpleClaims => SimpleClaims
  )(using
      ByteEncoder[JoseHeader],
      ByteEncoder[SimpleClaims]
  ): F[JWSDecoded[JoseHeader, SimpleClaims]] =
    of[F, JoseHeader, SimpleClaims](
      key,
      key.algorithm.map(JoseHeader.jwt.withAlgorithm).getOrElse(JoseHeader.jwt),
      now => modify(SimpleClaims.empty.withExpirationTime(now + validity))
    )
