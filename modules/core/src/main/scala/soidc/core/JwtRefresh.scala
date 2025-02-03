package soidc.core

import scala.concurrent.duration.FiniteDuration

import cats.*
import cats.effect.*
import cats.syntax.all.*

import soidc.jwt.*
import soidc.jwt.codec.ByteEncoder

trait JwtRefresh[F[_], H, C]:
  def refresh(token: JWSDecoded[H, C]): F[JWSDecoded[H, C]]

  def andThen(next: JwtRefresh[F, H, C])(using FlatMap[F]): JwtRefresh[F, H, C] =
    JwtRefresh.of(refresh.andThen(_.flatMap(next.refresh)))

  def filter(f: JWSDecoded[H, C] => Boolean)(using Applicative[F]): JwtRefresh[F, H, C] =
    JwtRefresh.of(in => if (f(in)) refresh(in) else in.pure[F])

  def forIssuer(f: String => Boolean)(using
      sc: StandardClaimsRead[C],
      F: Applicative[F]
  ): JwtRefresh[F, H, C] =
    filter(jws => sc.issuer(jws.claims).map(_.value).exists(f))

object JwtRefresh:
  def of[F[_], H, C](f: JWSDecoded[H, C] => F[JWSDecoded[H, C]]): JwtRefresh[F, H, C] =
    new JwtRefresh[F, H, C] {
      def refresh(token: JWSDecoded[H, C]): F[JWSDecoded[H, C]] = f(token)
    }

  def passthrough[F[_]: Applicative, H, C]: JwtRefresh[F, H, C] =
    of(_.pure[F])

  def modify[F[_]: Clock: MonadThrow, H, C](
      modifyHeader: (NumericDate, H) => H,
      modifyClaims: (NumericDate, C) => C
  )(using ByteEncoder[H], ByteEncoder[C]): JwtRefresh[F, H, C] =
    of(in =>
      Clock[F].realTimeInstant.map { now =>
        val date = NumericDate.instant(now)
        val h = modifyHeader(date, in.header)
        val c = modifyClaims(date, in.claims)
        in.copy(header = h, claims = c, jws = JWS.unsigned(h, c))
      }
    )

  def sign[F[_]: MonadThrow, H, C](key: JWK): JwtRefresh[F, H, C] =
    JwtRefresh.of { in =>
      in.jws.signWith(key) match
        case Right(signed) => in.copy(jws = signed).pure[F]
        case Left(err)     => MonadThrow[F].raiseError(err)
    }

  def extend[F[_]: Clock: MonadThrow, H, C](key: JWK)(
      validity: FiniteDuration
  )(using ByteEncoder[H], ByteEncoder[C], StandardClaimsWrite[C]): JwtRefresh[F, H, C] =
    modify[F, H, C](
      (_, h) => h,
      (now, c) => StandardClaimsWrite[C].setExpirationTime(c, now + validity)
    ).andThen(sign[F, H, C](key))

  def select[F[_], H, C](
      f: JWSDecoded[H, C] => JwtRefresh[F, H, C]
  ): JwtRefresh[F, H, C] =
    of(in => f(in).refresh(in))

  def liftF[F[_]: FlatMap, H, C](v: F[JwtRefresh[F, H, C]]): JwtRefresh[F, H, C] =
    of(in => v.flatMap(_.refresh(in)))

  // sign makes it non-associative, though
  given [F[_]: Monad, H, C]: Monoid[JwtRefresh[F, H, C]] =
    Monoid.instance(passthrough[F[_], H, C], _.andThen(_))
