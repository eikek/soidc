package soidc.core

import cats.Applicative
import cats.{Monad, Monoid}

import soidc.jwt.JWSDecoded
import soidc.jwt.StandardClaims

trait Realm[F[_], H, C]:
  /** Return a validator that can verify tokens from this provider. */
  def validator: JwtValidator[F, H, C]

  /** Return a refresher to obtain new access tokens. */
  def jwtRefresh: JwtRefresh[F, H, C]

  /** Check whether the given JWT was issued by this provider. */
  def isIssuer(jws: JWSDecoded[H, C])(using StandardClaims[C]): Boolean

  /** Combine this and `next` realm by combining their validator and jwtRefresh instances.
    */
  def or(next: Realm[F, H, C])(using Monad[F]): Realm[F, H, C] =
    Realm.combine(this, next)

object Realm:

  def empty[F[_]: Applicative, H, C]: Realm[F, H, C] =
    new Realm[F, H, C] {
      val validator: JwtValidator[F, H, C] = JwtValidator.notApplicable[F, H, C]
      val jwtRefresh: JwtRefresh[F, H, C] = JwtRefresh.passthrough[F, H, C]
      def isIssuer(jws: JWSDecoded[H, C])(using StandardClaims[C]): Boolean = false
    }

  def combine[F[_]: Monad, H, C](a: Realm[F, H, C], b: Realm[F, H, C]): Realm[F, H, C] =
    new Realm[F, H, C] {
      val validator: JwtValidator[F, H, C] = a.validator.orElse(b.validator)
      val jwtRefresh: JwtRefresh[F, H, C] = a.jwtRefresh.andThen(b.jwtRefresh)
      def isIssuer(jws: JWSDecoded[H, C])(using StandardClaims[C]): Boolean =
        a.isIssuer(jws) || b.isIssuer(jws)
    }

  given [F[_]: Monad, H, C]: Monoid[Realm[F, H, C]] =
    Monoid.instance(empty[F, H, C], combine[F, H, C])
