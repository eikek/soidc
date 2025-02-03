package soidc.core

import cats.Applicative
import cats.effect.*
import cats.syntax.all.*

import soidc.jwt.*

trait TokenStore[F[_], H, C]:
  def getRefreshToken(jwt: JWSDecoded[H, C]): F[Option[JWS]]
  def setRefreshToken(jwt: JWSDecoded[H, C], refreshToken: JWS): F[Unit]
  def setRefreshTokenIfPresent(
      jwt: JWSDecoded[H, C],
      refreshToken: Option[JWS]
  )(using Applicative[F]): F[Unit] =
    refreshToken.traverse_(setRefreshToken(jwt, _))

object TokenStore:
  def none[F[_]: Applicative, H, C]: TokenStore[F, H, C] =
    new TokenStore[F, H, C] {
      def getRefreshToken(jwt: JWSDecoded[H, C]): F[Option[JWS]] = None.pure[F]
      def setRefreshToken(jwt: JWSDecoded[H, C], refreshToken: JWS): F[Unit] = ().pure[F]
    }

  def keyed[F[_]: Applicative, H, C, K](keyFunction: JWSDecoded[H, C] => Option[K])(
      lookup: K => F[Option[JWS]],
      set: (K, JWS) => F[Unit]
  ): TokenStore[F, H, C] =
    new TokenStore[F, H, C] {
      def getRefreshToken(jwt: JWSDecoded[H, C]): F[Option[JWS]] =
        keyFunction(jwt) match
          case Some(key) => lookup(key)
          case None      => None.pure[F]

      def setRefreshToken(jwt: JWSDecoded[H, C], refreshToken: JWS): F[Unit] =
        keyFunction(jwt) match
          case Some(key) => set(key, refreshToken)
          case None      => ().pure[F]
    }

  def memory[F[_]: Sync, H, C](using sc: StandardClaimsRead[C]): F[TokenStore[F, H, C]] =
    def myKey(jws: JWSDecoded[H, C]): Option[String] =
      (sc.issuer(jws.claims), sc.subject(jws.claims)).mapN((a, b) => s"${a}.${b}")
    Ref[F].of(Map.empty[String, JWS]).map { data =>
      keyed[F, H, C, String](myKey)(
        key => data.get.map(_.get(key)),
        (key, value) => data.update(_.updated(key, value))
      )
    }
