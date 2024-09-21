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

  def memory[F[_]: Sync, H, C](using StandardClaims[C]): F[TokenStore[F, H, C]] =
    Ref[F].of(Map.empty[String, JWS]).map { data =>
      new TokenStore[F, H, C] {
        val c = StandardClaims[C]
        def mkKey(iss: StringOrUri, sub: StringOrUri): String =
          s"${iss.value}.${sub.value}"

        def getRefreshToken(jwt: JWSDecoded[H, C]): F[Option[JWS]] =
          (c.issuer(jwt.claims), c.subject(jwt.claims))
            .mapN(mkKey)
            .map { key =>
              data.get.map(_.get(key))
            }
            .getOrElse(None.pure[F])

        def setRefreshToken(jwt: JWSDecoded[H, C], refreshToken: JWS): F[Unit] =
          (c.issuer(jwt.claims), c.subject(jwt.claims))
            .mapN(mkKey)
            .map { key =>
              data.update(_.updated(key, refreshToken))
            }
            .getOrElse(().pure[F])
      }
    }
