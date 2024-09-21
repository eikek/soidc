package soidc.core.auth

import cats.MonadThrow
import cats.data.OptionT
import cats.syntax.all.*

import soidc.core.HttpClient
import soidc.core.JwtRefresh
import soidc.core.auth.OpenidRefresh.Config
import soidc.jwt.JWS
import soidc.jwt.JWSDecoded
import soidc.jwt.Uri
import soidc.jwt.codec.ByteDecoder

final class OpenidRefresh[F[_]: MonadThrow, H, C](
    client: HttpClient[F],
    tokenStore: TokenStore[F, H, C],
    config: Config[F]
)(using ByteDecoder[TokenResponse], ByteDecoder[H], ByteDecoder[C])
    extends JwtRefresh[F, H, C]:
  def refresh(token: JWSDecoded[H, C]): F[JWSDecoded[H, C]] =
    OptionT(tokenStore.getRefreshToken(token))
      .semiflatMap(runRefreshRequest)
      .semiflatTap(updateStore(token))
      .foldF(token.pure[F])(decode)

  def decode(tr: TokenResponse): F[JWSDecoded[H, C]] =
    tr match {
      case e: TokenResponse.Error => ???
      case s: TokenResponse.Success =>
        s.accessToken.decode[H, C] match
          case Right(t)  => t.pure[F]
          case Left(err) => MonadThrow[F].raiseError(err)
    }

  def updateStore(key: JWSDecoded[H, C])(tr: TokenResponse) =
    tokenStore.setRefreshTokenIfPresent(key, tr.fold(_ => None, _.refreshToken))

  def runRefreshRequest(rt: JWS): F[TokenResponse] =
    for
      uri <- config.tokenEndpoint
      req = TokenRequest.refresh(
        rt,
        config.clientId,
        config.clientSecret.some,
        config.scope
      )
      resp <- client.getToken(uri, req)
    yield resp

object OpenidRefresh:

  final case class Config[F[_]](
      clientId: ClientId,
      clientSecret: ClientSecret,
      tokenEndpoint: F[Uri],
      scope: Option[ScopeList] = None
  )
