package soidc.http4s.routes

import cats.effect.*
import cats.syntax.all.*

import org.http4s.*
import org.http4s.client.Client
import org.http4s.client.dsl.Http4sClientDsl
import org.http4s.dsl.Http4sDsl
import org.http4s.headers.Location
import soidc.core.model.*
import soidc.core.{AuthorizationCodeFlow as ACF, *}
import soidc.http4s.client.Http4sClient
import soidc.jwt.codec.ByteDecoder
import soidc.jwt.{Uri as _, *}

trait AuthCodeFlow[F[_]]:
  def validator[H, C](using
      StandardClaims[C],
      StandardHeader[H],
      ByteDecoder[JWKSet]
  ): JwtValidator[F, H, C]

  def jwtRefresh[H, C](tokenStore: TokenStore[F, H, C])(using
      StandardClaims[C],
      ByteDecoder[H],
      ByteDecoder[C]
  ): JwtRefresh[F, H, C]

  def routes(
      cont: Either[ACF.Failure, TokenResponse.Success] => F[Response[F]]
  ): HttpRoutes[F]

  def run(req: Request[F])(
      cont: Either[ACF.Failure, TokenResponse.Success] => F[Response[F]]
  )(using cats.Functor[F]): F[Response[F]]

object AuthCodeFlow:
  final case class Config[F[_]](
      clientId: ClientId,
      providerUri: Uri,
      baseUri: Uri,
      clientSecret: Option[ClientSecret],
      nonce: Option[Nonce],
      scope: Option[ScopeList],
      logger: String => F[Unit]
  )

  def apply[F[_]: Sync](cfg: Config[F], client: Client[F])(using
      EntityDecoder[F, OpenIdConfig],
      EntityDecoder[F, TokenResponse]
  )(using ByteDecoder[TokenResponse], ByteDecoder[OpenIdConfig]): F[AuthCodeFlow[F]] =
    for
      key <- JwkGenerate.symmetric()
      acfCfg = ACF.Config(
        cfg.clientId,
        cfg.clientSecret,
        jwtUri(cfg.baseUri / "resume"),
        jwtUri(cfg.providerUri),
        key,
        cfg.nonce,
        cfg.scope,
        cfg.logger
      )
      acf <- ACF[F](acfCfg, Http4sClient[F](client))
    yield new Impl(cfg, acf)

  private def jwtUri(uri: Uri): soidc.jwt.Uri =
    soidc.jwt.Uri.unsafeFromString(uri.renderString)

  private class Impl[F[_]: Sync](
      cfg: Config[F],
      flow: ACF[F]
  )(using EntityDecoder[F, OpenIdConfig], EntityDecoder[F, TokenResponse])
      extends AuthCodeFlow[F]
      with Http4sDsl[F]
      with Http4sClientDsl[F] {

    def validator[H, C](using
        StandardClaims[C],
        StandardHeader[H],
        ByteDecoder[JWKSet]
    ): JwtValidator[F, H, C] = flow.validator[H, C]

    def jwtRefresh[H, C](tokenStore: TokenStore[F, H, C])(using
        StandardClaims[C],
        ByteDecoder[H],
        ByteDecoder[C]
    ): JwtRefresh[F, H, C] = flow.jwtRefresh[H, C](tokenStore)

    def routes(
        cont: Either[ACF.Failure, TokenResponse.Success] => F[Response[F]]
    ): HttpRoutes[F] = HttpRoutes.of {
      case GET -> Root =>
        for
          authUri <- flow.authorizeUrl.map(_.asUri)
          _ <- cfg.logger(show"Redirect to provider: $authUri")
          resp <- TemporaryRedirect(Location(authUri))
        yield resp

      case req @ GET -> Root / "resume" :? Params.StateParam(authState) =>
        flow.obtainToken(req.params).flatMap(cont)
    }

    def run(req: Request[F])(
        cont: Either[ACF.Failure, TokenResponse.Success] => F[Response[F]]
    )(using cats.Functor[F]): F[Response[F]] =
      val path = Uri.Path(
        req.uri.path.segments.drop(cfg.baseUri.path.segments.size),
        req.uri.path.absolute,
        req.uri.path.endsWithSlash
      )
      val nr = req.withUri(req.uri.withPath(path))
      routes(cont).orNotFound.run(nr)

    extension (self: soidc.jwt.Uri) def asUri: Uri = Uri.unsafeFromString(self.value)
  }
