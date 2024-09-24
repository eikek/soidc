package soidc.http4s.routes

import cats.effect.*
import cats.syntax.all.*

import org.http4s.*
import org.http4s.client.dsl.Http4sClientDsl
import org.http4s.dsl.Http4sDsl
import org.http4s.headers.Location
import soidc.core.model.*
import soidc.core.{AuthorizationCodeFlow as ACF, *}
import soidc.jwt.codec.ByteDecoder
import soidc.jwt.{Uri as _, *}

trait AuthCodeFlow[F[_], H, C] extends Realm[F, H, C]:
  def routes(
      cont: AuthCodeFlow.Result[H, C] => F[Response[F]]
  ): HttpRoutes[F]

  def run(req: Request[F])(
      cont: AuthCodeFlow.Result[H, C] => F[Response[F]]
  )(using cats.Functor[F]): F[Response[F]]

object AuthCodeFlow:
  final case class Config(baseUri: Uri, resumeSegment: String = "resume") {
    lazy val redirectUri: Uri = baseUri / resumeSegment
  }

  type Result[H, C] = Either[Result.Failure, Result.Success[H, C]]

  object Result {
    def failure[H, C](cause: ACF.Failure): Result[H, C] =
      Left(Failure.Flow(cause))

    def failure[H, C](cause: JwtError.DecodeError): Result[H, C] =
      Left(Failure.Decode(cause))

    def success[H, C](jws: JWSDecoded[H, C], resp: TokenResponse.Success): Result[H, C] =
      Right(Success(jws, resp))

    enum Failure:
      case Flow(cause: ACF.Failure)
      case Decode(cause: JwtError.DecodeError)

    final case class Success[H, C](
        jws: JWSDecoded[H, C],
        respones: TokenResponse.Success
    )
  }

  def apply[F[_]: Sync, H, C](
      cfg: Config,
      acf: ACF[F, H, C],
      logger: Logger[F]
  )(using
      EntityDecoder[F, OpenIdConfig],
      EntityDecoder[F, TokenResponse],
      StandardClaimsRead[C],
      StandardHeaderRead[H],
      ByteDecoder[JWKSet],
      ByteDecoder[H],
      ByteDecoder[C]
  ): F[AuthCodeFlow[F, H, C]] =
    for key <- JwkGenerate.symmetric()
    yield new Impl(cfg, logger, acf)

  // private def jwtUri(uri: Uri): soidc.jwt.Uri =
  //   soidc.jwt.Uri.unsafeFromString(uri.renderString)

  private class Impl[F[_]: Sync, H, C](
      cfg: Config,
      logger: Logger[F],
      flow: ACF[F, H, C]
  )(using
      EntityDecoder[F, OpenIdConfig],
      EntityDecoder[F, TokenResponse],
      StandardClaimsRead[C],
      StandardHeaderRead[H],
      ByteDecoder[H],
      ByteDecoder[C],
      ByteDecoder[JWKSet]
  ) extends AuthCodeFlow[F, H, C]
      with Http4sDsl[F]
      with Http4sClientDsl[F] {

    def validator: JwtValidator[F, H, C] = flow.validator
    def jwtRefresh: JwtRefresh[F, H, C] = flow.jwtRefresh

    def routes(cont: Result[H, C] => F[Response[F]]): HttpRoutes[F] = HttpRoutes.of {
      case GET -> Root =>
        for
          authUri <- flow.authorizeUrl.map(_.asUri)
          _ <- logger.debug(show"Redirect to provider: $authUri")
          resp <- TemporaryRedirect(Location(authUri))
        yield resp

      case req @ GET -> Root / cfg.resumeSegment :? Params.StateParam(authState) =>
        flow.obtainToken(req.params).flatMap {
          case Left(err) => cont(Result.failure(err))
          case Right(resp) =>
            resp.accessToken.decode[H, C] match
              case Left(err) => cont(Result.failure(err))
              case Right(jws) =>
                flow.tokenStore.setRefreshTokenIfPresent(jws, resp.refreshToken) >> cont(
                  Result.success(jws, resp)
                )
        }
    }

    def run(req: Request[F])(cont: Result[H, C] => F[Response[F]])(using
        cats.Functor[F]
    ): F[Response[F]] =
      val path = Uri.Path(
        req.uri.path.segments.drop(cfg.baseUri.path.segments.size),
        req.uri.path.absolute,
        req.uri.path.endsWithSlash
      )
      val nr = req.withUri(req.uri.withPath(path))
      routes(cont).orNotFound.run(nr)

    extension (self: soidc.jwt.Uri) def asUri: Uri = Uri.unsafeFromString(self.value)
  }
