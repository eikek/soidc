package soidc.http4s.routes

import cats.effect.*
import cats.syntax.all.*

import soidc.core.model.*
import soidc.core.{AuthorizationCodeFlow as ACF, *}
import soidc.jwt.codec.ByteDecoder
import soidc.jwt.{Uri as _, *}

import org.http4s.*
import org.http4s.client.dsl.Http4sClientDsl
import org.http4s.dsl.Http4sDsl
import org.http4s.headers.Location

trait AuthCodeFlow[F[_], H, C] extends Realm[F, H, C]:
  def routes(mountUri: Uri)(
      cont: AuthCodeFlow.Result[H, C] => F[Response[F]]
  ): HttpRoutes[F]

  def run(req: Request[F], mountUri: Uri)(
      cont: AuthCodeFlow.Result[H, C] => F[Response[F]]
  )(using cats.Functor[F]): F[Response[F]]

object AuthCodeFlow:

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
    new Impl[F, H, C](logger, acf).pure[F]

  private class Impl[F[_]: Sync, H, C](
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
    def isIssuer(jws: JWSDecoded[H, C])(using StandardClaims[C]): Boolean =
      flow.isIssuer(jws)

    def routes(mountUri: Uri)(cont: Result[H, C] => F[Response[F]]): HttpRoutes[F] =
      val redirectUri = (mountUri / "resume").asJwtUri
      HttpRoutes.of {
        case GET -> Root =>
          for
            authUri <- flow.authorizeUrl(redirectUri).map(_.asUri)
            _ <- logger.debug(show"Redirect to provider: $authUri")
            resp <- TemporaryRedirect(Location(authUri))
          yield resp

        case req @ GET -> Root / "resume" :? Params.StateParam(authState) =>
          flow.obtainToken(redirectUri, req.params).flatMap {
            case Left(err) => cont(Result.failure(err))
            case Right(resp) =>
              resp.accessTokenJWS.flatMap(_.decode[H, C]) match
                case Left(err) => cont(Result.failure(err))
                case Right(jws) =>
                  flow.tokenStore
                    .setRefreshTokenIfPresent(
                      jws,
                      resp.refreshTokenJWS.flatMap(_.toOption)
                    ) >> cont(Result.success(jws, resp))
          }
      }

    def run(req: Request[F], mountUri: Uri)(cont: Result[H, C] => F[Response[F]])(using
        cats.Functor[F]
    ): F[Response[F]] =
      val path = Uri.Path(
        req.uri.path.segments.drop(mountUri.path.segments.size),
        req.uri.path.absolute,
        req.uri.path.endsWithSlash
      )
      val nr = req.withUri(req.uri.withPath(path))
      routes(mountUri)(cont).orNotFound.run(nr)

    extension (self: soidc.jwt.Uri) def asUri: Uri = Uri.unsafeFromString(self.value)
  }
