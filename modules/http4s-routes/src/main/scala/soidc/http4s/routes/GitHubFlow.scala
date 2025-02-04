package soidc.http4s.routes

import cats.effect.*
import cats.syntax.all.*

import soidc.core.model.*
import soidc.core.{AuthorizationCodeFlow as ACF, *}
import soidc.jwt.JwtError

import org.http4s.*
import org.http4s.dsl.Http4sDsl
import org.http4s.headers.Location

trait GitHubFlow[F[_]]:
  def routes(mountUri: Uri)(
      cont: GitHubFlow.Result => F[Response[F]]
  ): HttpRoutes[F]

  def run(req: Request[F], mountUri: Uri)(
      cont: GitHubFlow.Result => F[Response[F]]
  )(using cats.Functor[F]): F[Response[F]]

object GitHubFlow:
  type Result = Either[Result.Failure, Result.Success]
  object Result {
    def failure(cause: ACF.Failure): Result =
      Left(Failure.Flow(cause))

    def failure(cause: JwtError.DecodeError): Result =
      Left(Failure.Decode(cause))

    def success(user: GitHubUser, resp: TokenResponse.Success): Result =
      Right(Success(user, resp))

    enum Failure:
      case Flow(cause: ACF.Failure)
      case Decode(cause: JwtError.DecodeError)
      case UserInfo(cause: Throwable)

    final case class Success(user: GitHubUser, respones: TokenResponse.Success)
  }

  def apply[F[_]: Sync](github: GitHubOAuth[F], logger: Logger[F]): GitHubFlow[F] =
    new Impl[F](github, logger)

  private class Impl[F[_]: Sync](github: GitHubOAuth[F], logger: Logger[F])
      extends GitHubFlow[F]
      with Http4sDsl[F] {

    def routes(mountUri: Uri)(cont: Result => F[Response[F]]): HttpRoutes[F] =
      val redirectUri = (mountUri / "resume").asJwtUri
      HttpRoutes.of {
        case GET -> Root =>
          for
            authUri <- github.authorizeUrl(redirectUri).map(_.asUri)
            _ <- logger.debug(show"Redirect to GitHub: $authUri")
            resp <- TemporaryRedirect(Location(authUri))
          yield resp

        case req @ GET -> Root / "resume" :? Params.StateParam(_) =>
          github.obtainToken(redirectUri, req.params).flatMap {
            case Left(err) => cont(Result.failure(err))
            case Right(resp) =>
              github.getUserInfo(resp.accessToken).attempt.flatMap {
                case Left(ex)    => cont(Left(Result.Failure.UserInfo(ex)))
                case Right(user) => cont(Result.success(user, resp))
              }
          }
      }

    def run(req: Request[F], mountUri: Uri)(cont: Result => F[Response[F]])(using
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
