package soidc.http4s.routes

import cats.Monad
import cats.syntax.all.*

import soidc.core.JwtValidator
import soidc.core.JwtDecodingValidator.ValidateFailure
import soidc.http4s.routes.JwtContext.*
import soidc.jwt.json.JsonDecoder
import org.http4s.server.AuthMiddleware
import org.http4s.*
import org.http4s.headers.Location

/** Creates [[org.http4s.server.AuthMiddleware]]s */
object JwtAuthMiddleware:
  def builder[F[_]: Monad, H, C](using JsonDecoder[H], JsonDecoder[C]): Builder[F, H, C] =
    Builder(JwtAuth.builder[F, H, C])

  def secured[F[_]: Monad, H, C](
      auth: JwtAuth[F, Authenticated[H, C]]
  ): AuthMiddleware[F, Authenticated[H, C]] =
    AuthMiddleware(auth)

  def securedOr[F[_]: Monad, H, C](
      auth: JwtAuth[F, Authenticated[H, C]],
      onFailure: Request[F] => F[Response[F]]
  ): AuthMiddleware[F, Authenticated[H, C]] =
    AuthMiddleware.noSpider(auth, onFailure)

  def securedOrRedirect[F[_]: Monad, H, C](
      auth: JwtAuth[F, Authenticated[H, C]],
      uri: Uri
  ): AuthMiddleware[F, Authenticated[H, C]] =
    AuthMiddleware.noSpider(
      auth,
      _ =>
        Response(status = Status.TemporaryRedirect, headers = Headers(Location(uri)))
          .pure[F]
    )

  def optional[F[_]: Monad, H, C](
      auth: JwtAuth[F, MaybeAuthenticated[H, C]]
  ): AuthMiddleware[F, MaybeAuthenticated[H, C]] =
    AuthMiddleware(auth)

  final case class Builder[F[_], H, C](
      authBuilder: JwtAuth.Builder[F, H, C]
  )(using JsonDecoder[H], JsonDecoder[C], Monad[F]) {
    lazy val secured: AuthMiddleware[F, Authenticated[H, C]] =
      JwtAuthMiddleware.secured(authBuilder.secured)

    def securedOr(
        onFailure: Request[F] => F[Response[F]]
    ): AuthMiddleware[F, Authenticated[H, C]] =
      JwtAuthMiddleware.securedOr(authBuilder.secured, onFailure)

    def securedOrRedirect(uri: Uri): AuthMiddleware[F, Authenticated[H, C]] =
      JwtAuthMiddleware.securedOrRedirect(authBuilder.secured, uri)

    lazy val optional: AuthMiddleware[F, MaybeAuthenticated[H, C]] =
      JwtAuthMiddleware.optional(authBuilder.optional)

    def withOnInvalidToken(action: ValidateFailure => F[Unit]): Builder[F, H, C] =
      copy(authBuilder = authBuilder.withOnInvalidToken(action))

    def withGeToken(f: GetToken[F]): Builder[F, H, C] =
      copy(authBuilder = authBuilder.withGetToken(f))

    def withBearerToken: Builder[F, H, C] =
      withGeToken(GetToken.bearer[F])

    def withValidator(v: JwtValidator[F, H, C]): Builder[F, H, C] =
      copy(authBuilder = authBuilder.withValidator(v))

    def modifyGetToken(f: GetToken[F] => GetToken[F]): Builder[F, H, C] =
      copy(authBuilder = authBuilder.modifyGetToken(f))

    def modifyValidator(
        f: JwtValidator[F, H, C] => JwtValidator[F, H, C]
    ): Builder[F, H, C] =
      copy(authBuilder = authBuilder.modifyValidator(f))
  }
