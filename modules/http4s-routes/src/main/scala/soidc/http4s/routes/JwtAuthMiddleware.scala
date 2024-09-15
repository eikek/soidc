package soidc.http4s.routes

import cats.Monad
import cats.data.Kleisli
import cats.data.OptionT
import cats.syntax.all.*

import org.http4s.*
import org.http4s.headers.Location
import org.http4s.server.AuthMiddleware
import soidc.core.JwtDecodingValidator.ValidateFailure
import soidc.core.JwtValidator
import soidc.http4s.routes.JwtContext.*
import soidc.jwt.codec.ByteDecoder

/** Creates [[org.http4s.server.AuthMiddleware]]s */
object JwtAuthMiddleware:
  def builder[F[_]: Monad, H, C](using ByteDecoder[H], ByteDecoder[C]): Builder[F, H, C] =
    Builder(JwtAuth.builder[F, H, C], Nil, Nil)

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
      authBuilder: JwtAuth.Builder[F, H, C],
      middlewares1: List[JwtAuthenticatedRoutesMiddleware[F, H, C]],
      middlewares2: List[JwtMaybeAuthRoutesMiddleware[F, H, C]]
  )(using ByteDecoder[H], ByteDecoder[C], Monad[F]) {
    lazy val secured: AuthMiddleware[F, Authenticated[H, C]] =
      val route = JwtAuthMiddleware.secured(authBuilder.secured)
      applyMiddlewares1(route)

    def securedOr(
        onFailure: Request[F] => F[Response[F]]
    ): AuthMiddleware[F, Authenticated[H, C]] =
      applyMiddlewares1(JwtAuthMiddleware.securedOr(authBuilder.secured, onFailure))

    def securedOrRedirect(uri: Uri): AuthMiddleware[F, Authenticated[H, C]] =
      applyMiddlewares1(JwtAuthMiddleware.securedOrRedirect(authBuilder.secured, uri))

    lazy val optional: AuthMiddleware[F, MaybeAuthenticated[H, C]] =
      applyMiddlewares2(JwtAuthMiddleware.optional(authBuilder.optional))

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

    def withAuthMiddleware(
        mw: JwtAuthenticatedRoutesMiddleware[F, H, C]
    ): Builder[F, H, C] =
      copy(middlewares1 = mw :: middlewares1)

    def withMaybeAuthMiddleware(
        mw: JwtMaybeAuthRoutesMiddleware[F, H, C]
    ): Builder[F, H, C] =
      copy(middlewares2 = mw :: middlewares2)

    private def applyMiddlewares1(
        r: AuthMiddleware[F, Authenticated[H, C]]
    ): AuthMiddleware[F, Authenticated[H, C]] =
      val mw: JwtAuthenticatedRoutesMiddleware[F, H, C] = middlewares1.foldLeft(
        identity[
          Kleisli[OptionT[F, *], AuthedRequest[F, Authenticated[H, C]], Response[F]]
        ]
      )((res, el) => res.andThen(el))
      service => r(mw.apply(service))

    private def applyMiddlewares2(
        r: AuthMiddleware[F, MaybeAuthenticated[H, C]]
    ): AuthMiddleware[F, MaybeAuthenticated[H, C]] =
      val mw: JwtMaybeAuthRoutesMiddleware[F, H, C] = middlewares2.foldLeft(
        identity[
          Kleisli[OptionT[F, *], AuthedRequest[F, MaybeAuthenticated[H, C]], Response[F]]
        ]
      )((res, el) => res.andThen(el))
      service => r(mw.apply(service))

  }
