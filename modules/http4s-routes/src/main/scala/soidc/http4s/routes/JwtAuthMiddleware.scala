package soidc.http4s.routes

import cats.Monad
import cats.data.Kleisli
import cats.data.OptionT
import cats.effect.*
import cats.syntax.all.*

import soidc.core.JwtRefresh
import soidc.core.JwtValidator
import soidc.core.ValidateFailure
import soidc.http4s.routes.JwtContext.*
import soidc.http4s.routes.TokenRefreshMiddleware.Config as RefreshConfig
import soidc.jwt.StandardClaimsRead
import soidc.jwt.codec.ByteDecoder

import org.http4s.*
import org.http4s.server.AuthMiddleware

/** Creates [[org.http4s.server.AuthMiddleware]]s */
object JwtAuthMiddleware:
  def builder[F[_]: Monad, H, C](using ByteDecoder[H], ByteDecoder[C]): Builder[F, H, C] =
    Builder(
      JwtAuth.builder[F, H, C],
      AuthedRoutes(_ => OptionT.some(Response(status = Status.Unauthorized)))
    )

  def secured[F[_]: Monad, H, C](
      auth: JwtAuth[F, Authenticated[H, C]],
      onFailure: AuthedRoutes[ValidateFailure, F]
  ): AuthMiddleware[F, Authenticated[H, C]] =
    AuthMiddleware(auth, onFailure)

  def securedOrAnonymous[F[_]: Monad, H, C](
      auth: JwtAuth[F, JwtContext[H, C]],
      onFailure: AuthedRoutes[ValidateFailure, F]
  ): AuthMiddleware[F, JwtContext[H, C]] =
    AuthMiddleware(auth, onFailure)

  final case class Builder[F[_], H, C](
      authBuilder: JwtAuth.Builder[F, H, C],
      onFailure: AuthedRoutes[ValidateFailure, F],
      middlewares1: List[JwtAuthedRoutesMiddleware[F, H, C]] = Nil,
      middlewares2: List[JwtMaybeAuthedRoutesMiddleware[F, H, C]] = Nil
  )(using ByteDecoder[H], ByteDecoder[C], Monad[F]) {
    lazy val secured: AuthMiddleware[F, Authenticated[H, C]] =
      applyMiddlewares1(JwtAuthMiddleware.secured(authBuilder.secured, onFailure))

    lazy val securedOrAnonymous: AuthMiddleware[F, JwtContext[H, C]] =
      applyMiddlewares2(
        JwtAuthMiddleware.securedOrAnonymous(authBuilder.securedOrAnonymous, onFailure)
      )

    def withOnFailure(r: AuthedRoutes[ValidateFailure, F]): Builder[F, H, C] =
      copy(onFailure = r)

    def withOnFailure(r: Request[F] => F[Response[F]]): Builder[F, H, C] =
      copy(onFailure = Kleisli(req => OptionT.liftF(r(req.req))))

    def withOnFailure(resp: Response[F]): Builder[F, H, C] =
      withOnFailure(_ => resp.pure[F])

    def withGeToken(f: GetToken[F]): Builder[F, H, C] =
      copy(authBuilder = authBuilder.withGetToken(f))

    def withBearerToken: Builder[F, H, C] =
      withGeToken(GetToken.bearer[F])

    def withValidator(v: JwtValidator[F, H, C]): Builder[F, H, C] =
      copy(authBuilder = authBuilder.withValidator(v))

    def withRefresh(
        v: JwtRefresh[F, H, C],
        config: RefreshConfig[F, H, C] => RefreshConfig[F, H, C]
    )(using StandardClaimsRead[C], Clock[F]): Builder[F, H, C] =
      val cfg = TokenRefreshMiddleware.Config[F, H, C](v)
      withAuthMiddleware(
        TokenRefreshMiddleware.forAuthenticated[F, H, C](config(cfg))
      ).withMaybeAuthMiddleware(
        TokenRefreshMiddleware.forMaybeAuthenticated(config(cfg))
      )

    def modifyGetToken(f: GetToken[F] => GetToken[F]): Builder[F, H, C] =
      copy(authBuilder = authBuilder.modifyGetToken(f))

    def modifyValidator(
        f: JwtValidator[F, H, C] => JwtValidator[F, H, C]
    ): Builder[F, H, C] =
      copy(authBuilder = authBuilder.modifyValidator(f))

    def withAuthMiddleware(
        mw: JwtAuthedRoutesMiddleware[F, H, C]
    ): Builder[F, H, C] =
      copy(middlewares1 = middlewares1 :+ mw)

    def withMaybeAuthMiddleware(
        mw: JwtMaybeAuthedRoutesMiddleware[F, H, C]
    ): Builder[F, H, C] =
      copy(middlewares2 = middlewares2 :+ mw)

    private def applyMiddlewares1(
        r: AuthMiddleware[F, Authenticated[H, C]]
    ): AuthMiddleware[F, Authenticated[H, C]] =
      val mw: JwtAuthedRoutesMiddleware[F, H, C] = middlewares1.foldLeft(
        identity[
          Kleisli[OptionT[F, *], AuthedRequest[F, Authenticated[H, C]], Response[F]]
        ]
      )((res, el) => res.andThen(el))
      service => r(mw.apply(service))

    private def applyMiddlewares2(
        r: AuthMiddleware[F, JwtContext[H, C]]
    ): AuthMiddleware[F, JwtContext[H, C]] =
      val mw: JwtMaybeAuthedRoutesMiddleware[F, H, C] = middlewares2.foldLeft(
        identity[
          Kleisli[OptionT[F, *], AuthedRequest[F, JwtContext[H, C]], Response[F]]
        ]
      )((res, el) => res.andThen(el))
      service => r(mw.apply(service))
  }
