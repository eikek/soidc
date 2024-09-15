package soidc.http4s

import cats.data.{Kleisli, OptionT}

import org.http4s.*
import soidc.http4s.routes.JwtContext.*

package object routes {
  type JwtAuth[F[_], T] = Kleisli[OptionT[F, *], Request[F], T]
  type JwtAuthenticatedRoutesMiddleware[F[_], H, C] = Kleisli[
    OptionT[F, *],
    AuthedRequest[F, Authenticated[H, C]],
    Response[F]
  ] => Kleisli[OptionT[F, *], AuthedRequest[F, Authenticated[H, C]], Response[F]]

  type JwtMaybeAuthRoutesMiddleware[F[_], H, C] = Kleisli[
    OptionT[F, *],
    AuthedRequest[F, MaybeAuthenticated[H, C]],
    Response[F]
  ] => Kleisli[OptionT[F, *], AuthedRequest[F, MaybeAuthenticated[H, C]], Response[F]]

  type JwtContextAuthRoutesMiddleware[F[_], H, C, A <: JwtContext[H, C]] = Kleisli[
    OptionT[F, *],
    AuthedRequest[F, A],
    Response[F]
  ] => Kleisli[OptionT[F, *], AuthedRequest[F, A], Response[F]]

}
