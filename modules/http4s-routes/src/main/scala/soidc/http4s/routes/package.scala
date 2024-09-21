package soidc.http4s

import cats.data.{Kleisli, OptionT}

import org.http4s.*
import soidc.http4s.routes.JwtContext.*

package object routes {
  type JwtAuth[F[_], T] = Kleisli[OptionT[F, *], Request[F], T]

  type JwtAuthRoutes[F[_], H, C] =
    Kleisli[OptionT[F, *], AuthedRequest[F, Authenticated[H, C]], Response[F]]

  type JwtAuthenticatedRoutesMiddleware[F[_], H, C] =
    JwtAuthRoutes[F, H, C] => JwtAuthRoutes[F, H, C]

  type JwtMaybeAuthRoutes[F[_], H, C] =
    Kleisli[OptionT[F, *], AuthedRequest[F, MaybeAuthenticated[H, C]], Response[F]]

  type JwtMaybeAuthRoutesMiddleware[F[_], H, C] =
    JwtMaybeAuthRoutes[F, H, C] => JwtMaybeAuthRoutes[F, H, C]
}
