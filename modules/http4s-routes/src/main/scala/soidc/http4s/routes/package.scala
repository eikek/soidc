package soidc.http4s

import cats.Applicative
import cats.data.{Kleisli, OptionT}

import org.http4s.*
import soidc.core.JwtDecodingValidator.ValidateFailure
import soidc.http4s.routes.JwtContext.*

package object routes {
  type JwtAuth[F[_], T] = Kleisli[F, Request[F], Either[ValidateFailure, T]]
  type JwtAuthOpt[F[_], T] = Kleisli[OptionT[F, *], Request[F], T]

  type JwtAuthedRoutes[F[_], H, C] =
    Kleisli[OptionT[F, *], AuthedRequest[F, Authenticated[H, C]], Response[F]]

  type JwtAuthedRoutesMiddleware[F[_], H, C] =
    JwtAuthedRoutes[F, H, C] => JwtAuthedRoutes[F, H, C]

  type JwtMaybeAuthedRoutes[F[_], H, C] =
    Kleisli[OptionT[F, *], AuthedRequest[F, JwtContext[H, C]], Response[F]]

  type JwtMaybeAuthedRoutesMiddleware[F[_], H, C] =
    JwtMaybeAuthedRoutes[F, H, C] => JwtMaybeAuthedRoutes[F, H, C]

  extension (self: Uri)
    def asJwtUri: soidc.jwt.Uri =
      soidc.jwt.Uri.unsafeFromString(self.renderString)

  extension [F[_], H, C](self: JwtMaybeAuthedRoutes[F, H, C])
    def asAuthedRoutes: JwtAuthedRoutes[F, H, C] =
      Kleisli(req => self.run(ContextRequest(req.context.widen, req.req)))

  extension [F[_], H, C](self: JwtAuthedRoutes[F, H, C])(using Applicative[F])
    def toMaybeAuthedRoutes(
        onNotAuthed: HttpRoutes[F] = HttpRoutes.empty[F]
    ): JwtMaybeAuthedRoutes[F, H, C] =
      Kleisli { cr =>
        cr.context.toAuthenticated match
          case Some(authed) => self(ContextRequest(authed, cr.req))
          case None         => onNotAuthed.run(cr.req)
      }
}
