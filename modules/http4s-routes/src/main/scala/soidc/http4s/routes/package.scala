package soidc.http4s

import cats.data.{Kleisli, OptionT}

import org.http4s.*

package object routes {
  type JwtAuth[F[_], T] = Kleisli[OptionT[F, *], Request[F], T]
}
