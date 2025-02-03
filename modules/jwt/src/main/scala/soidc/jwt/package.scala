package soidc

import scala.util.Try

import soidc.jwt.JwtError.SecurityApiError

package object jwt {
  private def wrapSecurityApi[A](code: => A): Either[SecurityApiError, A] =
    Try(code).toEither.left.map(SecurityApiError.apply)

}
