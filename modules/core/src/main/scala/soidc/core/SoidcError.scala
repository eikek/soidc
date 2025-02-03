package soidc.core

import scala.concurrent.duration.FiniteDuration

import soidc.jwt.Uri

sealed trait SoidcError extends Throwable

object SoidcError:

  final case class JwtError(cause: soidc.jwt.JwtError)
      extends RuntimeException(cause)
      with SoidcError

  final case class OpenIdConfigError(uri: Uri, cause: Throwable)
      extends RuntimeException(
        s"Error getting openid config from: $uri",
        cause
      )
      with SoidcError

  final case class JwksError(uri: Uri, cause: Throwable)
      extends RuntimeException(
        s"Error getting jwks config from: $uri",
        cause
      )
      with SoidcError

  final case class TooManyValidationRequests(minDelay: FiniteDuration)
      extends RuntimeException(s"Too many validation attempts within $minDelay")
      with SoidcError
