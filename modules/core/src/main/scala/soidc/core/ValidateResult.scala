package soidc.core

import soidc.jwt.*

enum ValidateFailure:
  case Unhandled
  case DecodeFailure(cause: JwtError)
  case Invalid(result: Validate.Result.Invalid)

enum ValidateResult[H, C]:
  case Success(jwt: JWSDecoded[H, C])
  case Failure(cause: ValidateFailure)

  def toEither: Either[ValidateFailure, JWSDecoded[H, C]] = this match
    case Success(a) => Right(a)
    case Failure(b) => Left(b)
