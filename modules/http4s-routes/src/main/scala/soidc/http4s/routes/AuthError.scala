package soidc.http4s.routes

import soidc.jwt.JwtError
import soidc.jwt.Validate

/** Possible errors when decoding and validating a token from a request. */
enum AuthError:
  case Unhandled
  case Decode(cause: JwtError.DecodeError)
  case InvalidToken(failures: Validate.Result)
