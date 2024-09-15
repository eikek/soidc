package soidc.core

import cats.syntax.all.*
import soidc.jwt.json.JsonDecoder
import JwtDecodingValidator.*
import soidc.jwt.*
import cats.Applicative

trait JwtDecodingValidator[F[_], H, C]:

  def decodeValidate(token: String)(using JsonDecoder[H], JsonDecoder[C]): F[Result[H, C]]

object JwtDecodingValidator:

  enum ValidateFailure:
    case Unhandled
    case DecodeFailure(cause: JwtError.DecodeError)
    case Invalid(result: Validate.Result.Invalid)

  enum Result[H, C]:
    case Success(jwt: JWSDecoded[H, C])
    case Failure(cause: ValidateFailure)

  def from[F[_]: Applicative, H, C](
      validator: JwtValidator[F, H, C]
  ): JwtDecodingValidator[F, H, C] =
    new JwtDecodingValidator[F, H, C] {
      def decodeValidate(
          token: String
      )(using JsonDecoder[H], JsonDecoder[C]): F[Result[H, C]] =
        JWSDecoded.fromString[H, C](token) match
          case Left(err) => Result.Failure(ValidateFailure.DecodeFailure(err)).pure[F]
          case Right(jwt) =>
            validator.validate(jwt).map {
              case None => Result.Failure(ValidateFailure.Unhandled)
              case Some(r: Validate.Result.Invalid) =>
                Result.Failure(ValidateFailure.Invalid(r))
              case Some(r: Validate.Result.Valid.type) => Result.Success(jwt)
            }
    }
