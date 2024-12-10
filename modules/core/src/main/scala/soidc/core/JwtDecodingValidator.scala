package soidc.core

import cats.Applicative
import cats.syntax.all.*

import soidc.jwt.*
import soidc.jwt.codec.ByteDecoder

trait JwtDecodingValidator[F[_], H, C]:

  def decodeValidate(
      token: String
  )(using ByteDecoder[H], ByteDecoder[C]): F[ValidateResult[H, C]]

object JwtDecodingValidator:

  def from[F[_]: Applicative, H, C](
      validator: JwtValidator[F, H, C]
  ): JwtDecodingValidator[F, H, C] =
    new JwtDecodingValidator[F, H, C] {
      def decodeValidate(
          token: String
      )(using ByteDecoder[H], ByteDecoder[C]): F[ValidateResult[H, C]] =
        JWSDecoded.fromString[H, C](token) match
          case Left(err) =>
            ValidateResult.Failure(ValidateFailure.DecodeFailure(err)).pure[F]
          case Right(jwt) =>
            validator.validate(jwt).map {
              case None => ValidateResult.Failure(ValidateFailure.Unhandled)
              case Some(r: Validate.Result.Invalid) =>
                ValidateResult.Failure(ValidateFailure.Invalid(r))
              case Some(r: Validate.Result.Valid.type) => ValidateResult.Success(jwt)
            }
    }
