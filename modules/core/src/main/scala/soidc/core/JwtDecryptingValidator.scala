package soidc.core

import cats.Applicative
import cats.syntax.all.*

import soidc.jwt.*
import soidc.jwt.codec.ByteDecoder

trait JwtDecryptingValidator[F[_], H, C]:

  def decryptValidate(
      token: String
  )(using ByteDecoder[H], ByteDecoder[C], EncryptionHeader[H]): F[ValidateResult[H, C]]

object JwtDecryptingValidator:

  def from[F[_]: Applicative, H, C](
      validator: JwtValidator[F, H, C],
      key: JWK
  ): JwtDecryptingValidator[F, H, C] =
    new JwtDecryptingValidator[F, H, C] {
      def decryptValidate(
          token: String
      )(using ByteDecoder[H], ByteDecoder[C], EncryptionHeader[H]): F[ValidateResult[H, C]] =
        val jws =
          for
            jwe <- JWE
              .fromString(token)
              .left
              .map(err => JwtError.DecodeError(err))
            tokenRaw <- jwe.decrypt[H](key)
            jws <- JWS
              .fromString(tokenRaw.decodeUtf8Lenient)
              .left
              .map(err => JwtError.DecodeError(err))
            jwsd <- jws.decode[H, C]
          yield jwsd

        jws match
          case Left(err) => ValidateResult.Failure(ValidateFailure.DecodeFailure(err)).pure[F]
          case Right(jwt) =>
            validator.validate(jwt).map {
              case None => ValidateResult.Failure(ValidateFailure.Unhandled)
              case Some(r: Validate.Result.Invalid) =>
                ValidateResult.Failure(ValidateFailure.Invalid(r))
              case Some(r: Validate.Result.Valid.type) => ValidateResult.Success(jwt)
            }
    }
