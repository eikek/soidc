package soidc.http4s.routes

import cats.Monad
import cats.data.{Kleisli, OptionT}
import cats.syntax.all.*

import soidc.core.validate.JwtDecodingValidator.{Result, ValidateFailure}
import soidc.core.validate.JwtValidator
import soidc.http4s.routes.JwtContext.*
import soidc.jwt.JWSDecoded
import soidc.jwt.codec.ByteDecoder

/** Functions to obtain an `AuthedRequest` (a valid token) to use with http4s
  * `AuthMiddleware`.
  */
object JwtAuth:
  def builder[F[_]: Monad, H, C](using ByteDecoder[H], ByteDecoder[C]): Builder[F, H, C] =
    Builder(
      JwtValidator.notApplicable[F, H, C],
      GetToken.noToken[F],
      None
    )

  def secured[F[_]: Monad, H, C](
      getToken: GetToken[F],
      validator: JwtValidator[F, H, C],
      onInvalidToken: Option[ValidateFailure => F[Unit]] = None
  )(using ByteDecoder[H], ByteDecoder[C]): JwtAuth[F, Authenticated[H, C]] =
    Kleisli { req =>
      getToken(req) match
        case None => OptionT.none[F, Authenticated[H, C]]
        case Some(token) =>
          OptionT(validateToken[F, H, C](validator, token, onInvalidToken))
            .map(Authenticated.apply)
    }

  def optional[F[_]: Monad, H, C](
      getToken: GetToken[F],
      validator: JwtValidator[F, H, C],
      onInvalidToken: Option[ValidateFailure => F[Unit]] = None
  )(using
      ByteDecoder[H],
      ByteDecoder[C]
  ): JwtAuth[F, MaybeAuthenticated[H, C]] =
    Kleisli { req =>
      getToken(req) match
        case None => OptionT.some[F](MaybeAuthenticated(None))
        case Some(token) =>
          OptionT(validateToken[F, H, C](validator, token, onInvalidToken))
            .map(Authenticated.apply)
            .map(_.toMaybeAuthenticated)
    }

  private def validateToken[F[_]: Monad, H, C](
      validator: JwtValidator[F, H, C],
      token: String,
      onInvalidToken: Option[ValidateFailure => F[Unit]]
  )(using ByteDecoder[H], ByteDecoder[C]): F[Option[JWSDecoded[H, C]]] =
    validator.toDecodingValidator.decodeValidate(token).flatMap {
      case Result.Success(jwt) => jwt.some.pure[F]
      case Result.Failure(err) =>
        OptionT.fromOption(onInvalidToken).flatMapF(f => f(err).as(None)).value
    }

  final case class Builder[F[_], H, C](
      validator: JwtValidator[F, H, C],
      getToken: GetToken[F],
      onInvalidToken: Option[ValidateFailure => F[Unit]]
  )(using ByteDecoder[H], ByteDecoder[C], Monad[F]) {
    lazy val secured: JwtAuth[F, Authenticated[H, C]] =
      JwtAuth.secured(getToken, validator, onInvalidToken)

    lazy val optional: JwtAuth[F, MaybeAuthenticated[H, C]] =
      JwtAuth.optional(getToken, validator, onInvalidToken)

    def withOnInvalidToken(action: ValidateFailure => F[Unit]): Builder[F, H, C] =
      copy(onInvalidToken = Some(action))

    def withGetToken(f: GetToken[F]): Builder[F, H, C] =
      copy(getToken = f)

    def withBearerToken: Builder[F, H, C] =
      withGetToken(GetToken.bearer[F])

    def withValidator(v: JwtValidator[F, H, C]): Builder[F, H, C] =
      copy(validator = v)

    def modifyGetToken(f: GetToken[F] => GetToken[F]): Builder[F, H, C] =
      withGetToken(f(getToken))

    def modifyValidator(
        f: JwtValidator[F, H, C] => JwtValidator[F, H, C]
    ): Builder[F, H, C] =
      withValidator(f(validator))
  }
