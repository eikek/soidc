package soidc.http4s.routes

import cats.Monad
import cats.data.{Kleisli, OptionT}
import cats.syntax.all.*

import soidc.core.JwtDecodingValidator.ValidateFailure
import soidc.core.JwtValidator
import soidc.http4s.routes.JwtContext.*
import soidc.jwt.JWSDecoded
import soidc.jwt.JwtError
import soidc.jwt.codec.ByteDecoder

/** Functions to obtain an `AuthedRequest` (a valid token) to use with http4s
  * `AuthMiddleware`.
  */
object JwtAuth:
  val noTokenError = JwtError.DecodeError("No token available in request")

  def builder[F[_]: Monad, H, C](using ByteDecoder[H], ByteDecoder[C]): Builder[F, H, C] =
    Builder(
      JwtValidator.notApplicable[F, H, C],
      GetToken.noToken[F],
      None
    )

  /** Extract from the request and validate it. Returns either the error or the token. */
  def secured[F[_]: Monad, H, C](
      getToken: GetToken[F],
      validator: JwtValidator[F, H, C]
  )(using ByteDecoder[H], ByteDecoder[C]): JwtAuth[F, Authenticated[H, C]] =
    Kleisli { req =>
      getToken(req) match
        case None =>
          ValidateFailure.DecodeFailure(noTokenError).asLeft.pure[F]
        case Some(token) =>
          validateToken[F, H, C](validator, token).map(_.map(Authenticated.apply))
    }

  /** Requires a valid token, otherwise returns `OptionT.none`. */
  def securedOpt[F[_]: Monad, H, C](
      getToken: GetToken[F],
      validator: JwtValidator[F, H, C],
      onInvalidToken: Option[ValidateFailure => F[Unit]] = None
  )(using ByteDecoder[H], ByteDecoder[C]): JwtAuthOpt[F, Authenticated[H, C]] =
    Kleisli { req =>
      getToken(req) match
        case None => OptionT.none[F, Authenticated[H, C]]
        case Some(token) =>
          OptionT(validateTokenOpt[F, H, C](validator, token, onInvalidToken))
            .map(Authenticated.apply)
    }

  /** Returns a valid token or no token if none was found in the request. Returns
    * `OptionT.none` on validation error (a token was found in the request, but validation
    * failed).
    */
  def securedOrAnonymous[F[_]: Monad, H, C](
      getToken: GetToken[F],
      validator: JwtValidator[F, H, C],
      onInvalidToken: Option[ValidateFailure => F[Unit]] = None
  )(using
      ByteDecoder[H],
      ByteDecoder[C]
  ): JwtAuthOpt[F, JwtContext[H, C]] =
    Kleisli { req =>
      getToken(req) match
        case None => OptionT.some[F](JwtContext.notAuthenticated)
        case Some(token) =>
          OptionT(validateTokenOpt[F, H, C](validator, token, onInvalidToken))
            .map(Authenticated.apply)
    }

  private def validateToken[F[_]: Monad, H, C](
      validator: JwtValidator[F, H, C],
      token: String
  )(using ByteDecoder[H], ByteDecoder[C]): F[Either[ValidateFailure, JWSDecoded[H, C]]] =
    validator.toDecodingValidator.decodeValidate(token).map(_.toEither)

  private def validateTokenOpt[F[_]: Monad, H, C](
      validator: JwtValidator[F, H, C],
      token: String,
      onInvalidToken: Option[ValidateFailure => F[Unit]] = None
  )(using ByteDecoder[H], ByteDecoder[C]): F[Option[JWSDecoded[H, C]]] =
    validateToken[F, H, C](validator, token).flatMap {
      case Right(jwt) => jwt.some.pure[F]
      case Left(err) =>
        OptionT.fromOption(onInvalidToken).flatMapF(f => f(err).as(None)).value
    }

  final case class Builder[F[_], H, C](
      validator: JwtValidator[F, H, C],
      getToken: GetToken[F],
      onInvalidToken: Option[ValidateFailure => F[Unit]]
  )(using ByteDecoder[H], ByteDecoder[C], Monad[F]) {
    lazy val secured: JwtAuth[F, Authenticated[H, C]] =
      JwtAuth.secured(getToken, validator)

    lazy val securedOpt: JwtAuthOpt[F, Authenticated[H, C]] =
      JwtAuth.securedOpt(getToken, validator, onInvalidToken)

    lazy val securedOrAnonymous: JwtAuthOpt[F, JwtContext[H, C]] =
      JwtAuth.securedOrAnonymous(getToken, validator, onInvalidToken)

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
