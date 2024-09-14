package soidc.http4s.routes

import cats.Monad
import cats.data.{Kleisli, OptionT}
import cats.syntax.all.*

import soidc.core.JwtValidator
import soidc.http4s.routes.JwtContext.*
import soidc.jwt.JWSDecoded
import soidc.jwt.json.JsonDecoder

/** Functions to obtain an `AuthedRequest` to use with http4s `AuthMiddleware`. */
object JwtAuth:
  def builder[F[_]: Monad, H, C](using JsonDecoder[H], JsonDecoder[C]): Builder[F, H, C] =
    Builder(
      JwtValidator.notApplicable[F, H, C],
      GetToken.noToken[F],
      None
    )

  def secured[F[_]: Monad, H, C](
      getToken: GetToken[F],
      validator: JwtValidator[F, H, C],
      onInvalidToken: Option[AuthError => F[Unit]] = None
  )(using JsonDecoder[H], JsonDecoder[C]): JwtAuth[F, Authenticated[H, C]] =
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
      onInvalidToken: Option[AuthError => F[Unit]] = None
  )(using
      JsonDecoder[H],
      JsonDecoder[C]
  ): JwtAuth[F, MaybeAuthenticated[H, C]] =
    Kleisli { req =>
      getToken(req) match
        case None => OptionT.none[F, MaybeAuthenticated[H, C]]
        case Some(token) =>
          OptionT(validateToken[F, H, C](validator, token, onInvalidToken))
            .map(Authenticated.apply)
            .map(_.toMaybeAuthenticated)
    }

  private def validateToken[F[_]: Monad, H, C](
      validator: JwtValidator[F, H, C],
      token: String,
      onInvalidToken: Option[AuthError => F[Unit]]
  )(using JsonDecoder[H], JsonDecoder[C]): F[Option[JWSDecoded[H, C]]] =
    JWSDecoded.fromString[H, C](token) match
      case Left(err) =>
        OptionT
          .fromOption(onInvalidToken)
          .flatMapF(f => f(AuthError.Decode(err)).as(None))
          .value
      case Right(jwt) =>
        validator.validate(jwt).flatMap {
          case Some(r) if r.isValid => Some(jwt).pure[F]
          case result =>
            val err = result
              .map(AuthError.InvalidToken.apply)
              .getOrElse(AuthError.Unhandled)
            OptionT.fromOption(onInvalidToken).flatMapF(f => f(err).as(None)).value
        }

  final case class Builder[F[_], H, C](
      validator: JwtValidator[F, H, C],
      getToken: GetToken[F],
      onInvalidToken: Option[AuthError => F[Unit]]
  )(using JsonDecoder[H], JsonDecoder[C], Monad[F]) {
    lazy val secured: JwtAuth[F, Authenticated[H, C]] =
      JwtAuth.secured(getToken, validator, onInvalidToken)

    lazy val optional: JwtAuth[F, MaybeAuthenticated[H, C]] =
      JwtAuth.optional(getToken, validator, onInvalidToken)

    def withOnInvalidToken(action: AuthError => F[Unit]): Builder[F, H, C] =
      copy(onInvalidToken = Some(action))

    def withGeToken(f: GetToken[F]): Builder[F, H, C] =
      copy(getToken = f)

    def withBearerToken: Builder[F, H, C] =
      withGeToken(GetToken.bearer[F])

    def withValidator(v: JwtValidator[F, H, C]): Builder[F, H, C] =
      copy(validator = v)

    def modifyGetToken(f: GetToken[F] => GetToken[F]): Builder[F, H, C] =
      withGeToken(f(getToken))

    def modifyValidator(
        f: JwtValidator[F, H, C] => JwtValidator[F, H, C]
    ): Builder[F, H, C] =
      withValidator(f(validator))
  }
