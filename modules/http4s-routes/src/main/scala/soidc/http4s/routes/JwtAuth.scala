package soidc.http4s.routes

import cats.Monad
import cats.data.Kleisli
import cats.syntax.all.*

import soidc.core.JwtValidator
import soidc.core.ValidateFailure
import soidc.http4s.routes.JwtContext.*
import soidc.jwt.JWSDecoded
import soidc.jwt.codec.ByteDecoder
import soidc.jwt.{EncryptionHeader, JWK, JwtError}

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

  /** Extract token from the request and validate it. Returns either the error or the
    * token.
    */
  def secured[F[_]: Monad, H, C](
      getToken: GetToken[F],
      validator: JwtValidator[F, H, C],
      decryptSettings: Option[DecryptSettings[H]]
  )(using ByteDecoder[H], ByteDecoder[C]): JwtAuth[F, Authenticated[H, C]] =
    Kleisli { req =>
      getToken(req) match
        case None =>
          ValidateFailure.DecodeFailure(noTokenError).asLeft.pure[F]
        case Some(token) =>
          validateToken[F, H, C](validator, token, decryptSettings).map(
            _.map(Authenticated.apply)
          )
    }

  /** Extract token from the request and validate it. Returns either the token, an error
    * if it is invalid or none if no token was found.
    */
  def securedOrAnonymous[F[_]: Monad, H, C](
      getToken: GetToken[F],
      validator: JwtValidator[F, H, C],
      decryptSettings: Option[DecryptSettings[H]]
  )(using ByteDecoder[H], ByteDecoder[C]): JwtAuth[F, JwtContext[H, C]] =
    Kleisli { req =>
      getToken(req) match
        case None =>
          JwtContext.notAuthenticated.asRight[ValidateFailure].pure[F]
        case Some(token) =>
          validateToken[F, H, C](validator, token, decryptSettings).map(
            _.map(Authenticated.apply)
          )
    }

  private def validateToken[F[_]: Monad, H, C](
      validator: JwtValidator[F, H, C],
      token: String,
      decryptSettings: Option[DecryptSettings[H]]
  )(using ByteDecoder[H], ByteDecoder[C]): F[Either[ValidateFailure, JWSDecoded[H, C]]] =
    decryptSettings match
      case Some(DecryptSettings(key, header)) =>
        given h: EncryptionHeader[H] = header
        validator.toDecryptingValidator(key).decryptValidate(token).map(_.toEither)
      case None =>
        validator.toDecodingValidator.decodeValidate(token).map(_.toEither)

  final case class Builder[F[_], H, C](
      validator: JwtValidator[F, H, C],
      getToken: GetToken[F],
      decryptSettings: Option[DecryptSettings[H]]
  )(using ByteDecoder[H], ByteDecoder[C], Monad[F]) {
    lazy val secured: JwtAuth[F, Authenticated[H, C]] =
      JwtAuth.secured(getToken, validator, decryptSettings)

    lazy val securedOrAnonymous: JwtAuth[F, JwtContext[H, C]] =
      JwtAuth.securedOrAnonymous(getToken, validator, decryptSettings)

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

    def withDecryption(key: JWK)(using EncryptionHeader[H]): Builder[F, H, C] =
      copy(decryptSettings = DecryptSettings.of(key).some)
  }

  final case class DecryptSettings[H](key: JWK, header: EncryptionHeader[H])
  object DecryptSettings {
    def of[H](key: JWK)(using h: EncryptionHeader[H]): DecryptSettings[H] =
      DecryptSettings(key, h)
  }
