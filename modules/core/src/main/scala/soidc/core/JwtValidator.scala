package soidc.core

import scala.concurrent.duration.FiniteDuration

import cats.Applicative
import cats.MonadThrow
import cats.data.Kleisli
import cats.effect.*
import cats.syntax.all.*
import cats.{Monad, Monoid}

import soidc.core.JwtValidator.Result
import soidc.jwt.*
import soidc.jwt.json.JsonDecoder

trait JwtValidator[F[_], H, C]:

  def validate(jws: JWSDecoded[H, C]): F[Result]

  infix def orElse(next: JwtValidator[F, H, C])(using Monad[F]): JwtValidator[F, H, C] =
    JwtValidator.instance(jws =>
      validate(jws).flatMap {
        case Right(None) => next.validate(jws)
        case r           => r.pure[F]
      }
    )

  def scoped(enable: JWSDecoded[H, C] => Boolean)(using
      Applicative[F]
  ): JwtValidator[F, H, C] =
    JwtValidator.instance(jws => if (enable(jws)) validate(jws) else Right(None).pure[F])

  def forIssuer(f: String => Boolean)(using
      sc: StandardClaims[C],
      F: Applicative[F]
  ): JwtValidator[F, H, C] =
    scoped(jws => sc.issuer(jws.claims).map(_.value).exists(f))

object JwtValidator:
  type Result = Either[SoidcError, Option[Boolean]]

  object Result {
    def pure(valid: Option[Boolean]): Result = Right(valid)
    def notApplicable: Result = Right(None)
    def failure(err: SoidcError): Result = Left(err)

    object Failure {
      def unapply(r: Result): Option[SoidcError] =
        r.left.toOption
    }
    object NotApplicable {
      def unapply(r: Result): Option[Unit] =
        r.toOption.flatMap {
          case None => Some(())
          case _    => None
        }
    }
    object Validated {
      def unapply(r: Result): Option[Boolean] =
        r.toOption.flatten
    }
  }

  def kleisli[F[_], H, C](
      k: Kleisli[F, JWSDecoded[H, C], Result]
  ): JwtValidator[F, H, C] =
    instance(k.run)

  def instance[F[_], H, C](
      f: JWSDecoded[H, C] => F[Result]
  ): JwtValidator[F, H, C] =
    new JwtValidator[F, H, C] {
      def validate(jws: JWSDecoded[H, C]): F[Result] = f(jws)
    }

  def invalid[F[_]: Applicative, H, C]: JwtValidator[F, H, C] =
    instance(_ => Right(Some(false)).pure[F])

  def alwaysValid[F[_]: Applicative, H, C]: JwtValidator[F, H, C] =
    instance(_ => Right(Some(true)).pure[F])

  def notApplicable[F[_]: Applicative, H, C]: JwtValidator[F, H, C] =
    instance(_ => Right(None).pure[F])

  def validateTimingOnly[F[_], H, C](clock: Clock[F], timingLeeway: FiniteDuration)(using
      StandardClaims[C],
      Monad[F]
  ): JwtValidator[F, H, C] =
    instance(jws =>
      clock.realTimeInstant.map(
        jws.validateWithoutSignature(_, timingLeeway).some.asRight
      )
    )

  def validateWithKey[F[_], H, C](jwk: JWK, clock: Clock[F])(using
      StandardClaims[C],
      Monad[F]
  ): JwtValidator[F, H, C] =
    instance(jws =>
      clock.realTimeInstant.map(jws.validate(jwk, _)).map {
        case Right(r)                           => Some(r).asRight
        case Left(_: JwtError.SignatureMissing) => None.asRight
        case Left(_: JwtError.AlgorithmMissing) => None.asRight
        case Left(_)                            => Some(false).asRight
      }
    )

  def openId[F[_], H, C](config: OpenIdJwtValidator.Config, client: HttpClient[F])(using
      StandardClaims[C],
      StandardHeader[H],
      MonadThrow[F],
      JsonDecoder[OpenIdConfig],
      JsonDecoder[JWKSet],
      Ref.Make[F],
      Clock[F]
  ): F[JwtValidator[F, H, C]] =
    Ref[F]
      .of(OpenIdJwtValidator.State())
      .map(OpenIdJwtValidator[F, H, C](config, client, _, Clock[F]))

  given [F[_]: Monad, H, C]: Monoid[JwtValidator[F, H, C]] =
    Monoid.instance(notApplicable[F, H, C], _ orElse _)
