package soidc.core.validate

import scala.concurrent.duration.FiniteDuration

import cats.Applicative
import cats.MonadThrow
import cats.data.Kleisli
import cats.effect.*
import cats.syntax.all.*
import cats.{Monad, Monoid}

import soidc.core.*
import soidc.core.validate.JwtValidator.Result
import soidc.jwt.*
import soidc.jwt.codec.ByteDecoder

/** Validate JWT token. */
trait JwtValidator[F[_], H, C]:

  def validate(jws: JWSDecoded[H, C]): F[Result]

  /** Run this validator and then `next` and combine their results. */
  infix def ++(next: JwtValidator[F, H, C])(using Monad[F]): JwtValidator[F, H, C] =
    import Result.*
    JwtValidator.instance(jws =>
      validate(jws).flatMap(r1 => next.validate(jws).map(r2 => r1 + r2))
    )

  /** Run this validator and then the result of `next` and combine their results. */
  def andThen(next: Result => JwtValidator[F, H, C])(using
      Monad[F]
  ): JwtValidator[F, H, C] =
    import Result.*
    JwtValidator.instance(jws =>
      validate(jws).flatMap(r1 => next(r1).validate(jws).map(r2 => r1 + r2))
    )

  /** If this validator returns a "not applicable" result, the `next` validator is tried.
    */
  infix def orElse(
      next: => JwtValidator[F, H, C]
  )(using Monad[F]): JwtValidator[F, H, C] =
    JwtValidator.instance { jws =>
      validate(jws).flatMap {
        case Result.NotApplicable(_) => next.validate(jws)
        case r                       => r.pure[F]
      }
    }

  /** If this validator returns a "not applicable" result, the `next` validator is tried.
    */
  infix def orElseF(
      next: => F[JwtValidator[F, H, C]]
  )(using Monad[F]): JwtValidator[F, H, C] =
    JwtValidator.instance { jws =>
      validate(jws).flatMap {
        case Result.NotApplicable(_) => next.flatMap(_.validate(jws))
        case r                       => r.pure[F]
      }
    }

  /** Converts an invalid result to a not-applicable result. */
  def invalidToNotApplicable(using Monad[F]): JwtValidator[F, H, C] =
    JwtValidator.instance { jws =>
      validate(jws).map {
        case Result.Validated(Validate.Result.Failure(_)) =>
          Result.notApplicable
        case r => r
      }
    }

  /** Return a not-applicable result if the result of `enable` is false. Otherwise run
    * this validator.
    */
  def scoped(enable: JWSDecoded[H, C] => Boolean)(using
      Applicative[F]
  ): JwtValidator[F, H, C] =
    JwtValidator.instance(jws =>
      if (enable(jws)) validate(jws) else Result.notApplicable.pure[F]
    )

  /** Scopes this validator to only apply if an issuer exists in the claim and it matches
    * the given function.
    */
  def forIssuer(f: String => Boolean)(using
      sc: StandardClaims[C],
      F: Applicative[F]
  ): JwtValidator[F, H, C] =
    scoped(jws => sc.issuer(jws.claims).map(_.value).exists(f))

  def toDecodingValidator(using Applicative[F]): JwtDecodingValidator[F, H, C] =
    JwtDecodingValidator.from(this)

object JwtValidator:
  type Result = Option[Validate.Result]

  object Result {
    def pure(valid: Validate.Result): Result = Some(valid)
    def notApplicable: Result = None
    def success: Result = pure(Validate.Result.success)
    def failed(reason: Validate.FailureReason): Result = pure(
      Validate.Result.failed(reason)
    )

    object NotApplicable {
      def unapply(r: Result): Option[Unit] =
        r match {
          case None => Some(())
          case _    => None
        }
    }
    object Validated {
      def unapply(r: Result): Option[Validate.Result] =
        r
    }

    extension (self: Result)
      def +(next: Result): Result =
        (self, next) match
          case (Some(a), Some(b)) => Some(a + b)
          case (None, b)          => b
          case (a, None)          => a
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

  def select[F[_], H, C](
      f: JWSDecoded[H, C] => JwtValidator[F, H, C]
  ): JwtValidator[F, H, C] =
    instance(jws => f(jws).validate(jws))

  def selectF[F[_], H, C](
      f: JWSDecoded[H, C] => F[JwtValidator[F, H, C]]
  )(using Monad[F]): JwtValidator[F, H, C] =
    instance(jws => f(jws).flatMap(_.validate(jws)))

  def pure[F[_]: Applicative, H, C](result: Result): JwtValidator[F, H, C] =
    instance(_ => result.pure[F])

  def invalid[F[_]: Applicative, H, C](
      reason: Validate.FailureReason = Validate.FailureReason.GenericReason("JWT invalid")
  ): JwtValidator[F, H, C] =
    pure(Result.failed(reason))

  def alwaysValid[F[_]: Applicative, H, C]: JwtValidator[F, H, C] =
    pure(Result.success)

  def notApplicable[F[_]: Applicative, H, C]: JwtValidator[F, H, C] =
    pure(Result.notApplicable)

  def validateTimingOnly[F[_], H, C](clock: Clock[F], timingLeeway: FiniteDuration)(using
      StandardClaims[C],
      Monad[F]
  ): JwtValidator[F, H, C] =
    instance(jws =>
      clock.realTimeInstant.map(
        jws.validateWithoutSignature(_, timingLeeway).some
      )
    )

  def validateWithKey[F[_], H, C](
      jwk: JWK,
      clock: Clock[F],
      timingLeeway: FiniteDuration
  )(using
      StandardClaims[C],
      StandardHeader[H],
      Monad[F]
  ): JwtValidator[F, H, C] =
    instance(jws => clock.realTimeInstant.map(jws.validate(jwk, _, timingLeeway).some))

  def validateWithJWKSet[F[_], H, C](
      jwks: JWKSet,
      clock: Clock[F],
      timingLeeway: FiniteDuration
  )(using StandardHeader[H], StandardClaims[C], Monad[F]): JwtValidator[F, H, C] =
    validateTimingOnly(clock, timingLeeway) ++ instance(jws =>
      Result.pure(Validate.validateSignature(jwks, jws)).pure[F]
    )

  def openId[F[_], H, C](config: OpenIdJwtValidator.Config, client: HttpClient[F])(using
      StandardClaims[C],
      StandardHeader[H],
      MonadThrow[F],
      ByteDecoder[OpenIdConfig],
      ByteDecoder[JWKSet],
      Ref.Make[F],
      Clock[F]
  ): F[JwtValidator[F, H, C]] =
    Ref[F]
      .of(OpenIdJwtValidator.State())
      .map(OpenIdJwtValidator[F, H, C](config, client, _, Clock[F]))

  given [F[_]: Monad, H, C]: Monoid[JwtValidator[F, H, C]] =
    Monoid.instance(notApplicable[F, H, C], _ ++ _)
