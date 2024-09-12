package soidc.core

import scala.concurrent.duration.*

import cats.MonadThrow
import cats.data.EitherT
import cats.effect.*
import cats.syntax.all.*

import soidc.core.JwtValidator.Result
import soidc.core.OpenIdJwtValidator.*
import soidc.jwt.*
import soidc.jwt.json.JsonDecoder

final class OpenIdJwtValidator[F[_], H, C](
    config: Config,
    client: HttpClient[F],
    state: Ref[F, State],
    clock: Clock[F]
)(using
    StandardClaims[C],
    StandardHeader[H],
    MonadThrow[F],
    JsonDecoder[OpenIdConfig],
    JsonDecoder[JWKSet]
) extends JwtValidator[F, H, C]:

  def validate(jws: JWSDecoded[H, C]): F[Result] =
    create.validate(jws)

  def create = JwtValidator.selectF[F, H, C] { jws =>
    StandardClaims[C]
      .issuer(jws.claims)
      .flatMap(s => Uri.fromString(s.value).toOption) match
      case None => JwtValidator.notApplicable[F, H, C].pure[F]
      case Some(issuer) =>
        for
          jwks <- state.get.map(_.get(issuer))
          v1 = JwtValidator.validateWithJWKSet(jwks.jwks, clock).invalidToNone
          v2 <- fetchJWKSetGuarded(issuer).value.map {
            case Right(jwks) => JwtValidator.validateWithJWKSet(jwks, clock)
            case Left(err)   => JwtValidator.failure(err)
          }
        yield v1 orElse v2
  }

  def fetchJWKSetGuarded(issuer: Uri): EitherT[F, SoidcError, JWKSet] =
    for
      _ <- checkLastUpdateDelay(issuer, config.minRequestDelay)
      result <- fetchJWKSet(issuer)
    yield result

  def checkLastUpdateDelay(
      issuer: Uri,
      min: FiniteDuration
  ): EitherT[F, SoidcError, Unit] =
    EitherT(
      clock.monotonic.flatMap(ct => state.modify(_.setLastUpdateDelay(issuer, ct))).map {
        case delay if delay > min => Right(())
        case _                    => Left(SoidcError.TooManyValidationRequests(min))
      }
    )

  def fetchJWKSet(issuerUri: Uri): EitherT[F, SoidcError, JWKSet] =
    for
      _ <- EitherT.right(
        clock.monotonic.flatMap(t => state.update(_.setLastUpdate(issuerUri, t)))
      )
      configUri = issuerUri.addPath(config.openIdConfigPath)
      openIdCfg <- EitherT(client.get[OpenIdConfig](configUri).attempt)
        .leftMap(ex => SoidcError.OpenIdConfigError(configUri, ex))
      jwks <- EitherT(client.get[JWKSet](openIdCfg.jwksUri).attempt)
        .leftMap(ex => SoidcError.JwksError(openIdCfg.jwksUri, ex))

      _ <- EitherT.right(state.update(_.setJwks(issuerUri, jwks)))
    yield jwks

object OpenIdJwtValidator:
  /** Configuration settings for [[OpenIdJwtValidator]]
    *
    * @param minRequestDelay
    *   minimum delay between requests to fetch an JWKS
    * @param openIdConfigPath
    *   the uri path part after the issuer url that denotes the endpoint to get the
    *   configuration data from
    * @param timingLeeway
    *   A short duration to extend timing validation (nbf and exp) to make up for clock
    *   skew
    */
  final case class Config(
      minRequestDelay: FiniteDuration = 1.minute,
      timingLeeway: FiniteDuration = 30.seconds,
      openIdConfigPath: String = ".well-known/openid-configuration"
  )

  /** For maintaining last fetch and access of this JWKS */
  final case class JwksState(
      jwks: JWKSet = JWKSet.empty,
      lastUpdate: FiniteDuration = Duration.Zero,
      lastAccess: FiniteDuration = Duration.Zero
  ):
    def lastUpdateDelay(now: FiniteDuration): (JwksState, FiniteDuration) =
      (copy(lastAccess = now), now - lastUpdate)

  /** Maintains a `JwksState` per issuer. */
  final case class State(jwks: Map[String, JwksState] = Map.empty):
    def get(issuer: Uri): JwksState =
      jwks.getOrElse(issuer.value, JwksState())

    def modify(issuer: Uri, f: JwksState => JwksState): State =
      copy(jwks = jwks.updatedWith(issuer.value) {
        case Some(v) => Some(f(v))
        case None    => Some(f(JwksState()))
      })

    def setLastUpdate(issuer: Uri, time: FiniteDuration): State =
      modify(issuer, _.copy(lastUpdate = time))

    def setJwks(issuer: Uri, data: JWKSet): State =
      modify(issuer, _.copy(jwks = data))

    def setLastUpdateDelay(issuer: Uri, now: FiniteDuration): (State, FiniteDuration) =
      val issuerUri = issuer.value
      val (ns, time) = get(issuer).lastUpdateDelay(now)
      (copy(jwks = jwks.updated(issuerUri, ns)), time)

  object State:
    def of(
        issuer: Uri,
        jwks: JWKSet = JWKSet.empty,
        lastUpdate: FiniteDuration = Duration.Zero,
        lastAccess: FiniteDuration = Duration.Zero
    ): State =
      State(Map(issuer.value -> JwksState(jwks, lastUpdate, lastAccess)))
