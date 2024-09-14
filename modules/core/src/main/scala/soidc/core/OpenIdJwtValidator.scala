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
  override def toString(): String = s"OpenIdJwtValidator(config=$config, client=$client)"

  def validate(jws: JWSDecoded[H, C]): F[Result] =
    create.validate(jws)

  def create: JwtValidator[F, H, C] =
    JwtValidator.selectF[F, H, C] { jws =>
      StandardClaims[C]
        .issuer(jws.claims)
        .flatMap(s => Uri.fromString(s.value).toOption) match
        case None =>
          config.jwksProvider match
            case JwksProvider.FromIssuer(_) =>
              JwtValidator.notApplicable[F, H, C].pure[F]
            case _ =>
              val dummyIssuer = Uri.unsafeFromString("static:")
              state.get.map(_.get(dummyIssuer)).flatMap(s => create(dummyIssuer, s.jwks))

        case Some(issuer) =>
          state.get.map(_.get(issuer)).flatMap(s => create(issuer, s.jwks))
    }

  def create(issuer: Uri, jwks: JWKSet): F[JwtValidator[F, H, C]] =
    val v1 = JwtValidator
      .validateWithJWKSet(jwks, clock, config.timingLeeway)
      .invalidToNotApplicable
    val v2 = fetchJWKSetGuarded(issuer).map { jwks =>
      JwtValidator.validateWithJWKSet(jwks, clock, config.timingLeeway)
    }
    v2.map(v1.orElse(_))

  def fetchJWKSetGuarded(issuer: Uri): F[JWKSet] =
    for
      _ <- checkLastUpdateDelay(issuer, config.minRequestDelay)
      result <- fetchJWKSet(issuer)
    yield result

  def checkLastUpdateDelay(
      issuer: Uri,
      min: FiniteDuration
  ): F[Unit] =
    clock.monotonic
      .flatMap(ct => state.modify(_.setLastUpdateDelay(issuer, ct)))
      .flatMap {
        case delay if delay > min => ().pure[F]
        case _ => MonadThrow[F].raiseError(SoidcError.TooManyValidationRequests(min))
      }

  def getOpenIdConfig(uri: Uri): F[OpenIdConfig] =
    EitherT(client.get[OpenIdConfig](uri).attempt)
      .leftMap(ex => SoidcError.OpenIdConfigError(uri, ex))
      .rethrowT

  def getJWKSet(uri: Uri): F[JWKSet] =
    EitherT(client.get[JWKSet](uri).attempt)
      .leftMap(ex => SoidcError.JwksError(uri, ex))
      .rethrowT

  def findJWKSet(issuerUri: Uri) = config.jwksProvider match
    case JwksProvider.FromIssuer(path) =>
      getOpenIdConfig(issuerUri.addPath(path)).flatMap(c => getJWKSet(c.jwksUri))
    case JwksProvider.StaticJwksUri(uri) => getJWKSet(uri)
    case JwksProvider.StaticOpenIdUri(uri) =>
      getOpenIdConfig(uri).flatMap(c => getJWKSet(c.jwksUri))

  def fetchJWKSet(issuerUri: Uri): F[JWKSet] =
    for
      _ <- clock.monotonic.flatMap(t => state.update(_.setLastUpdate(issuerUri, t)))
      jwks <- findJWKSet(issuerUri)
      _ <- state.update(_.setJwks(issuerUri, jwks))
    yield jwks

object OpenIdJwtValidator:
  /** Configuration settings for [[OpenIdJwtValidator]]
    *
    * @param minRequestDelay
    *   minimum delay between requests to fetch an JWKS
    * @param jwksProvider
    *   how to retrieve a JWKSet finally used to verify the token
    * @param timingLeeway
    *   A short duration to extend timing validation (nbf and exp) to make up for clock
    *   skew
    */
  final case class Config(
      minRequestDelay: FiniteDuration = 1.minute,
      timingLeeway: FiniteDuration = 30.seconds,
      jwksProvider: JwksProvider = JwksProvider.FromIssuer()
  ):
    def withJwksProvider(p: JwksProvider): Config =
      copy(jwksProvider = p)

    def withJwksUri(uri: Uri): Config =
      withJwksProvider(JwksProvider.StaticJwksUri(uri))

    def withOpenIdConfigUri(uri: Uri): Config =
      withJwksProvider(JwksProvider.StaticOpenIdUri(uri))

  enum JwksProvider:
    case FromIssuer(path: String = ".well-known/openid-configuration")
    case StaticOpenIdUri(uri: Uri)
    case StaticJwksUri(uri: Uri)

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
