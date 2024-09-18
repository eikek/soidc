package soidc.http4s.routes

import cats.effect.*
import cats.syntax.all.*

import org.http4s.*
import org.http4s.client.Client
import org.http4s.client.dsl.Http4sClientDsl
import org.http4s.dsl.Http4sDsl
import org.http4s.headers.Location
import org.http4s.headers.`Content-Type`
import soidc.core.auth.{AuthorizationCodeResponse as ACR, State as AuthzState, *}
import soidc.core.validate.JwtValidator
import soidc.core.validate.OpenIdJwtValidator
import soidc.core.{JwkGenerate, OpenIdConfig}
import soidc.http4s.client.Http4sClient
import soidc.jwt.codec.ByteDecoder
import soidc.jwt.{Uri as _, *}

trait AuthCodeFlow[F[_]]:
  def validator[H, C](using
      StandardClaims[C],
      StandardHeader[H],
      ByteDecoder[OpenIdConfig],
      ByteDecoder[JWKSet]
  ): JwtValidator[F, H, C]

  def routes(
      cont: Either[AuthCodeFlow.Failure, TokenResponse] => F[Response[F]]
  ): HttpRoutes[F]

  def run(req: Request[F])(
      cont: Either[AuthCodeFlow.Failure, TokenResponse] => F[Response[F]]
  )(using cats.Functor[F]): F[Response[F]]

object AuthCodeFlow:
  final case class Config[F[_]](
      clientId: ClientId,
      providerUri: Uri,
      baseUri: Uri,
      clientSecret: Option[ClientSecret],
      nonce: Option[Nonce],
      logger: String => F[Unit]
  )

  enum Failure:
    case Code(cause: ACR.Result.Failure)
    case StateMismatch

  def apply[F[_]: Sync](cfg: Config[F], client: Client[F])(using
      EntityDecoder[F, OpenIdConfig],
      EntityDecoder[F, TokenResponse]
  ): F[AuthCodeFlow[F]] =
    JwkGenerate
      .symmetric()
      .flatMap(jwk => Ref[F].of(State(jwk)).map(Impl[F](cfg, client, _)))

  private class Impl[F[_]: Sync](
      cfg: Config[F],
      client: Client[F],
      state: Ref[F, State]
  )(using EntityDecoder[F, OpenIdConfig], EntityDecoder[F, TokenResponse])
      extends AuthCodeFlow[F]
      with Http4sDsl[F]
      with Http4sClientDsl[F] {
    val openIdCfgUri = cfg.providerUri / ".well-known" / "openid-configuration"
    val redirectUri = cfg.baseUri / "resume"

    def mkAuthRequest =
      AuthorizationRequest(cfg.clientId, redirectUri.asJwtUri, ResponseType.Code)

    def openIdConfig: F[OpenIdConfig] = state.get.map(_.openIdCfg).flatMap {
      case Some(c) => c.pure[F]
      case None =>
        cfg.logger(s"Fetch openid-config from $openIdCfgUri") >>
          client.expect[OpenIdConfig](openIdCfgUri).flatMap { cfg =>
            state.update(_.withOpenIdConfig(cfg)).as(cfg)
          }
    }

    def validator[H, C](using
        StandardClaims[C],
        StandardHeader[H],
        ByteDecoder[OpenIdConfig],
        ByteDecoder[JWKSet]
    ): JwtValidator[F, H, C] = JwtValidator.selectF[F, H, C] { jws =>
      openIdConfig.flatMap { c =>
        val valCfg = OpenIdJwtValidator
          .Config()
          .withJwksProvider(OpenIdJwtValidator.JwksProvider.StaticJwksUri(c.jwksUri))
        JwtValidator
          .openId(valCfg, Http4sClient(client))
          .map(_.forIssuer(_ == c.issuer.value))
      }
    }

    def routes(
        cont: Either[AuthCodeFlow.Failure, TokenResponse] => F[Response[F]]
    ): HttpRoutes[F] = HttpRoutes.of {
      case GET -> Root =>
        for
          key <- state.get.map(_.key)
          randomState <- AuthzState.randomSigned(key)
          baseReq = mkAuthRequest.withState(randomState).copy(nonce = cfg.nonce)
          authUri <- openIdConfig.map(_.authorizationEndpoint.asUri).map { uri =>
            uri.copy(query = Query.fromPairs(baseReq.asMap.toList*))
          }
          _ <- cfg.logger(show"Redirect to provider: $authUri")
          resp <- TemporaryRedirect(Location(authUri))
        yield resp

      case req @ GET -> Root / "resume" :? Params.StateParam(authState) =>
        state.get.map(_.key).flatMap { key =>
          if (authState.forall(!_.checkWith(key)))
            cfg.logger(s"State does not match") >> cont(Left(Failure.StateMismatch))
          else
            ACR.read(req.params) match
              case r @ ACR.Result.Failure(_) =>
                cfg.logger(s"Authentication failed: ${req.params}") >> cont(
                  Left(Failure.Code(r))
                )

              case ACR.Result.Success(code) =>
                val req = TokenRequest.code(
                  code,
                  redirectUri.asJwtUri,
                  cfg.clientId,
                  cfg.clientSecret
                )
                for
                  _ <- cfg.logger("Authentication successful, obtaining access token…")
                  tokUri <- openIdConfig.map(_.tokenEndpoint.asUri)
                  token <- client.expect[TokenResponse](
                    POST(req.asUrlQuery, tokUri).withContentType(
                      `Content-Type`(MediaType.application.`x-www-form-urlencoded`)
                    )
                  )
                  resp <- cont(Right(token))
                yield resp
        }
    }

    def run(req: Request[F])(
        cont: Either[AuthCodeFlow.Failure, TokenResponse] => F[Response[F]]
    )(using cats.Functor[F]): F[Response[F]] =
      val path = Uri.Path(
        req.uri.path.segments.drop(cfg.baseUri.path.segments.size),
        req.uri.path.absolute,
        req.uri.path.endsWithSlash
      )
      val nr = req.withUri(req.uri.withPath(path))
      routes(cont).orNotFound.run(nr)

    extension (self: soidc.jwt.Uri) def asUri: Uri = Uri.unsafeFromString(self.value)

    extension (self: Uri)
      def asJwtUri: soidc.jwt.Uri =
        soidc.jwt.Uri.unsafeFromString(self.renderString)
  }

  private case class State(
      key: JWK,
      openIdCfg: Option[OpenIdConfig] = None
  ) {
    def withOpenIdConfig(c: OpenIdConfig) = copy(openIdCfg = c.some)

  }
