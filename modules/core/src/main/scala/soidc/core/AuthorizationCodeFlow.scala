package soidc.core

import cats.data.OptionT
import cats.effect.*
import cats.syntax.all.*

import soidc.core.AuthorizationCodeFlow.Failure
import soidc.core.model.*
import soidc.core.model.AuthorizationCodeResponse as ACR
import soidc.jwt.*
import soidc.jwt.codec.ByteDecoder

trait AuthorizationCodeFlow[F[_], H, C] extends Realm[F, H, C]:
  /** Creates the authorization uri for redirecting the user agent to the auth provider.
    */
  def authorizeUrl(redirectUri: Uri): F[Uri]

  /** Creates the logout uri for redirecting the user-agent to logout the user. This might
    * not be supported by the OP.
    */
  def logoutUrl(req: LogoutRequest): F[Option[Uri]]

  /** Get the access token with the query parameters from the redirect request. */
  def obtainToken(
      redirectUri: Uri,
      reqParams: Map[String, String]
  ): F[Either[Failure, TokenResponse.Success]]

  /** Get a new access token using the given refresh token. */
  def runRefreshRequest(refreshToken: JWS): F[TokenResponse]

  /** The token store used for `jwtRefresh`. */
  def tokenStore: TokenStore[F, H, C]

object AuthorizationCodeFlow:
  final case class Config(
      clientId: ClientId,
      clientSecret: Option[ClientSecret],
//      redirectUri: Uri,
      providerUri: Uri,
      privateKey: JWK,
      scope: Option[ScopeList] = None,
      nonce: Option[Nonce] = None
  )

  enum Failure:
    case Code(cause: ACR.Result.Failure)
    case Token(cause: TokenResponse.Error)
    case StateMismatch

  def apply[F[_], H, C](
      cfg: Config,
      client: HttpClient[F],
      tokenStore: TokenStore[F, H, C],
      logger: Logger[F]
  )(using
      StandardClaimsRead[C],
      StandardHeaderRead[H],
      ByteDecoder[OpenIdConfig],
      ByteDecoder[TokenResponse],
      ByteDecoder[JWKSet],
      ByteDecoder[H],
      ByteDecoder[C],
      Sync[F]
  ): F[AuthorizationCodeFlow[F, H, C]] =
    Ref[F].of(FlowState()).map(new Impl(cfg, client, tokenStore, logger, _))

  private class Impl[F[_], H, C](
      cfg: Config,
      client: HttpClient[F],
      val tokenStore: TokenStore[F, H, C],
      logger: Logger[F],
      flowState: Ref[F, FlowState]
  )(using
      StandardClaimsRead[C],
      StandardHeaderRead[H],
      ByteDecoder[OpenIdConfig],
      ByteDecoder[TokenResponse],
      ByteDecoder[JWKSet],
      ByteDecoder[H],
      ByteDecoder[C],
      Sync[F]
  ) extends AuthorizationCodeFlow[F, H, C] {
    def authorizeUrl(redirectUri: Uri): F[Uri] =
      for
        randomState <- State.randomSigned[F](cfg.privateKey)
        baseReq = AuthorizationRequest(
          cfg.clientId,
          redirectUri,
          ResponseType.Code,
          cfg.scope.getOrElse(ScopeList()),
          randomState.some,
          None,
          cfg.nonce,
          None,
          None
        )
        authUri <- openIdConfig.map(_.authorizationEndpoint).map { uri =>
          uri.appendQuery(baseReq.asMap)
        }
      yield authUri

    def logoutUrl(req: LogoutRequest): F[Option[Uri]] =
      (for
        endpoint <- OptionT(openIdConfig.map(_.endSessionEndpoint))
        randomState <- OptionT.liftF(State.randomSigned[F](cfg.privateKey))
        rreq = req.state
          .map(_ => req)
          .getOrElse(req.withState(randomState))
          .withClientId(cfg.clientId)
        result = endpoint.appendQuery(rreq.asMap)
      yield result).value

    def isIssuer(jws: JWSDecoded[H, C])(using StandardClaims[C]): Boolean =
      StandardClaims[C].issuer(jws.claims).exists(_.value == cfg.providerUri.value)

    def obtainToken(
        redirectUri: Uri,
        reqParams: Map[String, String]
    ): F[Either[Failure, TokenResponse.Success]] =
      val authState = reqParams.get("state").map(State.fromString)
      if (authState.forall(!_.checkWith(cfg.privateKey)))
        Left(Failure.StateMismatch).pure[F]
      else
        ACR.read(reqParams) match
          case r @ ACR.Result.Failure(_) =>
            Left(Failure.Code(r)).pure[F]

          case ACR.Result.Success(code) =>
            val req = TokenRequest.code(
              code,
              redirectUri,
              cfg.clientId,
              cfg.clientSecret
            )
            for
              tokUri <- openIdConfig.map(_.tokenEndpoint)
              _ <- logger.debug(
                s"Authentication successful, obtaining access token: $tokUri"
              )
              token <- client.getToken(tokUri, req)
              resp = token.fold(err => Left(Failure.Token(err)), Right(_))
            yield resp

    def runRefreshRequest(refreshToken: JWS): F[TokenResponse] =
      val req =
        TokenRequest.refresh(refreshToken, cfg.clientId, cfg.clientSecret, cfg.scope)
      for
        tokUri <- openIdConfig.map(_.tokenEndpoint)
        _ <- logger.debug(s"Refresh access token: $tokUri")
        token <- client.getToken(tokUri, req)
      yield token

    def validator: JwtValidator[F, H, C] = JwtValidator.selectF[F, H, C] { jws =>
      openIdConfig.flatMap { c =>
        val valCfg = OpenIdJwtValidator
          .Config()
          .withJwksProvider(OpenIdJwtValidator.JwksProvider.StaticJwksUri(c.jwksUri))
        JwtValidator
          .openId(valCfg, client)
          .map(_.forIssuer(_ == c.issuer.value))
      }
    }

    def jwtRefresh: JwtRefresh[F, H, C] =
      cfg.clientSecret match
        case None => JwtRefresh.passthrough[F, H, C]
        case Some(secret) =>
          JwtRefresh.liftF(openIdConfig.map(mkOpenidRefresh(secret, _)))

    def mkOpenidRefresh(secret: ClientSecret, oidCfg: OpenIdConfig) =
      val rc = OpenIdRefresh.Config(
        cfg.clientId,
        secret,
        oidCfg.tokenEndpoint.pure[F],
        cfg.scope
      )
      OpenIdRefresh[F, H, C](client, tokenStore, rc).forIssuer(_ == oidCfg.issuer.value)

    def openIdConfig: F[OpenIdConfig] = flowState.get.map(_.openidConfig).flatMap {
      case Some(c) => c.pure[F]
      case None =>
        val cfgUri = cfg.providerUri.addPath(".well-known/openid-configuration")
        logger.debug(s"Fetch openid-config from $cfgUri") >>
          client.get[OpenIdConfig](cfgUri).flatMap { cfg =>
            flowState.update(_.copy(openidConfig = Some(cfg))).as(cfg)
          }
    }
  }

  private case class FlowState(openidConfig: Option[OpenIdConfig] = None)
