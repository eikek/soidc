package soidc.core

import cats.effect.*
import cats.syntax.all.*

import soidc.core.AuthorizationCodeFlow.Failure
import soidc.core.model.{AuthorizationCodeResponse as ACR, *}
import soidc.jwt.JWK
import soidc.jwt.Uri
import soidc.jwt.codec.ByteDecoder

trait GitHubOAuth[F[_]]:
  /** Creates the authorization uri for redirecting the user agent to GitHub. */
  def authorizeUrl(redirectUri: Uri): F[Uri]

  /** Get the access token with the query parameters from the redirect request. */
  def obtainToken(
      redirectUri: Uri,
      reqParams: Map[String, String]
  ): F[Either[Failure, TokenResponse.Success]]

  def getUserInfo(accessToken: String): F[GitHubUser]

object GitHubOAuth:
  final case class Config(
      clientId: ClientId,
      privateKey: JWK,
      clientSecret: Option[ClientSecret] = None,
      scope: Option[ScopeList] = None,
      authorizeEndpoint: Uri =
        Uri.unsafeFromString("https://github.com/login/oauth/authorize"),
      tokenEndpoint: Uri =
        Uri.unsafeFromString("https://github.com/login/oauth/access_token"),
      userEndpoint: Uri = Uri.unsafeFromString("https://api.github.com/user")
  )

  def apply[F[_]: Sync](
      cfg: Config,
      client: HttpClient[F],
      logger: Logger[F]
  )(using ByteDecoder[TokenResponse], ByteDecoder[GitHubUser]): GitHubOAuth[F] =
    new Impl[F](cfg, client, logger)

  private class Impl[F[_]: Sync](
      cfg: Config,
      client: HttpClient[F],
      logger: Logger[F]
  )(using ByteDecoder[TokenResponse], ByteDecoder[GitHubUser])
      extends GitHubOAuth[F] {
    def authorizeUrl(redirectUri: Uri): F[Uri] =
      for
        randomState <- State.randomSigned[F](cfg.privateKey)
        baseReq = AuthorizationRequest(
          clientId = cfg.clientId,
          redirectUri = redirectUri,
          responseType = ResponseType.Code,
          state = randomState.some
        )
        params = baseReq.asMap.removed("response_type")
        withScopes = cfg.scope match {
          case None => params.removed("scope")
          case Some(sl) =>
            val names =
              sl.scopes.toList.filter(_ != Scope.OpenId).map(_.name).mkString(" ")
            params.updated("scope", names)
        }
        authUri = cfg.authorizeEndpoint.appendQuery(withScopes)
      yield authUri

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
              _ <- logger.debug(
                s"Authentication successful, obtaining access token: ${cfg.tokenEndpoint}"
              )
              token <- client.getToken(cfg.tokenEndpoint, req)
              resp = token.fold(err => Left(Failure.Token(err)), Right(_))
            yield resp

    def getUserInfo(accessToken: String): F[GitHubUser] =
      client.get(cfg.userEndpoint, Some(accessToken))
  }
