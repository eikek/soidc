package soidc.core.auth

import java.nio.charset.StandardCharsets

import cats.syntax.all.*

import soidc.jwt.JWS
import soidc.jwt.Uri

sealed trait TokenRequest:
  def asMap: Map[String, String]

  lazy val asUrlParameterMap: Map[String, String] =
    asMap.view.mapValues(Util.urlEncode).toMap

  def asUrlQuery: String =
    asUrlParameterMap.map { case (k, v) => s"${k}=${v}" }.mkString("&")

object TokenRequest:
  def refresh(
      refreshToken: JWS,
      clientId: ClientId,
      clientSecret: Option[ClientSecret],
      scope: Option[ScopeList]
  ): TokenRequest =
    Refresh(refreshToken, clientId, clientSecret, scope)

  def code(
      code: AuthorizationCode,
      redirectUri: Uri,
      clientId: ClientId,
      clientSecret: Option[ClientSecret]
  ): TokenRequest =
    Code(code, redirectUri, clientId, clientSecret)

  final case class Code(
      code: AuthorizationCode,
      redirectUri: Uri,
      clientId: ClientId,
      clientSecret: Option[ClientSecret]
  ) extends TokenRequest {
    lazy val asMap: Map[String, String] =
      List(
        "client_id" -> clientId.value.some,
        "client_secret" -> clientSecret.map(_.secret),
        "redirect_uri" -> redirectUri.value.some,
        "grant_type" -> GrantType.AuthorizationCode.render.some,
        "code" -> code.value.some
      ).collect { case (name, Some(v)) => name -> v }.toMap
  }

  final case class Refresh(
      refreshToken: JWS,
      clientId: ClientId,
      clientSecret: Option[ClientSecret],
      scope: Option[ScopeList]
  ) extends TokenRequest {
    lazy val asMap: Map[String, String] =
      List(
        "client_id" -> clientId.value.some,
        "client_secret" -> clientSecret.map(_.secret),
        "grant_type" -> GrantType.RefreshToken.render.some,
        "refresh_token" -> refreshToken.compact.some
      ).collect { case (name, Some(v)) => name -> v }.toMap
  }
