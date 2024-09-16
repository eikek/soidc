package soidc.core.auth

import java.nio.charset.StandardCharsets

import cats.syntax.all.*

import soidc.jwt.Uri

final case class TokenRequest(
    grantType: GrantType,
    code: AuthorizationCode,
    redirectUri: Uri,
    clientId: ClientId,
    clientSecret: Option[ClientSecret]
):

  def withGrantType(gt: GrantType): TokenRequest =
    copy(grantType = gt)

  def withCode(code: AuthorizationCode): TokenRequest =
    copy(code = code)

  def withClientId(id: ClientId): TokenRequest =
    copy(clientId = id)

  def withRedirectUri(uri: Uri): TokenRequest =
    copy(redirectUri = uri)

  lazy val asMap: Map[String, String] =
    List(
      "client_id" -> clientId.value.some,
      "client_secret" -> clientSecret.map(_.secret),
      "redirect_uri" -> redirectUri.value.some,
      "grant_type" -> grantType.render.some,
      "code" -> code.value.some
    ).collect { case (name, Some(v)) => name -> v }.toMap

  private inline def encodeParam(s: String): String =
    java.net.URLEncoder.encode(s, StandardCharsets.UTF_8)

  lazy val asUrlParameterMap: Map[String, String] =
    asMap.view.mapValues(encodeParam).toMap

  def asUrlQuery: String =
    asUrlParameterMap.map { case (k, v) => s"${k}=${v}" }.mkString("&")

object TokenRequest:
  def code(
      code: AuthorizationCode,
      redirectUri: Uri,
      clientId: ClientId,
      clientSecret: Option[ClientSecret]
  ): TokenRequest =
    TokenRequest(GrantType.AuthorizationCode, code, redirectUri, clientId, clientSecret)
