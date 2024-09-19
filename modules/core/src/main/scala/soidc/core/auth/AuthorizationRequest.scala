package soidc.core.auth

import java.nio.charset.StandardCharsets

import cats.syntax.all.*

import soidc.jwt.Uri

final case class AuthorizationRequest(
    clientId: ClientId,
    redirectUri: Uri,
    responseType: ResponseType,
    scopes: ScopeList = ScopeList(),
    state: Option[State] = None,
    responseMode: Option[ResponseMode] = None,
    nonce: Option[Nonce] = None,
    prompt: Option[Prompt] = None,
    maxAge: Option[MaxAge] = None
):
  def withClientId(id: ClientId): AuthorizationRequest =
    copy(clientId = id)

  def withRedirectUri(uri: Uri): AuthorizationRequest =
    copy(redirectUri = uri)

  def withResponseType(rt: ResponseType): AuthorizationRequest =
    copy(responseType = rt)

  def withScopes(scopes: ScopeList): AuthorizationRequest =
    copy(scopes = scopes)

  def addScope(scope: Scope): AuthorizationRequest =
    copy(scopes = scopes + scope)

  def withState(state: State): AuthorizationRequest =
    copy(state = Some(state))

  def withResponseMode(rm: ResponseMode): AuthorizationRequest =
    if (rm.isDefault) copy(responseMode = None)
    else copy(responseMode = Some(rm))

  def withNonce(n: Nonce): AuthorizationRequest =
    copy(nonce = Some(n))

  def withPrompt(p: Prompt): AuthorizationRequest =
    copy(prompt = Some(p))

  def withMaxAge(ma: MaxAge): AuthorizationRequest =
    copy(maxAge = Some(ma))

  lazy val asMap: Map[String, String] =
    List(
      "client_id" -> clientId.value.some,
      "redirect_uri" -> redirectUri.value.some,
      "response_type" -> responseType.render.some,
      "scope" -> scopes.render.some,
      "state" -> state.map(_.render),
      "response_mode" -> responseMode.map(_.render),
      "nonce" -> nonce.map(_.render),
      "prompt" -> prompt.map(_.render),
      "max_age" -> maxAge.map(_.render)
    ).collect { case (param, Some(v)) => param -> v }.toMap

  lazy val asUrlParameterMap: Map[String, String] =
    asMap.view.mapValues(Util.urlEncode).toMap

  def asUrlQuery: String =
    asUrlParameterMap.map { case (k, v) => s"${k}=${v}" }.mkString("&")
