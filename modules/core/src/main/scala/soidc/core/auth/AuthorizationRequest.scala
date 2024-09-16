package soidc.core.auth

import soidc.core.OpenIdConfig
import soidc.jwt.Uri

final case class AuthorizationRequest(
    endpoint: Uri,
    clientId: ClientId,
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

  def withEndpoint(uri: Uri): AuthorizationRequest =
    copy(endpoint = uri)

  def withEndpoint(cfg: OpenIdConfig): AuthorizationRequest =
    withEndpoint(cfg.authorizationEndpoint)

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
