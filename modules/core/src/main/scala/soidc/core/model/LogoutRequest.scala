package soidc.core.model

import soidc.jwt.JWS
import soidc.jwt.Uri

/** A request to the `end_session_endpoint` */
final case class LogoutRequest(
    idTokenHint: Option[JWS] = None,
    logoutHint: Option[String] = None,
    clientId: Option[ClientId] = None,
    postLogoutRedirectUri: Option[Uri] = None,
    state: Option[State] = None
):

  def withIdToken(idt: JWS): LogoutRequest =
    copy(idTokenHint = Some(idt))

  def withLogoutHint(hint: String): LogoutRequest =
    copy(logoutHint = Some(hint))

  def withClientId(clientId: ClientId): LogoutRequest =
    copy(clientId = Some(clientId))

  def withPostLogoutRedirectUri(uri: Uri): LogoutRequest =
    copy(postLogoutRedirectUri = Some(uri))

  def withState(state: State): LogoutRequest =
    copy(state = Some(state))

  lazy val asMap: Map[String, String] =
    List(
      "id_token_hint" -> idTokenHint.map(_.compact),
      "logout_hint" -> logoutHint,
      "client_id" -> clientId.map(_.value),
      "post_logout_redirect_uri" -> postLogoutRedirectUri.map(_.value),
      "state" -> state.map(_.render)
    ).collect { case (param, Some(v)) => param -> v }.toMap

  lazy val asUrlParameterMap: Map[String, String] =
    asMap.map { case (k, v) => Util.urlEncode(k) -> Util.urlEncode(v) }

  def asUrlQuery: String =
    asUrlParameterMap.map { case (k, v) => s"${k}=${v}" }.mkString("&")
