package soidc.core.model

/** A request to the `device_authorization_endpoint` */
final case class DeviceCodeRequest(
    clientId: ClientId,
    clientSecret: Option[ClientSecret] = None,
    scope: Option[ScopeList] = None
):
  def withClientId(clientId: ClientId): DeviceCodeRequest =
    copy(clientId = clientId)

  def withClientSecret(secret: ClientSecret): DeviceCodeRequest =
    copy(clientSecret = Some(secret))

  lazy val asMap: Map[String, String] =
    List(
      "client_id" -> clientId.value,
      "client_secret" -> clientSecret.map(_.secret),
      "scope" -> scope.map(_.render)
    ).collect { case (param, Some(v)) => param -> v }.toMap

  lazy val asUrlParameterMap: Map[String, String] =
    asMap.map { case (k, v) => Util.urlEncode(k) -> Util.urlEncode(v) }

  def asUrlQuery: String =
    asUrlParameterMap.map { case (k, v) => s"${k}=${v}" }.mkString("&")
