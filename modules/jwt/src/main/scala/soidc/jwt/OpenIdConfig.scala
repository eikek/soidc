package soidc.jwt

final case class OpenIdConfig(
    issuer: Uri,
    authorizationEndpoint: Uri,
    tokenEndpoint: Uri,
    userInfoEndpoint: Uri,
    jwksUri: Uri,
    endSessionEndpoint: Option[Uri] = None,
    claimsParameterSupporte: Boolean,
    claimsSupported: List[String] = Nil,
    grantTypesSupported: List[String] = Nil,
    responseTypesSupported: List[String] = Nil,
    idTokenSigningAlgSupported: List[String] = Nil,
    userInfoSigningAlgSupported: List[String] = Nil,
    authorizationSigningAlgSupported: List[String] = Nil
)
