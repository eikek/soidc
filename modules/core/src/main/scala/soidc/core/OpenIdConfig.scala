package soidc.core

import cats.syntax.all.*

import soidc.jwt.*
import soidc.jwt.JwtError.DecodeError
import soidc.jwt.json.{FromJson, JsonValue, ToJson}

final case class OpenIdConfig(
    issuer: Uri,
    authorizationEndpoint: Uri,
    tokenEndpoint: Uri,
    userInfoEndpoint: Uri,
    jwksUri: Uri,
    endSessionEndpoint: Option[Uri] = None,
    claimsParameterSupported: Option[Boolean] = None,
    claimsSupported: List[String] = Nil,
    grantTypesSupported: List[String] = Nil,
    responseTypesSupported: List[String] = Nil
)

object OpenIdConfig:
  private object P {
    val issuer = ParameterName.of("issuer")
    val authEndpoint = ParameterName.of("authorization_endpoint")
    val tokenEndpoint = ParameterName.of("token_endpoint")
    val userInfoEndpoint = ParameterName.of("userinfo_endpoint")
    val jwksUri = ParameterName.of("jwks_uri")
    val endSessionEndpoint = ParameterName.of("end_session_endpoint")
    val claimsParamSupported = ParameterName.of("claims_parameter_supported")
    val claimsSupported = ParameterName.of("claims_supported")
    val grantTypesSupported = ParameterName.of("grant_types_supported")
    val responseTypesSupported = ParameterName.of("response_types_supported")
  }

  def fromObj(obj: JsonValue.Obj): Either[DecodeError, OpenIdConfig] =
    for
      issuer <- obj.requireAs[Uri](P.issuer)
      authEp <- obj.requireAs[Uri](P.authEndpoint)
      tokEp <- obj.requireAs[Uri](P.tokenEndpoint)
      userEp <- obj.requireAs[Uri](P.userInfoEndpoint)
      jwks <- obj.requireAs[Uri](P.jwksUri)
      endEp <- obj.getAs[Uri](P.endSessionEndpoint)
      clPS <- obj.getAs[Boolean](P.claimsParamSupported)
      cs <- obj.getAs[List[String]](P.claimsSupported)
      gts <- obj.getAs[List[String]](P.grantTypesSupported)
      rts <- obj.getAs[List[String]](P.responseTypesSupported)
    yield OpenIdConfig(
      issuer,
      authEp,
      tokEp,
      userEp,
      jwks,
      endEp,
      clPS,
      cs.orEmpty,
      gts.orEmpty,
      rts.orEmpty
    )

  given FromJson[OpenIdConfig] =
    FromJson.obj(fromObj)

  given ToJson[OpenIdConfig] =
    ToJson.instance(cfg =>
      JsonValue.emptyObj
        .replace(P.issuer, cfg.issuer)
        .replace(P.authEndpoint, cfg.authorizationEndpoint)
        .replace(P.tokenEndpoint, cfg.tokenEndpoint)
        .replace(P.userInfoEndpoint, cfg.userInfoEndpoint)
        .replace(P.jwksUri, cfg.jwksUri)
        .replaceIfDefined(P.endSessionEndpoint, cfg.endSessionEndpoint)
        .replace(P.claimsSupported, cfg.claimsSupported)
        .replace(P.grantTypesSupported, cfg.grantTypesSupported)
        .replace(P.responseTypesSupported, cfg.responseTypesSupported)
    )
