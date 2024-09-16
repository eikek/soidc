package soidc.core.auth

import java.util.concurrent.TimeUnit

import scala.concurrent.duration.Duration
import scala.concurrent.duration.FiniteDuration

import soidc.jwt.JWS
import soidc.jwt.JwtError
import soidc.jwt.ParameterName
import soidc.jwt.codec.*

final case class TokenResponse(
    accessToken: JWS,
    tokenType: String,
    refreshToken: Option[JWS],
    expiresIn: Option[FiniteDuration],
    idToken: Option[JWS],
    scope: Option[ScopeList],
    values: JsonValue.Obj
)

object TokenResponse:
  private object P {
    val accessToken = ParameterName.of("access_token")
    val tokenType = ParameterName.of("token_type")
    val refreshToken = ParameterName.of("refresh_token")
    val expiresIn = ParameterName.of("expires_in")
    val idToken = ParameterName.of("id_token")
    val scope = ParameterName.of("scope")
  }
  def fromObj(obj: JsonValue.Obj): Either[JwtError.DecodeError, TokenResponse] =
    for
      at <- obj.requireAs[JWS](P.accessToken)
      tt <- obj.requireAs[String](P.tokenType)
      rt <- obj.getAs[JWS](P.refreshToken)
      exp <- obj.getAs[Long](P.expiresIn)
      it <- obj.getAs[JWS](P.idToken)
      sc <- obj.getAs[ScopeList](P.scope)
    yield TokenResponse(at, tt, rt, exp.map(Duration(_, TimeUnit.SECONDS)), it, sc, obj)

  given FromJson[TokenResponse] = FromJson.obj(fromObj)
