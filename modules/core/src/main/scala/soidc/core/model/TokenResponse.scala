package soidc.core.model

import scala.concurrent.duration.*

import soidc.jwt.*
import soidc.jwt.codec.*

sealed trait TokenResponse:
  def isSuccess: Boolean = fold(_ => false, _ => true)
  def isError: Boolean = !isSuccess

  def fold[A](fe: TokenResponse.Error => A, fs: TokenResponse.Success => A): A

object TokenResponse:
  given FromJson[TokenResponse] =
    FromJson[Error].widen[TokenResponse].orElse(FromJson[Success].widen[TokenResponse])

  final case class Success(
      accessToken: String,
      tokenType: String,
      refreshToken: Option[String],
      expiresIn: Option[FiniteDuration],
      idToken: Option[String],
      scope: Option[ScopeList],
      values: JsonValue.Obj
  ) extends TokenResponse {
    def fold[A](fe: TokenResponse.Error => A, fs: TokenResponse.Success => A): A =
      fs(this)

    def accessTokenJWS: Either[JwtError.DecodeError, JWS] =
      JWS.fromString(accessToken)

    def idTokenJWS: Option[Either[JwtError.DecodeError, JWS]] =
      idToken.map(JWS.fromString)

    def refreshTokenJWS: Option[Either[JwtError.DecodeError, JWS]] =
      refreshToken.map(JWS.fromString)
  }

  object Success {
    private object P {
      val accessToken = ParameterName.of("access_token")
      val tokenType = ParameterName.of("token_type")
      val refreshToken = ParameterName.of("refresh_token")
      val expiresIn = ParameterName.of("expires_in")
      val idToken = ParameterName.of("id_token")
      val scope = ParameterName.of("scope")
    }
    def fromObj(obj: JsonValue.Obj): Either[JwtError.DecodeError, Success] =
      for
        at <- obj.requireAs[String](P.accessToken)
        tt <- obj.requireAs[String](P.tokenType)
        rt <- obj.getAs[String](P.refreshToken)
        exp <- obj.getAs[Long](P.expiresIn)
        it <- obj.getAs[String](P.idToken)
        sc <- obj.getAs[ScopeList](P.scope)
      yield Success(at, tt, rt, exp.map(_.seconds), it, sc, obj)

    given FromJson[Success] = FromJson.obj(fromObj)
  }

  final case class Error(
      code: TokenErrorCode,
      description: Option[String],
      uri: Option[Uri]
  ) extends TokenResponse {
    def fold[A](fe: TokenResponse.Error => A, fs: TokenResponse.Success => A): A =
      fe(this)
  }
  object Error {
    private object P {
      val description = ParameterName.of("error_description")
      val uri = ParameterName.of("error_uri")
      val code = ParameterName.of("error")
    }
    def fromObj(obj: JsonValue.Obj): Either[JwtError.DecodeError, Error] =
      for
        c <- obj.requireAs[TokenErrorCode](P.code)
        d <- obj.getAs[String](P.description)
        u <- obj.getAs[Uri](P.uri)
      yield Error(c, d, u)

    given FromJson[Error] = FromJson.obj(fromObj)
  }
