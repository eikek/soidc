package soidc.core.model

import scala.concurrent.duration.*

import soidc.jwt.*
import soidc.jwt.codec.*

sealed trait TokenResponse:
  def isSuccess: Boolean
  def isError: Boolean = !isSuccess

  def fold[A](fe: TokenResponse.Error => A, fs: TokenResponse.Success => A): A

object TokenResponse:
  given FromJson[TokenResponse] =
    FromJson[Error].widen[TokenResponse].orElse(FromJson[Success].widen[TokenResponse])

  final case class Success(
      accessToken: JWS,
      tokenType: String,
      refreshToken: Option[JWS],
      expiresIn: Option[FiniteDuration],
      idToken: Option[JWS],
      scope: Option[ScopeList],
      values: JsonValue.Obj
  ) extends TokenResponse {
    val isSuccess = true
    def fold[A](fe: TokenResponse.Error => A, fs: TokenResponse.Success => A): A = fs(
      this
    )
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
        at <- obj.requireAs[JWS](P.accessToken)
        tt <- obj.requireAs[String](P.tokenType)
        rt <- obj.getAs[JWS](P.refreshToken)
        exp <- obj.getAs[Long](P.expiresIn)
        it <- obj.getAs[JWS](P.idToken)
        sc <- obj.getAs[ScopeList](P.scope)
      yield Success(at, tt, rt, exp.map(_.seconds), it, sc, obj)

    given FromJson[Success] = FromJson.obj(fromObj)
  }

  final case class Error(
      code: TokenErrorCode,
      description: Option[String],
      uri: Option[Uri]
  ) extends TokenResponse {
    val isSuccess = false
    def fold[A](fe: TokenResponse.Error => A, fs: TokenResponse.Success => A): A = fe(
      this
    )
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
