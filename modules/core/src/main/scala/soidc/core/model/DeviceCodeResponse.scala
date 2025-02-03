package soidc.core.model

import java.util.concurrent.TimeUnit

import scala.concurrent.duration.Duration
import scala.concurrent.duration.FiniteDuration

import soidc.jwt.codec.FromJson
import soidc.jwt.codec.JsonValue
import soidc.jwt.codec.ToJson
import soidc.jwt.{JwtError, ParameterName, Uri}

sealed trait DeviceCodeResponse:
  def fold[A](fe: DeviceCodeResponse.Error => A, fs: DeviceCodeResponse.Success => A): A
  def isSuccess: Boolean = fold(_ => false, _ => true)

object DeviceCodeResponse:
  given FromJson[DeviceCodeResponse] =
    FromJson[Error]
      .widen[DeviceCodeResponse]
      .orElse(FromJson[Success].widen[DeviceCodeResponse])

  final case class Success(
      deviceCode: DeviceCode,
      userCode: UserCode,
      verificationUri: Uri,
      verificationUriComplete: Option[Uri],
      expiresIn: FiniteDuration,
      interval: Option[FiniteDuration]
  ) extends DeviceCodeResponse {
    def fold[A](
        fe: DeviceCodeResponse.Error => A,
        fs: DeviceCodeResponse.Success => A
    ): A =
      fs(this)
  }

  object Success {
    private object P {
      val deviceCode = ParameterName.of("device_code")
      val userCode = ParameterName.of("user_code")
      val verificationUri = ParameterName.of("verification_uri")
      val verificationUriComplete = ParameterName.of("verification_uri_complete")
      val expires = ParameterName.of("expires_in")
      val interval = ParameterName.of("interval")
    }

    def fromObj(obj: JsonValue.Obj): Either[JwtError.DecodeError, Success] =
      for
        devc <- obj.requireAs[DeviceCode](P.deviceCode)
        usc <- obj.requireAs[UserCode](P.userCode)
        vuri <- obj.requireAs[Uri](P.verificationUri)
        vuric <- obj.getAs[Uri](P.verificationUriComplete)
        exp <- obj.requireAs[Long](P.expires).map(Duration(_, TimeUnit.SECONDS))
        interval <- obj.getAs[Long](P.interval).map(_.map(Duration(_, TimeUnit.SECONDS)))
      yield Success(devc, usc, vuri, vuric, exp, interval)

    given FromJson[Success] =
      FromJson.obj(fromObj)

    given ToJson[Success] =
      ToJson.instance(r =>
        JsonValue.emptyObj
          .replace(P.deviceCode, r.deviceCode)
          .replace(P.userCode, r.userCode)
          .replace(P.verificationUri, r.verificationUri)
          .replaceIfDefined(P.verificationUriComplete, r.verificationUriComplete)
          .replace(P.expires, r.expiresIn.toSeconds)
          .replaceIfDefined(P.interval, r.interval.map(_.toSeconds))
      )
  }

  final case class Error(
      code: TokenErrorCode,
      description: Option[String],
      uri: Option[Uri]
  ) extends DeviceCodeResponse {
    def fold[A](
        fe: DeviceCodeResponse.Error => A,
        fs: DeviceCodeResponse.Success => A
    ): A = fe(
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
