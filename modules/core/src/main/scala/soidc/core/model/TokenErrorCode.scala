package soidc.core.model

import soidc.jwt.codec.FromJson
import soidc.jwt.codec.ToJson

enum TokenErrorCode:
  case InvalidRequest
  case InvalidClient
  case InvalidGrant
  case UnauthorizedClient
  case UnsupportedGrantType
  case InvalidScope
  // for device code flow
  case AuthorizationPending
  case SlowDown
  case AccessDenied
  case ExpiredToken

  lazy val name: String = Util.snakeCase(productPrefix)

object TokenErrorCode:
  def fromString(str: String): Either[String, TokenErrorCode] =
    TokenErrorCode.values
      .find(_.name.equalsIgnoreCase(str))
      .toRight(s"Invalid token error code: $str")

  given FromJson[TokenErrorCode] = FromJson.strm(fromString)
  given ToJson[TokenErrorCode] = ToJson.forString.contramap(_.name)
