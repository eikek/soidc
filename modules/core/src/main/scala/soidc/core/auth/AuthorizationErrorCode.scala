package soidc.core.auth

enum AuthorizationErrorCode:
  // OAuth
  case InvalidRequest
  case UnauthorizedClient
  case AccessDenied
  case UnsupportedResponseType
  case InvalidScope
  case ServerError
  case TemporarilyUnavailable
  // OpenId
  case InteractionRequired
  case LoginRequired
  case AccountSelectionRequired
  case ConsentRequired
  case InvalidRequestUrl
  case InvalidRequestObject
  case RequestNotSupported
  case RequestUriNotSupported
  case RegistrationNotSupported

  lazy val name: String = Util.snakeCase(productPrefix)

object AuthorizationErrorCode:
  def fromString(str: String): Either[String, AuthorizationErrorCode] =
    AuthorizationErrorCode.values
      .find(_.name.equalsIgnoreCase(str))
      .toRight(s"Invalid authorization error code: $str")
