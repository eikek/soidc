package soidc.core.auth

object AuthorizationCodeResponse:

  enum Result:
    case Success(code: AuthorizationCode)
    case Failure(errorCode: Option[AuthorizationErrorCode])

  def read(params: Map[String, String]): Result =
    params.get("error") match
      case None =>
        params
          .get("code")
          .map(AuthorizationCode.apply)
          .map(Result.Success.apply)
          .getOrElse(Result.Failure(None))
      case Some(err) =>
        Result.Failure(AuthorizationErrorCode.fromString(err).toOption)
