package soidc.core.model

import soidc.jwt.codec.FromJson
import soidc.jwt.codec.JsonValue
import soidc.jwt.codec.ToJson
import soidc.jwt.{JwtError, ParameterName}

/** As found here:
  * https://docs.github.com/en/rest/users/users?apiVersion=2022-11-28#get-the-authenticated-user
  */
final case class GitHubUser(
    id: Long,
    login: Option[String],
    name: Option[String],
    email: Option[String]
)

object GitHubUser:
  private object P {
    val id = ParameterName.of("id")
    val login = ParameterName.of("login")
    val name = ParameterName.of("name")
    val email = ParameterName.of("email")
  }

  def fromObj(obj: JsonValue.Obj): Either[JwtError.DecodeError, GitHubUser] =
    for
      id <- obj.requireAs[Long](P.id)
      login <- obj.getAs[String](P.login)
      name <- obj.getAs[String](P.name)
      email <- obj.getAs[String](P.email)
    yield GitHubUser(id, login, name, email)

  given FromJson[GitHubUser] = FromJson.obj(fromObj)
  given ToJson[GitHubUser] = ToJson.instance(u =>
    JsonValue.emptyObj
      .replace(P.id, u.id)
      .replaceIfDefined(P.login, u.login)
      .replaceIfDefined(P.name, u.name)
      .replaceIfDefined(P.email, u.email)
  )
