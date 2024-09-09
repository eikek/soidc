package soidc.core

import soidc.core.OidcError.DecodeError
import soidc.core.json.ToJson.syntax.*
import soidc.core.json.{FromJson, JsonValue, ToJson}

final case class SimpleClaims(
    issuer: Option[StringOrUri],
    subject: Option[StringOrUri],
    audience: List[StringOrUri],
    expirationTime: Option[NumericDate],
    notBefore: Option[NumericDate],
    jwtId: Option[String],
    values: JsonValue.Obj
):

  def get[A: FromJson](key: String): Either[DecodeError, Option[A]] =
    values.get(key).traverseConvert[A]

  def withIssuer(iss: StringOrUri): SimpleClaims =
    copy(issuer = Some(iss), values = values.replace("iss", iss.toJsonValue))

  def withExpirationTime(exp: NumericDate): SimpleClaims =
    copy(expirationTime = Some(exp), values = values.replace("exp", exp.toJsonValue))

  def withValue(key: String, value: JsonValue): SimpleClaims =
    copy(values = values.replace(key, value))

object SimpleClaims:
  val empty: SimpleClaims =
    SimpleClaims(None, None, Nil, None, None, None, JsonValue.Obj(Nil))

  def fromObj(values: JsonValue.Obj): Either[DecodeError, SimpleClaims] =
    for
      iss <- values.get("iss").traverseConvert[StringOrUri]
      sub <- values.get("sub").traverseConvert[StringOrUri]
      aud <- values.get("aud").traverseConvert[List[StringOrUri]]
      exp <- values.get("exp").traverseConvert[NumericDate]
      nbf <- values.get("nbf").traverseConvert[NumericDate]
      jti <- values.get("jti").traverseConvert[String]
    yield SimpleClaims(iss, sub, aud.getOrElse(Nil), exp, nbf, jti, values)

  given FromJson[SimpleClaims] = FromJson.obj(fromObj)
  given ToJson[SimpleClaims] = ToJson.instance(_.values)
