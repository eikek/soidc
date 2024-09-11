package soidc.jwt

import soidc.jwt.JwtError.DecodeError
import soidc.jwt.RegisteredParameterName as P
import soidc.jwt.json.{FromJson, JsonValue, ToJson}

final case class SimpleClaims(
    issuer: Option[StringOrUri],
    subject: Option[StringOrUri],
    audience: List[StringOrUri],
    expirationTime: Option[NumericDate],
    notBefore: Option[NumericDate],
    jwtId: Option[String],
    values: JsonValue.Obj
):

  def get[A: FromJson](key: ParameterName): Either[DecodeError, Option[A]] =
    values.get(key).traverseConvert[A]

  def withIssuer(iss: StringOrUri): SimpleClaims =
    copy(issuer = Some(iss), values = values.replace(P.Iss, iss))

  def withExpirationTime(exp: NumericDate): SimpleClaims =
    copy(expirationTime = Some(exp), values = values.replace(P.Exp, exp))

  def withValue[V: ToJson](name: ParameterName, value: V): SimpleClaims =
    copy(values = values.replace(name, value))

object SimpleClaims:
  val empty: SimpleClaims =
    SimpleClaims(None, None, Nil, None, None, None, JsonValue.emptyObj)

  def fromObj(values: JsonValue.Obj): Either[DecodeError, SimpleClaims] =
    for
      iss <- values.get(P.Iss).traverseConvert[StringOrUri]
      sub <- values.get(P.Sub).traverseConvert[StringOrUri]
      aud <- values.get(P.Aud).traverseConvert[List[StringOrUri]]
      exp <- values.get(P.Exp).traverseConvert[NumericDate]
      nbf <- values.get(P.Nbf).traverseConvert[NumericDate]
      jti <- values.get(P.Jti).traverseConvert[String]
    yield SimpleClaims(iss, sub, aud.getOrElse(Nil), exp, nbf, jti, values)

  given FromJson[SimpleClaims] = FromJson.obj(fromObj)
  given ToJson[SimpleClaims] = ToJson.instance(_.values)
