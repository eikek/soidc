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
  def withIssuer(iss: StringOrUri): SimpleClaims =
    copy(issuer = Some(iss), values = values.replace(P.Iss, iss))

  def withExpirationTime(exp: NumericDate): SimpleClaims =
    copy(expirationTime = Some(exp), values = values.replace(P.Exp, exp))

  def withSubject(sub: StringOrUri): SimpleClaims =
    copy(subject = Some(sub), values = values.replace(P.Sub, sub))

  def withAudience(aud: StringOrUri): SimpleClaims =
    copy(audience = List(aud), values = values.replace(P.Aud, aud))

  def withNotBefore(nbf: NumericDate): SimpleClaims =
    copy(notBefore = Some(nbf), values = values.replace(P.Nbf, nbf))

  def withJwtId(jti: String): SimpleClaims =
    copy(jwtId = Some(jti), values = values.replace(P.Jti, jti))

  def withValue[V: ToJson](name: ParameterName, value: V): SimpleClaims =
    copy(values = values.replace(name, value))

object SimpleClaims:
  val empty: SimpleClaims =
    SimpleClaims(None, None, Nil, None, None, None, JsonValue.emptyObj)

  def fromObj(values: JsonValue.Obj): Either[DecodeError, SimpleClaims] =
    for
      iss <- values.getAs[StringOrUri](P.Iss)
      sub <- values.getAs[StringOrUri](P.Sub)
      aud <- values.getAs[List[StringOrUri]](P.Aud)
      exp <- values.getAs[NumericDate](P.Exp)
      nbf <- values.getAs[NumericDate](P.Nbf)
      jti <- values.getAs[String](P.Jti)
    yield SimpleClaims(iss, sub, aud.getOrElse(Nil), exp, nbf, jti, values)

  given FromJson[SimpleClaims] = FromJson.obj(fromObj)
  given ToJson[SimpleClaims] = ToJson.instance(_.values)

  given StandardClaims[SimpleClaims] =
    StandardClaims(_.notBefore, _.expirationTime, _.issuer, _.jwtId)
