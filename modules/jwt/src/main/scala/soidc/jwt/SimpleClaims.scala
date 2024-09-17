package soidc.jwt

import soidc.jwt.JwtError.DecodeError
import soidc.jwt.RegisteredParameterName as P
import soidc.jwt.codec.{FromJson, JsonValue, ToJson}

final case class SimpleClaims private (
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

  def withSubject(sub: StringOrUri): SimpleClaims =
    copy(subject = Some(sub), values = values.replace(P.Sub, sub))

  def withAudience(aud: StringOrUri): SimpleClaims =
    copy(audience = List(aud), values = values.replace(P.Aud, aud))

  def withExpirationTime(exp: NumericDate): SimpleClaims =
    copy(expirationTime = Some(exp), values = values.replace(P.Exp, exp))

  def withNotBefore(nbf: NumericDate): SimpleClaims =
    copy(notBefore = Some(nbf), values = values.replace(P.Nbf, nbf))

  def withJwtId(jti: String): SimpleClaims =
    copy(jwtId = Some(jti), values = values.replace(P.Jti, jti))

  def withValue[V: ToJson](name: ParameterName, value: V): SimpleClaims =
    copy(values = values.replace(name, value))

  def remove(name: ParameterName): SimpleClaims =
    val nv = values.remove(name)
    name.key match
      case P.Iss.key => copy(issuer = None, values = nv)
      case P.Sub.key => copy(subject = None, values = nv)
      case P.Aud.key => copy(audience = Nil, values = nv)
      case P.Exp.key => copy(expirationTime = None, values = nv)
      case P.Nbf.key => copy(notBefore = None, values = nv)
      case P.Jti.key => copy(jwtId = None, values = nv)
      case _         => copy(values = nv)

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
    StandardClaims(
      _.notBefore,
      _.expirationTime,
      _.issuer,
      _.jwtId,
      _.withExpirationTime(_)
    )
