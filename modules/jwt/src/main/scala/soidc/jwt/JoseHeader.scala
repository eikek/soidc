package soidc.jwt

import soidc.jwt.JwtError.DecodeError
import soidc.jwt.RegisteredParameterName as P
import soidc.jwt.json.{FromJson, JsonValue, ToJson}

final case class JoseHeader(
    algorithm: Option[Algorithm],
    keyId: Option[KeyId],
    contentType: Option[String],
    issuer: Option[StringOrUri],
    subject: Option[StringOrUri],
    audience: List[StringOrUri],
    values: JsonValue.Obj
):
  def withValue[V: ToJson](param: ParameterName, value: V): JoseHeader =
    copy(values = values.replace(param, value))

  def withAlgorithm(alg: Algorithm): JoseHeader =
    copy(
      algorithm = Some(alg),
      values = values.replace(P.Alg, alg)
    )

  def withIssuer(iss: StringOrUri): JoseHeader =
    copy(issuer = Some(iss), values = values.replace(P.Iss, iss))

  def withSubject(sub: StringOrUri): JoseHeader =
    copy(subject = Some(sub), values = values.replace(P.Sub, sub))

  def withKeyId(kid: KeyId): JoseHeader =
    copy(keyId = Some(kid), values = values.replace(P.Kid, kid))

object JoseHeader:
  val empty: JoseHeader =
    JoseHeader(None, None, None, None, None, Nil, JsonValue.emptyObj)

  val jwt: JoseHeader = empty.withValue(P.Typ, "JWT")

  def fromObj(values: JsonValue.Obj): Either[DecodeError, JoseHeader] =
    for
      alg <- values.getAs[Algorithm](P.Alg)
      kid <- values.getAs[KeyId](P.Kid)
      cty <- values.getAs[String](P.Cty)
      iss <- values.getAs[StringOrUri](P.Iss)
      sub <- values.getAs[StringOrUri](P.Sub)
      aud <- values.getAs[List[StringOrUri]](P.Aud)
    yield JoseHeader(alg, kid, cty, iss, sub, aud.getOrElse(Nil), values)

  given FromJson[JoseHeader] = FromJson.obj(fromObj)
  given ToJson[JoseHeader] = ToJson.instance(_.values)

  given StandardHeader[JoseHeader] =
    StandardHeader(_.keyId, _.algorithm)
