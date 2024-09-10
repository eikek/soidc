package soidc.jwt

import soidc.jwt.OidcError.DecodeError
import soidc.jwt.json.{FromJson, JsonValue, ToJson}
import soidc.jwt.RegisteredParameterName as P

final case class JoseHeader(
    algorithm: Option[Algorithm],
    keyId: Option[KeyId],
    contentType: Option[String],
    issuer: Option[StringOrUri],
    subject: Option[StringOrUri],
    audience: List[StringOrUri],
    values: JsonValue.Obj
):

  def get[A: FromJson](param: ParameterName): Either[DecodeError, Option[A]] =
    values.get(param).traverseConvert[A]

  def withValue[V: ToJson](param: ParameterName, value: V): JoseHeader =
    copy(values = values.replace(param, value))

  def withAlgorithm(alg: Algorithm): JoseHeader =
    copy(
      algorithm = Some(alg),
      values = values.replace(P.Alg, alg)
    )

  def withKeyId(kid: KeyId): JoseHeader =
    copy(keyId = Some(kid), values = values.replace(P.Kid, kid))

object JoseHeader:
  val empty: JoseHeader =
    JoseHeader(None, None, None, None, None, Nil, JsonValue.emptyObj)

  val jwt: JoseHeader = empty.withValue(P.Typ, "JWT")

  def fromObj(values: JsonValue.Obj): Either[DecodeError, JoseHeader] =
    for
      alg <- values.get(P.Alg).traverseConvert[Algorithm]
      kid <- values.get(P.Kid).traverseConvert[KeyId]
      cty <- values.get(P.Cty).traverseConvert[String]
      iss <- values.get(P.Iss).traverseConvert[StringOrUri]
      sub <- values.get(P.Sub).traverseConvert[StringOrUri]
      aud <- values.get(P.Aud).traverseConvert[List[StringOrUri]]
    yield JoseHeader(alg, kid, cty, iss, sub, aud.getOrElse(Nil), values)

  given FromJson[JoseHeader] = FromJson.obj(fromObj)
  given ToJson[JoseHeader] = ToJson.instance(_.values)
