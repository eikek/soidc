package soidc.core

import soidc.core.OidcError.DecodeError
import soidc.core.json.ToJson.syntax.*
import soidc.core.json.{FromJson, JsonValue, ToJson}

final case class JoseHeader(
    algorithm: Option[Algorithm],
    keyId: Option[KeyId],
    contentType: Option[String],
    issuer: Option[StringOrUri],
    subject: Option[StringOrUri],
    audience: List[StringOrUri],
    values: JsonValue.Obj
):

  def get[A: FromJson](key: String): Either[DecodeError, Option[A]] =
    values.get(key).traverseConvert[A]

  def withValue(key: String, value: JsonValue): JoseHeader =
    copy(values = values.replace(key, value))

  def withAlgorithm(alg: Algorithm): JoseHeader =
    copy(
      algorithm = Some(alg),
      values = values.replace("alg", alg.toJsonValue)
    )

  def withKeyId(kid: KeyId): JoseHeader =
    copy(keyId = Some(kid), values = values.replace("kid", kid.toJsonValue))

object JoseHeader:
  val empty: JoseHeader =
    JoseHeader(None, None, None, None, None, Nil, JsonValue.Obj(Nil))

  def fromObj(values: JsonValue.Obj): Either[DecodeError, JoseHeader] =
    for
      alg <- values.get("alg").traverseConvert[Algorithm]
      kid <- values.get("kid").traverseConvert[KeyId]
      cty <- values.get("cty").traverseConvert[String]
      iss <- values.get("iss").traverseConvert[StringOrUri]
      sub <- values.get("sub").traverseConvert[StringOrUri]
      aud <- values.get("aud").traverseConvert[List[StringOrUri]]
    yield JoseHeader(alg, kid, cty, iss, sub, aud.getOrElse(Nil), values)

  given FromJson[JoseHeader] = FromJson.obj(fromObj)
  given ToJson[JoseHeader] = ToJson.instance(_.values)
