package soidc.jwt

import soidc.jwt.JwtError.DecodeError
import soidc.jwt.RegisteredParameterName as P
import soidc.jwt.codec.{FromJson, JsonValue, ToJson}

final case class JoseHeader private (
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

  def withKeyId(kid: KeyId): JoseHeader =
    copy(keyId = Some(kid), values = values.replace(P.Kid, kid))

  def withContentType(cty: String): JoseHeader =
    copy(contentType = Some(cty), values = values.replace(P.Cty, cty))

  def withIssuer(iss: StringOrUri): JoseHeader =
    copy(issuer = Some(iss), values = values.replace(P.Iss, iss))

  def withSubject(sub: StringOrUri): JoseHeader =
    copy(subject = Some(sub), values = values.replace(P.Sub, sub))

  def withAudience(aud: List[StringOrUri]): JoseHeader =
    copy(audience = aud, values = values.replace(P.Aud, aud))

  def remove(name: ParameterName): JoseHeader =
    val nv = values.remove(name)
    name.key match
      case P.Alg.key => copy(algorithm = None, values = nv)
      case P.Kid.key => copy(keyId = None, values = nv)
      case P.Cty.key => copy(contentType = None, values = nv)
      case P.Iss.key => copy(issuer = None, values = nv)
      case P.Sub.key => copy(subject = None, values = nv)
      case P.Aud.key => copy(audience = Nil, values = nv)
      case _         => copy(values = nv)

object JoseHeader:
  val empty: JoseHeader =
    JoseHeader(None, None, None, None, None, Nil, JsonValue.emptyObj)

  /** Initialize the `typ` property with "JWT". */
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

  given StandardHeaderRead[JoseHeader] =
    StandardHeaderRead(_.keyId, _.algorithm)

  given StandardHeaderWrite[JoseHeader] =
    StandardHeaderWrite(_.withAlgorithm(_))
