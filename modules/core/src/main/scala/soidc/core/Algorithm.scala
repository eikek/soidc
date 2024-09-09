package soidc.core

import soidc.core.OidcError.DecodeError
import soidc.core.json.{FromJson, ToJson}

enum Algorithm:
  case HS256
  case HS384
  case HS512
  case RS256
  case RS384
  case RS512
  case ES256
  case ES384
  case ES512

  def name: String = productPrefix

object Algorithm:
  def fromString(str: String): Either[String, Algorithm] =
    Algorithm.values
      .find(_.name.equalsIgnoreCase(str))
      .toRight(s"Invalid algorithm: $str")

  given FromJson[Algorithm] = FromJson.str(s => fromString(s).left.map(DecodeError(_)))
  given ToJson[Algorithm] = ToJson[String].contramap(_.name)
