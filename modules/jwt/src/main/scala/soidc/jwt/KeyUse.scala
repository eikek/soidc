package soidc.jwt

import soidc.jwt.json.*

enum KeyUse(val name: String):
  case Sign extends KeyUse("sig")
  case Encrypt extends KeyUse("enc")

object KeyUse:
  def fromString(s: String): Either[String, KeyUse] =
    KeyUse.values.find(_.name.equalsIgnoreCase(s)).toRight(s"Invalid key use: $s")

  given FromJson[KeyUse] = FromJson.strm(fromString)
  given ToJson[KeyUse] = ToJson.forString.contramap(_.name)
