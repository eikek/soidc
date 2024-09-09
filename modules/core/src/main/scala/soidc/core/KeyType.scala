package soidc.core

import soidc.core.json.*

enum KeyType:
  case EC
  case RSA
  case OCT

  def name: String = productPrefix.toUpperCase

object KeyType:
  def fromString(s: String): Either[String, KeyType] =
    KeyType.values.find(_.name.equalsIgnoreCase(s)).toRight(s"Invalid key type: $s")

  given FromJson[KeyType] = FromJson.strm(fromString)
  given ToJson[KeyType] = ToJson.forString.contramap(_.name)
