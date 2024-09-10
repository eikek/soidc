package soidc.jwt

import soidc.jwt.json.*

enum KeyOperation:
  case Sign
  case Verify
  case Encrypt
  case Decrypt
  // case WrapKey
  // case UnwrapKey
  // case DeriveKey
  // case DeriveBits
  case Other(name: String)

  def value: String = this match
    case Other(v) => v
    case _ =>
      val s = productPrefix
      s.updated(0, s.charAt(0).toLower)

object KeyOperation:
  val known = Set(Sign, Verify, Encrypt, Decrypt)

  def fromString(str: String): Either[String, KeyOperation] =
    if (str.trim.isEmpty()) Left("Empty string for key-operation")
    else Right(known.find(_.value.equalsIgnoreCase(str)).getOrElse(Other(str)))

  given FromJson[KeyOperation] = FromJson.strm(fromString)
  given ToJson[KeyOperation] = ToJson.forString.contramap(_.value)
