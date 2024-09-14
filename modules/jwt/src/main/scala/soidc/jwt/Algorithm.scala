package soidc.jwt

import soidc.jwt.JwtError.DecodeError
import soidc.jwt.json.{FromJson, ToJson}

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

  def isEC: Boolean = fold(_ => true, _ => false, _ => false)
  def isHMAC: Boolean = fold(_ => false, _ => true, _ => false)
  def isRSA: Boolean = fold(_ => false, _ => false, _ => true)

  def keyType: KeyType =
    fold(_ => KeyType.EC, _ => KeyType.OCT, _ => KeyType.RSA)

  def fold[A](ec: Algorithm => A, hmac: Algorithm => A, rsa: Algorithm => A): A =
    this match
      case HS256 | HS384 | HS512 => hmac(this)
      case RS256 | RS384 | RS512 => rsa(this)
      case ES256 | ES384 | ES512 => ec(this)

object Algorithm:
  def fromString(str: String): Either[String, Algorithm] =
    Algorithm.values
      .find(_.name.equalsIgnoreCase(str))
      .toRight(s"Invalid algorithm: $str")

  given FromJson[Algorithm] = FromJson.str(s => fromString(s).left.map(DecodeError(_)))
  given ToJson[Algorithm] = ToJson[String].contramap(_.name)
