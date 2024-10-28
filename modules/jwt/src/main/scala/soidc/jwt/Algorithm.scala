package soidc.jwt

import soidc.jwt.JwtError.DecodeError
import soidc.jwt.codec.{FromJson, ToJson}

sealed trait Algorithm:
  def name: String
  def keyType: KeyType

  def mapBoth[A](fa: Algorithm.Sign => A, fb: Algorithm.Encrypt => A): A

object Algorithm:

  enum Sign(val id: String) extends Algorithm {
    case HS256 extends Sign("HmacSHA256")
    case HS384 extends Sign("HmacSHA384")
    case HS512 extends Sign("HmacSHA512")
    case RS256 extends Sign("SHA256withRSA")
    case RS384 extends Sign("SHA384withRSA")
    case RS512 extends Sign("SHA512withRSA")
    case ES256 extends Sign("SHA256withECDSA")
    case ES384 extends Sign("SHA384withECDSA")
    case ES512 extends Sign("SHA512withECDSA")

    def name: String = productPrefix

    def isEC: Boolean = fold(_ => true, _ => false, _ => false)
    def isHMAC: Boolean = fold(_ => false, _ => true, _ => false)
    def isRSA: Boolean = fold(_ => false, _ => false, _ => true)

    def keyType: KeyType =
      fold(_ => KeyType.EC, _ => KeyType.OCT, _ => KeyType.RSA)

    def mapBoth[A](fa: Algorithm.Sign => A, fb: Algorithm.Encrypt => A): A = fa(this)

    def fold[A](ec: Sign => A, hmac: Sign => A, rsa: Sign => A): A =
      this match
        case HS256 | HS384 | HS512 => hmac(this)
        case RS256 | RS384 | RS512 => rsa(this)
        case ES256 | ES384 | ES512 => ec(this)
  }

  enum Encrypt extends Algorithm {
    case RSA_OAEP

    def name: String = productPrefix.replace('_', '-')
    def keyType: KeyType = KeyType.RSA

    def mapBoth[A](fa: Algorithm.Sign => A, fb: Algorithm.Encrypt => A): A = fb(this)
  }

  def fromString(str: String): Either[String, Algorithm] =
    Algorithm.Sign.values
      .find(_.name.equalsIgnoreCase(str))
      .toRight(s"Invalid algorithm: $str")

  given FromJson[Algorithm] = FromJson.str(s => fromString(s).left.map(DecodeError(_)))
  given ToJson[Algorithm] = ToJson[String].contramap(_.name)
