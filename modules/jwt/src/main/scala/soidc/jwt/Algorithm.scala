package soidc.jwt

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

  object Sign {
    def fromString(str: String): Either[String, Algorithm.Sign] =
      Algorithm.Sign.values
        .find(_.name.equalsIgnoreCase(str))
        .toRight(s"Invalid algorithm: $str")

    given FromJson[Sign] = FromJson.strm(fromString)
    given ToJson[Sign] = ToJson.forString.contramap(_.name)
  }

  /** See https://datatracker.ietf.org/doc/html/rfc7518#section-4.1 */
  enum Encrypt extends Algorithm {
    case RSA_OAEP
    case RSA_OAEP_256
    case dir

    lazy val name: String = productPrefix.replace('_', '-')
    val keyType: KeyType = KeyType.RSA

    def mapBoth[A](fa: Algorithm.Sign => A, fb: Algorithm.Encrypt => A): A = fb(this)
  }

  object Encrypt {
    def fromString(str: String): Either[String, Algorithm.Encrypt] =
      Algorithm.Encrypt.values
        .find(_.name.equalsIgnoreCase(str))
        .toRight(s"Invalid algorithm: $str")

    given FromJson[Encrypt] = FromJson.strm(fromString)
    given ToJson[Encrypt] = ToJson.forString.contramap(_.name)
  }

  def fromString(str: String): Either[String, Algorithm] =
    Sign.fromString(str).orElse(Encrypt.fromString(str))

  given FromJson[Algorithm] = FromJson.strm(fromString)
  given ToJson[Algorithm] = ToJson.forString.contramap(_.name)
