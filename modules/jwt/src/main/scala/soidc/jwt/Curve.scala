package soidc.jwt

import soidc.jwt.json.*

// https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.1
enum Curve(val nameShort: String, val name: String, val oid: String):
  case P256 extends Curve("P-256", "secp256r1", "1.2.840.10045.3.1.7")
  case P384 extends Curve("P-384", "secp384r1", "1.3.132.0.34")
  case P521 extends Curve("P-521", "secp521r1", "1.3.132.0.35")

object Curve:
  def fromString(s: String): Either[String, Curve] =
    Curve.values
      .find(c =>
        c.name.equalsIgnoreCase(s) || c.nameShort.equalsIgnoreCase(s) || c.oid == s
      )
      .toRight(s"Unsupported curve: $s")

  given FromJson[Curve] = FromJson.strm(fromString)
  given ToJson[Curve] = ToJson.forString.contramap(_.name)
