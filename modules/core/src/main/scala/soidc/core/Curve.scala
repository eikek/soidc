package soidc.core

import soidc.core.json.*


// https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.1
enum Curve(val nameShort: String, val name: String):
  case P256 extends Curve("P-256", "secp256r1")
  case P384 extends Curve("P-384", "secp384r1")
  case P521 extends Curve("P-521", "secp521r1")

object Curve:
  def fromString(s: String): Either[String, Curve] =
    Curve.values.find(_.name.equalsIgnoreCase(s)).toRight(s"Unsupported curve: $s")

  given FromJson[Curve] = FromJson.strm(fromString)
  given ToJson[Curve] = ToJson.forString.contramap(_.name)
