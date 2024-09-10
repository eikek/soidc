package soidc.jwt

import soidc.jwt.json.JsonEncoder

final case class JWS(
    header: Base64String,
    claims: Base64String,
    signature: Option[Base64String]
):

  def withSignature(sig: Base64String): JWS =
    copy(signature = Some(sig))

  def removeSignature: JWS =
    copy(signature = None)

  def compact: String =
    val sig = signature.map(s => s".${s}").getOrElse("")
    s"${header.value}.${claims.value}${sig}"

object JWS:

  def unsigned[H, C](header: H, claims: C)(using
      he: JsonEncoder[H],
      ce: JsonEncoder[C]
  ): JWS =
    JWS(
      Base64String.encode(he.encode(header)),
      Base64String.encode(ce.encode(claims)),
      None
    )

  def fromString(str: String): Either[String, JWS] =
    str.split('.') match {
      case Array(h, c, s) =>
        for
          h64 <- Base64String.of(h)
          c64 <- Base64String.of(c)
          s64 <- Base64String.of(s)
        yield JWS(h64, c64, Some(s64))
      case Array(h, c) =>
        for
          h64 <- Base64String.of(h)
          c64 <- Base64String.of(c)
        yield JWS(h64, c64, None)
      case _ =>
        Left(s"Invalid JWT: $str")
    }

  def unsafeFromString(s: String): JWS =
    fromString(s).fold(sys.error, identity)
