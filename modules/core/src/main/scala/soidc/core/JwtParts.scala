package soidc.core

final case class JwtParts(
    header: Base64String,
    claims: Base64String,
    signature: Option[Base64String]
):

  def asToken: String =
    val sig = signature.map(s => s".${s}").getOrElse("")
    s"${header.value}.${claims.value}${sig}"

object JwtParts:

  def fromString(str: String): Either[String, JwtParts] =
    str.split('.') match {
      case Array(h, c, s) =>
        for
          h64 <- Base64String.of(h)
          c64 <- Base64String.of(c)
          s64 <- Base64String.of(s)
        yield JwtParts(h64, c64, Some(s64))
      case Array(h, c) =>
        for
          h64 <- Base64String.of(h)
          c64 <- Base64String.of(c)
        yield JwtParts(h64, c64, None)
      case _ =>
        Left(s"Invalid JWT: $str")
    }

  def unsafeFromString(s: String): JwtParts =
    fromString(s).fold(sys.error, identity)
