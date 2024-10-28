package soidc.jwt

final case class JWE(
    header: Base64String,
    encryptedKey: Base64String,
    initv: Base64String,
    cipherText: Base64String,
    authTag: Base64String
)

object JWE:

  def fromString(str: String): Either[String, JWE] =
    str.split('.') match {
      case Array(h, ek, iv, ct, tag) =>
        for
          h64 <- Base64String.of(h)
          ek64 <- Base64String.of(ek)
          iv64 <- Base64String.of(iv)
          txt64 <- Base64String.of(ct)
          atag64 <- Base64String.of(tag)
        yield JWE(h64, ek64, iv64, txt64, atag64)
      case _ =>
        Left(s"Invalid JWE: $str")
    }
