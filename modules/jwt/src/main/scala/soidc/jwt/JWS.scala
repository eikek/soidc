package soidc.jwt

import scodec.bits.ByteVector
import soidc.jwt.json.JsonEncoder

/** A JSON Web Signature.
  *
  * See RFC7515 (https://datatracker.ietf.org/doc/html/rfc7515)
  */
final case class JWS(
    header: Base64String,
    claims: Base64String,
    signature: Option[Base64String] = None
):

  def withSignature(sig: Base64String): JWS =
    copy(signature = Some(sig))

  def removeSignature: JWS =
    copy(signature = None)

  lazy val compact: String =
    val sig = signature.map(s => s".${s}").getOrElse("")
    s"${header.value}.${claims.value}${sig}"

  lazy val payload: ByteVector =
    ByteVector.encodeUtf8(header.value).fold(throw _, identity) ++
      ('.'.toByte +: ByteVector.encodeUtf8(claims.value).fold(throw _, identity))

  def signWith(key: JWK): Either[JwtError, JWS] =
    val sig = Sign.signWith(payload.toArray, key)
    sig.map(bv => withSignature(Base64String.encode(bv)))

  def unsafeSignWith(key: JWK): JWS =
    signWith(key).fold(throw _, identity)

  def verify(key: JWK): Either[JwtError, Boolean] =
    Verify.verifyJWS(this, key)

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

  def signed[H, C](header: H, claims: C, key: JWK)(using
      JsonEncoder[H],
      JsonEncoder[C]
  ): Either[JwtError, JWS] =
    val raw = unsigned(header, claims)
    val sig = Sign.signWith(raw.payload.toArray, key)
    sig.map(bv => raw.withSignature(Base64String.encode(bv)))

  def unsafeSigned[H, C](header: H, claims: C, key: JWK)(using
      JsonEncoder[H],
      JsonEncoder[C]
  ): JWS =
    signed(header, claims, key).fold(throw _, identity)

  def fromString(str: String): Either[String, JWS] =
    str.split('.') match {
      case Array(h, c, s) =>
        for
          h64 <- Base64String.of(h)
          c64 <- Base64String.of(c)
          s64 <- Base64String.of(s)
        yield JWS(h64, c64, Some(s64).filter(_.value.nonEmpty))
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
