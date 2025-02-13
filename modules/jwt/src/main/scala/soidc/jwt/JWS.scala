package soidc.jwt

import soidc.jwt.codec.ByteDecoder
import soidc.jwt.codec.ByteEncoder
import soidc.jwt.codec.FromJson
import soidc.jwt.codec.ToJson

import scodec.bits.ByteVector

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

  def signWith(key: JWK): Either[JwtError.SignError, JWS] =
    val sig = Sign.signWith(payload.toArray, key)
    sig.map(bv => withSignature(Base64String.encode(bv)))

  def unsafeSignWith(key: JWK): JWS =
    signWith(key).fold(throw _, identity)

  def decode[H: ByteDecoder, C: ByteDecoder]
      : Either[JwtError.DecodeError, JWSDecoded[H, C]] =
    for
      h <- header.as[H]
      c <- claims.as[C]
    yield JWSDecoded(this, h, c)

  def verifySignature(key: JWK): Either[JwtError.VerifyError, Boolean] =
    Verify.verifyJWS(this, key)

object JWS:

  def unsigned[H, C](header: H, claims: C)(using
      he: ByteEncoder[H],
      ce: ByteEncoder[C]
  ): JWS =
    JWS(
      Base64String.encode(he.encode(header)),
      Base64String.encode(ce.encode(claims)),
      None
    )

  def signed[H, C](header: H, claims: C, key: JWK)(using
      ByteEncoder[H],
      ByteEncoder[C]
  ): Either[JwtError.SignError, JWS] =
    val raw = unsigned(header, claims)
    val sig = Sign.signWith(raw.payload.toArray, key)
    sig.map(bv => raw.withSignature(Base64String.encode(bv)))

  def unsafeSigned[H, C](header: H, claims: C, key: JWK)(using
      ByteEncoder[H],
      ByteEncoder[C]
  ): JWS =
    signed(header, claims, key).fold(throw _, identity)

  def fromString(str: String): Either[JwtError.DecodeError, JWS] =
    (str.split('.') match {
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
        Left(s"Invalid JWS: $str")
    }).left.map(JwtError.DecodeError(_))

  def unsafeFromString(s: String): JWS =
    fromString(s).fold(throw _, identity)

  given FromJson[JWS] =
    FromJson[String].mapEither(fromString)
  given ToJson[JWS] =
    ToJson[String].contramap(_.compact)
