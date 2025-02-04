package soidc.jwt

import soidc.jwt.JwtError.DecodeError
import soidc.jwt.codec.ByteDecoder
import soidc.jwt.codec.{FromJson, ToJson}

import scodec.bits.Bases.Alphabets
import scodec.bits.ByteVector

opaque type Base64String = String

object Base64String:
  private val alphabet = Alphabets.Base64UrlNoPad

  def of(b64: String, m: String*): Either[String, Base64String] =
    val v = (b64 +: m).mkString
    ByteVector.fromBase64Descriptive(v, alphabet).map(_ => b64)

  def unsafeOf(b64: String, m: String*): Base64String =
    (b64 +: m).mkString

  def encodeString(plain: String): Base64String =
    ByteVector.view(plain.getBytes()).toBase64(alphabet)

  def encode(bv: ByteVector): Base64String =
    bv.toBase64(alphabet)

  def encode(n: BigInt): Base64String =
    encode(ByteVector.view(n.toByteArray))

  given ToJson[Base64String] = ToJson.forString
  given FromJson[Base64String] =
    FromJson.str(s => Base64String.of(s).left.map(err => JwtError.DecodeError(err)))

  extension (self: Base64String)
    def value: String = self
    def decoded: ByteVector = ByteVector.fromValidBase64(self, alphabet)
    def decodedUtf8: String = decoded.decodeUtf8Lenient
    def decodeBigInt: BigInt = BigInt(1, decoded.toArray)
    def as[A](using d: ByteDecoder[A]): Either[DecodeError, A] =
      d.decode(decoded)
