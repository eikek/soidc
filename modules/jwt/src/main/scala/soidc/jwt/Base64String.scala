package soidc.jwt

import scodec.bits.Bases.Alphabets
import scodec.bits.ByteVector
import soidc.jwt.OidcError.DecodeError
import soidc.jwt.json.JsonDecoder
import soidc.jwt.json.{FromJson, ToJson}

opaque type Base64String = String

object Base64String:
  private val alphabet = Alphabets.Base64UrlNoPad

  def of(b64: String): Either[String, Base64String] =
    ByteVector.fromBase64Descriptive(b64, alphabet).map(_ => b64)

  def unsafeOf(b64: String): Base64String = b64

  def encodeString(plain: String): Base64String =
    ByteVector.view(plain.getBytes()).toBase64(alphabet)

  def encode(bv: ByteVector): Base64String =
    bv.toBase64(alphabet)

  given ToJson[Base64String] = ToJson.forString
  given FromJson[Base64String] =
    FromJson.str(s => Base64String.of(s).left.map(err => OidcError.DecodeError(err)))

  extension (self: Base64String)
    def value: String = self
    def decoded: ByteVector = ByteVector.fromValidBase64(self, alphabet)
    def decodedUtf8: String = decoded.decodeUtf8Lenient
    def decodeBigInt: BigInt = BigInt(1, decoded.toArray)
    def as[A](using d: JsonDecoder[A]): Either[DecodeError, A] =
      d.decode(decoded)
