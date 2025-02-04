package soidc.jwt

import soidc.jwt.JwtError.DecodeError
import soidc.jwt.codec.{FromJson, ToJson}

import scodec.bits.ByteVector

/** See https://datatracker.ietf.org/doc/html/rfc7518#section-5 */
enum ContentEncryptionAlgorithm(val bits: 128 | 192 | 256 | 384 | 512):
  case A128GCM
      extends ContentEncryptionAlgorithm(128)
      with ContentEncryptionAlgorithm.GCM128
  case A192GCM
      extends ContentEncryptionAlgorithm(192)
      with ContentEncryptionAlgorithm.GCM192
  case A256GCM
      extends ContentEncryptionAlgorithm(256)
      with ContentEncryptionAlgorithm.GCM256
  case A128CBC_HS256
      extends ContentEncryptionAlgorithm(256)
      with ContentEncryptionAlgorithm.CBC256
  case A192CBC_HS384
      extends ContentEncryptionAlgorithm(384)
      with ContentEncryptionAlgorithm.CBC384
  case A256CBC_HS512
      extends ContentEncryptionAlgorithm(512)
      with ContentEncryptionAlgorithm.CBC512

  lazy val name: String = productPrefix.replace('-', '_')

  def generateKey: ByteVector = this match
    case a: ContentEncryptionAlgorithm.GCM =>
      ByteVector.view(AesGcm.generateKey(a.gcmBits).getEncoded)
    case a: ContentEncryptionAlgorithm.CBC =>
      ByteVector.view(AesCbc.generateKey(a.cbcBits).raw.getEncoded)

object ContentEncryptionAlgorithm:
  sealed trait GCM {
    def gcmBits: 128 | 192 | 256
  }
  sealed trait GCM128 extends GCM {
    val gcmBits: 128 = 128
  }
  sealed trait GCM192 extends GCM {
    val gcmBits: 192 = 192
  }
  sealed trait GCM256 extends GCM {
    val gcmBits: 256 = 256
  }
  sealed trait CBC {
    def cbcBits: 256 | 384 | 512
  }
  sealed trait CBC256 extends CBC {
    val cbcBits: 256 = 256
  }
  sealed trait CBC384 extends CBC {
    def cbcBits: 384 = 384
  }
  sealed trait CBC512 extends CBC {
    def cbcBits: 512 = 512
  }

  def fromString(str: String): Either[String, ContentEncryptionAlgorithm] =
    ContentEncryptionAlgorithm.values
      .find(_.name.equalsIgnoreCase(str))
      .toRight(s"Invalid content encryption algorthim: $str")

  given FromJson[ContentEncryptionAlgorithm] =
    FromJson.str(s => fromString(s).left.map(DecodeError(_)))
  given ToJson[ContentEncryptionAlgorithm] = ToJson[String].contramap(_.name)
