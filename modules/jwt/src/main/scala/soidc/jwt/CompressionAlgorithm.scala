package soidc.jwt

import soidc.jwt.codec.FromJson
import soidc.jwt.codec.ToJson

enum CompressionAlgorithm:
  case Deflate

  def name: String = this match
    case Deflate => "DEF"

object CompressionAlgorithm:

  def fromString(str: String): Either[String, CompressionAlgorithm] =
    CompressionAlgorithm.values
      .find(_.name.equalsIgnoreCase(str))
      .toRight(s"Invalid compression algorithm: $str")

  given FromJson[CompressionAlgorithm] = FromJson.strm(fromString)
  given ToJson[CompressionAlgorithm] = ToJson.forString.contramap(_.name)
