package soidc.jwt

import java.net.URI
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

import scala.util.Try

import soidc.jwt.JwtError.DecodeError
import soidc.jwt.codec.{FromJson, ToJson}

opaque type Uri = String

object Uri:
  def fromString(s: String): Either[String, Uri] =
    if (s.trim.isEmpty()) Left("Empty uri")
    else Try(URI.create(s)).toEither.left.map(_.getMessage()).map(_ => s)

  def unsafeFromString(s: String): Uri =
    fromString(s).fold(sys.error, identity)

  given FromJson[Uri] = FromJson.str(s => fromString(s).left.map(DecodeError(_)))
  given ToJson[Uri] = ToJson.forString

  private def urlEncode(s: String) = URLEncoder.encode(s, StandardCharsets.UTF_8)

  extension (self: Uri)
    def value: String = self

    def addPath(path: String): Uri =
      val p = if (path.startsWith("/")) path.drop(1) else path
      val u = if (self.endsWith("/")) self.dropRight(1) else self
      s"${u}/${p}"

    def appendQuery(query: Map[String, String]): Uri =
      if (query.isEmpty) self
      else {
        val qstr = query.toList
          .map { case (k, v) => s"${urlEncode(k)}=${urlEncode(v)}" }
          .mkString("&")
        s"${self}?${qstr}"
      }
