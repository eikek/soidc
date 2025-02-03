package soidc.core

import cats.MonadThrow

import soidc.core.model.*
import soidc.jwt.*
import soidc.jwt.codec.*

object TestHttpClient:

  def fromMap[F[_]: MonadThrow](
      data: Map[Uri, JsonValue]
  )(using e: ByteEncoder[JsonValue]): HttpClient[F] =
    new HttpClient[F] {
      def get[A](url: Uri, authorization: Option[String] = None)(using
          ByteDecoder[A]
      ): F[A] =
        data.get(url) match
          case None => MonadThrow[F].raiseError(new Exception(s"not found: $url"))
          case Some(value) =>
            val dec = summon[ByteDecoder[A]]
            dec.decode(e.encode(value)) match
              case Right(v)  => MonadThrow[F].pure(v)
              case Left(err) => MonadThrow[F].raiseError(err)

      def getToken(url: Uri, body: TokenRequest)(using
          ByteDecoder[TokenResponse]
      ): F[TokenResponse] =
        MonadThrow[F].raiseError(new Exception("not implemented"))

      def getDeviceCode(uri: Uri, body: DeviceCodeRequest)(using
          ByteDecoder[DeviceCodeResponse]
      ): F[DeviceCodeResponse] =
        MonadThrow[F].raiseError(new Exception("not implemented"))
    }
