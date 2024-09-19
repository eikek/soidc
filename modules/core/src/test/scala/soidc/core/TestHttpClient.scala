package soidc.core

import cats.MonadThrow

import soidc.core.auth.TokenRequest
import soidc.core.auth.TokenResponse
import soidc.jwt.*
import soidc.jwt.codec.*

object TestHttpClient:

  def fromMap[F[_]: MonadThrow](
      data: Map[Uri, JsonValue]
  )(using e: ByteEncoder[JsonValue]): HttpClient[F] =
    new HttpClient[F] {
      def get[A](url: Uri)(using ByteDecoder[A]): F[A] =
        data.get(url) match
          case None => MonadThrow[F].raiseError(new Exception(s"not found: $url"))
          case Some(value) =>
            val dec = summon[ByteDecoder[A]]
            dec.decode(e.encode(value)) match
              case Right(v)  => MonadThrow[F].pure(v)
              case Left(err) => MonadThrow[F].raiseError(err)

      def post(url: Uri, body: TokenRequest)(using
          ByteDecoder[TokenResponse]
      ): F[TokenResponse] =
        MonadThrow[F].raiseError(new Exception("not implemented"))
    }
