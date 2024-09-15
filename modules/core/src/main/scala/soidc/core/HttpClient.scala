package soidc.core

import cats.MonadThrow

import soidc.jwt.Uri
import soidc.jwt.codec.*

trait HttpClient[F[_]]:
  def get[A](url: Uri)(using ByteDecoder[A]): F[A]

object HttpClient:

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
    }
