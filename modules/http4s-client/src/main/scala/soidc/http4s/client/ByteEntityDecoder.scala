package soidc.http4s.client

import cats.data.EitherT
import cats.effect.*
import cats.syntax.all.*

import soidc.jwt.codec.ByteDecoder

import org.http4s.*
import scodec.bits.ByteVector

trait ByteEntityDecoder:
  def decodeFrom[F[_]: Sync, A: ByteDecoder](ct: MediaType): EntityDecoder[F, A] =
    val decoder = summon[ByteDecoder[A]]
    EntityDecoder.decodeBy(ct) { entity =>
      EitherT(entity.body.compile.to(ByteVector).map(bv => decoder.decode(bv)))
        .leftMap(err => MalformedMessageBodyFailure("Cannot decode response", Some(err)))
    }

  given [F[_]: Sync, A](using ByteDecoder[A]): EntityDecoder[F, A] =
    decodeFrom[F, A](MediaType.application.json)

object ByteEntityDecoder extends ByteEntityDecoder
