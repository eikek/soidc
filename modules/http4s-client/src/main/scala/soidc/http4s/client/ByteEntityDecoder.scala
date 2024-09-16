package soidc.http4s.client

import cats.data.EitherT
import cats.effect.*
import cats.syntax.all.*

import org.http4s.*
import scodec.bits.ByteVector
import soidc.jwt.codec.ByteDecoder

trait ByteEntityDecoder:

  given [F[_]: Sync, A](using ByteDecoder[A]): EntityDecoder[F, A] =
    val decoder = summon[ByteDecoder[A]]
    EntityDecoder.decodeBy(MediaType.application.json) { entity =>
      EitherT(entity.body.compile.to(ByteVector).map(bv => decoder.decode(bv)))
        .leftMap(err => MalformedMessageBodyFailure("Cannot decode response", Some(err)))
    }

object ByteEntityDecoder extends ByteEntityDecoder
