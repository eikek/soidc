package soidc

import soidc.jwt.JwtError
import soidc.jwt.codec.{ByteDecoder, ByteEncoder}

import io.bullet.borer.Json
import io.bullet.borer.compat.scodec.*
import io.bullet.borer.{Decoder, Encoder}
import scodec.bits.ByteVector

package object borer extends BorerJsonCodec {

  given [A](using Decoder[A]): ByteDecoder[A] =
    ByteDecoder.instance { bv =>
      Json
        .decode(bv)
        .to[A]
        .valueEither
        .left
        .map(err =>
          JwtError.DecodeError("Error decoding from json using borer", Some(err))
        )
    }

  given [A](using Encoder[A]): ByteEncoder[A] =
    ByteEncoder.instance { a =>
      Json.encode(a).to[ByteVector].result
    }
}
