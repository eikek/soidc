package soidc

import io.bullet.borer.Json
import io.bullet.borer.compat.scodec.*
import io.bullet.borer.{Decoder, Encoder}
import scodec.bits.ByteVector
import soidc.jwt.JwtError
import soidc.jwt.json.{JsonDecoder, JsonEncoder}

package object borer extends BorerJsonCodec {

  given [A](using Decoder[A]): JsonDecoder[A] =
    JsonDecoder.instance { bv =>
      Json
        .decode(bv)
        .to[A]
        .valueEither
        .left
        .map(err =>
          JwtError.DecodeError("Error decoding from json using borer", Some(err))
        )
    }

  given [A](using Encoder[A]): JsonEncoder[A] =
    JsonEncoder.instance { a =>
      Json.encode(a).to[ByteVector].result
    }
}
