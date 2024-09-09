package soidc.core.json

import scodec.bits.ByteVector
import soidc.core.OidcError.DecodeError

trait JsonDecoder[A]:
  def decode(json: ByteVector): Either[DecodeError, A]

object JsonDecoder:
  def instance[A](f: ByteVector => Either[DecodeError, A]): JsonDecoder[A] =
    (json: ByteVector) => f(json)

  given [A](using f: FromJson[A], d: JsonDecoder[JsonValue]): JsonDecoder[A] =
    instance(bv => d.decode(bv).flatMap(jv => f.from(jv)))

  trait Syntax {
    extension (self: ByteVector)
      def as[A](using d: JsonDecoder[A]): Either[DecodeError, A] =
        d.decode(self)

      def unsafeAs[A](using JsonDecoder[A]): A =
        self.as[A].fold(throw _, identity)
  }
  object syntax extends Syntax
