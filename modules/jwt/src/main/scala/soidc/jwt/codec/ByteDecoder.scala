package soidc.jwt.codec

import soidc.jwt.JwtError.DecodeError

import scodec.bits.ByteVector

trait ByteDecoder[A]:
  def decode(json: ByteVector): Either[DecodeError, A]

object ByteDecoder:
  def instance[A](f: ByteVector => Either[DecodeError, A]): ByteDecoder[A] =
    (json: ByteVector) => f(json)

  given [A](using f: FromJson[A], d: ByteDecoder[JsonValue]): ByteDecoder[A] =
    instance(bv => d.decode(bv).flatMap(jv => f.from(jv)))

  given ByteDecoder[ByteVector] = instance(Right(_))

  trait Syntax {
    extension (self: ByteVector)
      def as[A](using d: ByteDecoder[A]): Either[DecodeError, A] =
        d.decode(self)

      def unsafeAs[A](using ByteDecoder[A]): A =
        self.as[A].fold(throw _, identity)
  }
  object syntax extends Syntax
