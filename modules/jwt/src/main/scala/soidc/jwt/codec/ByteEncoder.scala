package soidc.jwt.codec

import scodec.bits.ByteVector

trait ByteEncoder[A]:
  def encode(value: A): ByteVector

object ByteEncoder:
  def instance[A](f: A => ByteVector): ByteEncoder[A] =
    (a: A) => f(a)

  given [A](using f: ToJson[A], e: ByteEncoder[JsonValue]): ByteEncoder[A] =
    instance(a => e.encode(f.toJson(a)))

  given ByteEncoder[ByteVector] = instance(identity)

  trait Syntax {
    extension [A: ByteEncoder](self: A)
      def toJsonUtf8 = summon[ByteEncoder[A]].encode(self).decodeUtf8Lenient
      def toJsonBytes = summon[ByteEncoder[A]].encode(self)
  }
  object syntax extends Syntax
