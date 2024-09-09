package soidc.core.json

import scodec.bits.ByteVector

trait JsonEncoder[A]:
  def encode(value: A): ByteVector

object JsonEncoder:
  def instance[A](f: A => ByteVector): JsonEncoder[A] =
    (a: A) => f(a)

  given [A](using f: ToJson[A], e: JsonEncoder[JsonValue]): JsonEncoder[A] =
    instance(a => e.encode(f.toJson(a)))

  trait Syntax {
    extension [A: JsonEncoder](self: A)
      def toJsonUtf8 = summon[JsonEncoder[A]].encode(self).decodeUtf8Lenient
      def toJsonBytes = summon[JsonEncoder[A]].encode(self)
  }
  object syntax extends Syntax
