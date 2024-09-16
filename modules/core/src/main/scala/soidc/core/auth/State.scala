package soidc.core.auth

import java.nio.charset.StandardCharsets

import cats.effect.*
import cats.syntax.all.*

import scodec.bits.Bases.Alphabets
import scodec.bits.ByteVector

opaque type State = ByteVector

object State:
  def fromString(str: String): State =
    ByteVector.view(str.getBytes(StandardCharsets.UTF_8))

  def fromBytes(bv: ByteVector): State = bv

  def random[F[_]: Sync](len: Int = 16): F[State] =
    cats.effect.std.Random.scalaUtilRandom[F].flatMap { rng =>
      rng.nextBytes(len).map(ByteVector.view)
    }

  extension (self: State) def render: String = self.toBase64(Alphabets.Base64UrlNoPad)
