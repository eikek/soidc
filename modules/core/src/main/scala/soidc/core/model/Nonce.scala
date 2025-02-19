package soidc.core.model

import cats.effect.Sync
import cats.effect.std.SecureRandom
import cats.syntax.all.*

import scodec.bits.Bases.Alphabets
import scodec.bits.ByteVector

opaque type Nonce = ByteVector

object Nonce:
  def apply(bv: ByteVector): Nonce = bv

  def random[F[_]: Sync](len: Int = 16): F[Nonce] =
    SecureRandom.javaSecuritySecureRandom[F].flatMap { rng =>
      rng.nextBytes(len).map(ByteVector.view)
    }

  extension (self: Nonce) def render: String = self.toBase64(Alphabets.Base64UrlNoPad)
