package soidc.core.auth

import java.security.MessageDigest

import cats.effect.Sync
import cats.syntax.all.*

import scodec.bits.Bases.Alphabets
import scodec.bits.ByteVector

opaque type Nonce = ByteVector

object Nonce:
  def apply(bv: ByteVector): Nonce = bv

  def random[F[_]: Sync](len: Int = 16): F[Nonce] =
    cats.effect.std.Random.scalaUtilRandom[F].flatMap { rng =>
      rng.nextBytes(len).map(ByteVector.view)
    }

  def randomWithHash[F[_]: Sync](
      len: Int = 16,
      messageDigest: MessageDigest = MessageDigest.getInstance("SHA-256")
  ): F[(String, Nonce)] =
    cats.effect.std.Random.scalaUtilRandom[F].flatMap { rng =>
      rng.nextBytes(len).map(ByteVector.view).map { value =>
        (
          value.toBase64(Alphabets.Base64UrlNoPad),
          value.digest(messageDigest)
        )
      }
    }

  extension (self: Nonce) def render: String = self.toBase64(Alphabets.Base64UrlNoPad)
