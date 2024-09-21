package soidc.core.model

import java.nio.charset.StandardCharsets

import cats.effect.*
import cats.syntax.all.*

import scodec.bits.ByteVector
import soidc.jwt.*

opaque type State = String

object State:
  def fromString(str: String): State = str

  def fromBytes(bv: ByteVector): State = bv.toBase64UrlNoPad

  def random[F[_]: Sync](len: Int = 16): F[State] =
    cats.effect.std.Random.scalaUtilRandom[F].flatMap { rng =>
      rng.nextBytes(len).map(ByteVector.view).map(fromBytes)
    }

  def randomSigned[F[_]: Sync](key: JWK, len: Int = 16): F[State] =
    for
      rval <- random[F](len)
      sig = JWS.signed(ByteVector.empty, rval.bytes, key)
      s <- Sync[F].pure(sig).rethrow
    yield fromString(s.compact)

  extension (self: State)
    def render: String = self
    def bytes: ByteVector = ByteVector.view(self.getBytes(StandardCharsets.UTF_8))
    def checkWith(key: JWK) =
      JWS.fromString(self) match
        case Left(_)    => false
        case Right(jws) => jws.verifySignature(key).exists(_ == true)
