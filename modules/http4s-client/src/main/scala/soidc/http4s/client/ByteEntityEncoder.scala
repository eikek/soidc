package soidc.http4s.client

import fs2.Chunk

import soidc.jwt.codec.ByteEncoder

import org.http4s.*
import org.http4s.headers.`Content-Type`

trait ByteEntityEncoder:

  def encodeAs[F[_], A: ByteEncoder](ct: MediaType): EntityEncoder[F, A] =
    val encoder = summon[ByteEncoder[A]]
    EntityEncoder.simple(`Content-Type`(ct)) { a =>
      Chunk.byteVector(encoder.encode(a))
    }

  given [F[_], A](using ByteEncoder[A]): EntityEncoder[F, A] =
    encodeAs[F, A](MediaType.application.json)

object ByteEntityEncoder extends ByteEntityEncoder
