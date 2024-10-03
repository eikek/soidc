package soidc.http4s.client

trait ByteEntityCodec extends ByteEntityDecoder with ByteEntityEncoder

object ByteEntityCodec extends ByteEntityCodec
