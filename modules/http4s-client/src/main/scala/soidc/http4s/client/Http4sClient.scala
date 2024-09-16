package soidc.http4s.client

import cats.effect.*
import fs2.io.net.Network

import org.http4s.*
import org.http4s.client.Client
import org.http4s.ember.client.EmberClientBuilder
import soidc.core.HttpClient
import soidc.jwt.Uri
import soidc.jwt.codec.ByteDecoder

final class Http4sClient[F[_]: Sync](client: Client[F])
    extends HttpClient[F]
    with ByteEntityDecoder:

  def get[A](url: Uri)(using ByteDecoder[A]): F[A] =
    client.expect(url.value)

object Http4sClient:

  def default[F[_]: Async: Network]: Resource[F, HttpClient[F]] =
    EmberClientBuilder.default[F].build.map(Http4sClient(_))
