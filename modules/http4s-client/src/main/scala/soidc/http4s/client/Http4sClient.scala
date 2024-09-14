package soidc.http4s.client

import cats.data.EitherT
import cats.effect.*
import cats.syntax.all.*
import fs2.io.net.Network

import org.http4s.*
import org.http4s.client.Client
import org.http4s.ember.client.EmberClientBuilder
import scodec.bits.ByteVector
import soidc.core.HttpClient
import soidc.jwt.Uri
import soidc.jwt.json.JsonDecoder

final class Http4sClient[F[_]: Sync](client: Client[F]) extends HttpClient[F]:

  def get[A](url: Uri)(using JsonDecoder[A]): F[A] =
    client.expect(url.value)

  given [A](using JsonDecoder[A]): EntityDecoder[F, A] =
    val decoder = summon[JsonDecoder[A]]
    EntityDecoder.decodeBy(MediaType.application.json) { entity =>
      EitherT(entity.body.compile.to(ByteVector).map(bv => decoder.decode(bv)))
        .leftMap(err => MalformedMessageBodyFailure("Cannot decode response", Some(err)))
    }

object Http4sClient:

  def default[F[_]: Async: Network]: Resource[F, HttpClient[F]] =
    EmberClientBuilder.default[F].build.map(Http4sClient(_))
