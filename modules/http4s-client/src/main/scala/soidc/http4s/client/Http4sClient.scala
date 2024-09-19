package soidc.http4s.client

import cats.effect.*
import fs2.io.net.Network

import org.http4s.*
import org.http4s.Method.POST
import org.http4s.client.Client
import org.http4s.client.dsl.Http4sClientDsl
import org.http4s.ember.client.EmberClientBuilder
import org.http4s.headers.`Content-Type`
import soidc.core.HttpClient
import soidc.core.auth.*
import soidc.jwt.Uri as JwtUri
import soidc.jwt.codec.ByteDecoder

final class Http4sClient[F[_]: Sync](client: Client[F])
    extends HttpClient[F]
    with Http4sClientDsl[F]
    with ByteEntityDecoder:

  def get[A](url: JwtUri)(using ByteDecoder[A]): F[A] =
    client.expect(url.value)

  def post(url: JwtUri, body: TokenRequest)(using
      ByteDecoder[TokenResponse]
  ): F[TokenResponse] =
    val uri = Uri.unsafeFromString(url.value)
    client.expect[TokenResponse](
      POST(body.asUrlQuery, uri).withContentType(
        `Content-Type`(MediaType.application.`x-www-form-urlencoded`)
      )
    )

object Http4sClient:

  def default[F[_]: Async: Network]: Resource[F, HttpClient[F]] =
    EmberClientBuilder.default[F].build.map(Http4sClient(_))
