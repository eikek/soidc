package soidc.http4s.client

import cats.effect.*
import fs2.io.net.Network

import org.http4s.*
import org.http4s.Method.{GET, POST}
import org.http4s.client.Client
import org.http4s.client.dsl.Http4sClientDsl
import org.http4s.ember.client.EmberClientBuilder
import org.http4s.headers.Accept
import org.http4s.headers.{Authorization, `Content-Type`}
import soidc.core.HttpClient
import soidc.core.model.*
import soidc.jwt.Uri as JwtUri
import soidc.jwt.codec.ByteDecoder

final class Http4sClient[F[_]: Sync](client: Client[F])
    extends HttpClient[F]
    with Http4sClientDsl[F]
    with ByteEntityDecoder:

  def get[A](url: JwtUri, bearerToken: Option[String] = None)(using
      ByteDecoder[A]
  ): F[A] =
    val req = GET(Uri.unsafeFromString(url.value)).withBearer(bearerToken)
    client.expect(req)

  def getToken(url: JwtUri, body: TokenRequest)(using
      ByteDecoder[TokenResponse]
  ): F[TokenResponse] =
    val uri = Uri.unsafeFromString(url.value)
    val creds = body.clientSecret.map { sec =>
      BasicCredentials(body.clientId.value, sec.secret)
    }
    client.fetchAs[TokenResponse](
      POST(body.asUrlQuery, uri)
        .withBasicAuth(creds)
        .putHeaders(Accept(MediaType.application.json))
        .withContentType(
          `Content-Type`(MediaType.application.`x-www-form-urlencoded`)
        )
    )

  def getDeviceCode(url: JwtUri, body: DeviceCodeRequest)(using
      ByteDecoder[DeviceCodeResponse]
  ): F[DeviceCodeResponse] =
    val uri = Uri.unsafeFromString(url.value)
    val creds = body.clientSecret.map { sec =>
      BasicCredentials(body.clientId.value, sec.secret)
    }
    client.fetchAs[DeviceCodeResponse](
      POST(body.asUrlQuery, uri)
        .withBasicAuth(creds)
        .putHeaders(Accept(MediaType.application.json))
        .withContentType(
          `Content-Type`(MediaType.application.`x-www-form-urlencoded`)
        )
    )

  extension (self: Request[F])
    def withAuthorizationHeader(header: Option[Authorization]) =
      header.map(self.putHeaders(_)).getOrElse(self)

    def withBasicAuth(cred: Option[BasicCredentials]) =
      self.withAuthorizationHeader(cred.map(Authorization(_)))

    def withBearer(token: Option[String]) =
      self.withAuthorizationHeader(
        token.map(t => Authorization(Credentials.Token(AuthScheme.Bearer, t)))
      )

object Http4sClient:

  def default[F[_]: Async: Network]: Resource[F, HttpClient[F]] =
    EmberClientBuilder.default[F].build.map(Http4sClient(_))
