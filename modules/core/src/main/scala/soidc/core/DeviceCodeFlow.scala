package soidc.core

import java.util.concurrent.TimeUnit

import scala.concurrent.duration.Duration
import scala.concurrent.duration.FiniteDuration

import cats.data.Kleisli
import cats.effect.*
import cats.syntax.all.*

import soidc.core.DeviceCodeFlow.DeviceFlowResult
import soidc.core.model.*
import soidc.jwt.Uri
import soidc.jwt.codec.ByteDecoder

/** This is the "oauth 2.0 device code grant flow".
  * https://datatracker.ietf.org/doc/html/rfc8628
  */
trait DeviceCodeFlow[F[_]]:

  def getDeviceCode(req: DeviceCodeRequest): F[DeviceCodeResponse]

  def getAccessToken(req: TokenRequest.Device): F[TokenResponse]

  def pollAccessToken(
      req: TokenRequest.Device,
      interval: Option[FiniteDuration],
      onPending: Kleisli[F, TokenResponse.Error, Unit]
  ): F[TokenResponse]

  def run(
      req: DeviceCodeRequest,
      onPending: Kleisli[F, TokenResponse.Error, Unit]
  ): F[DeviceFlowResult[F]]

object DeviceCodeFlow:
  type DeviceFlowResult[F[_]] =
    Either[DeviceCodeResponse.Error, (DeviceCodeResponse.Success, F[TokenResponse])]

  final case class Config(
      deviceAuthorizationEndpoint: Uri,
      tokenEndpoint: Uri
  )
  object Config {
    def from(oidCfg: OpenIdConfig): Option[Config] =
      oidCfg.deviceAuthorizationEndpoint.map(u => Config(u, oidCfg.tokenEndpoint))
  }

  def apply[F[_]: Async](cfg: Config, client: HttpClient[F])(using
      ByteDecoder[DeviceCodeResponse],
      ByteDecoder[TokenResponse]
  ): DeviceCodeFlow[F] =
    new Impl[F](cfg, client)

  private class Impl[F[_]: Async](cfg: Config, client: HttpClient[F])(using
      ByteDecoder[DeviceCodeResponse],
      ByteDecoder[TokenResponse]
  ) extends DeviceCodeFlow[F] {
    private val defaultInterval = Duration(5, TimeUnit.SECONDS)
    def getDeviceCode(req: DeviceCodeRequest): F[DeviceCodeResponse] =
      client.getDeviceCode(cfg.deviceAuthorizationEndpoint, req)

    def getAccessToken(req: TokenRequest.Device): F[TokenResponse] =
      client.getToken(cfg.tokenEndpoint, req)

    def pollAccessToken(
        req: TokenRequest.Device,
        interval: Option[FiniteDuration],
        onPending: Kleisli[F, TokenResponse.Error, Unit]
    ): F[TokenResponse] =
      getAccessToken(req).flatMap {
        case s: TokenResponse.Success => s.pure[F]

        case e @ TokenResponse.Error(TokenErrorCode.AuthorizationPending, _, _) =>
          onPending.run(e) >> Async[F].sleep(
            interval.getOrElse(defaultInterval)
          ) >> pollAccessToken(req, interval, onPending)

        case e @ TokenResponse.Error(TokenErrorCode.SlowDown, _, _) =>
          val newInterval = interval.getOrElse(defaultInterval) + defaultInterval
          onPending(e) >> Async[F].sleep(newInterval) >> pollAccessToken(
            req,
            newInterval.some,
            onPending
          )

        case e: TokenResponse.Error => e.pure[F]
      }

    def run(
        req: DeviceCodeRequest,
        onPending: Kleisli[F, TokenResponse.Error, Unit]
    ): F[DeviceFlowResult[F]] =
      getDeviceCode(req).map {
        case s: DeviceCodeResponse.Success =>
          val poll = pollAccessToken(
            TokenRequest.Device(s.deviceCode, req.clientId, req.clientSecret),
            s.interval,
            onPending
          )
          Right((s, poll))

        case e: DeviceCodeResponse.Error =>
          Left(e)
      }
  }
