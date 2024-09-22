package soidc.core

import scala.util.matching.Regex

import cats.MonadThrow
import cats.effect.*
import cats.syntax.all.*

import soidc.jwt.*
import soidc.jwt.codec.ByteDecoder

object DefaultJwtValidator:

  final case class Config(
      openIdConfig: OpenIdJwtValidator.Config = OpenIdJwtValidator.Config(),
      allowedIssuerUrls: List[Regex] = Nil,
      disableSignatureValidation: Boolean = false
  ):
    def isIssuerAllowed(issuer: String): Boolean =
      allowedIssuerUrls.exists(p => p.matches(issuer))
    def enableSignatureValidation: Boolean = !disableSignatureValidation

  def apply[F[_], H, C](config: Config, client: HttpClient[F])(using
      StandardClaimsRead[C],
      StandardHeader[H],
      MonadThrow[F],
      ByteDecoder[OpenIdConfig],
      ByteDecoder[JWKSet],
      Ref.Make[F],
      Clock[F]
  ): F[JwtValidator[F, H, C]] =
    val clock = Clock[F]
    val v1 = JwtValidator
      .validateTimingOnly[F, H, C](clock, config.openIdConfig.timingLeeway)
      .scoped(_ => config.disableSignatureValidation)

    JwtValidator
      .openId(config.openIdConfig, client)
      .map(_.scoped(_ => config.enableSignatureValidation))
      .map { v2 =>
        v1.orElse(v2).forIssuer(config.isIssuerAllowed)
      }

  def default[F[_]](config: Config, client: HttpClient[F])(using
      MonadThrow[F],
      ByteDecoder[OpenIdConfig],
      ByteDecoder[JWKSet],
      Ref.Make[F],
      Clock[F]
  ): F[JwtValidator[F, JoseHeader, SimpleClaims]] =
    apply[F, JoseHeader, SimpleClaims](config, client)
