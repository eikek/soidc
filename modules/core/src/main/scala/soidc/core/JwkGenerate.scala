package soidc.core

import java.security.KeyPairGenerator
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateCrtKey
import java.security.spec.ECGenParameterSpec

import cats.effect.*
import cats.effect.std.SecureRandom
import cats.syntax.all.*

import scodec.bits.ByteVector
import soidc.jwt.Algorithm
import soidc.jwt.Curve
import soidc.jwt.JWK

/** Functions for creating random keys. */
object JwkGenerate:

  def symmetric[F[_]: Sync](
      len: Int = 16,
      algorithm: Algorithm = Algorithm.HS256
  ): F[JWK] =
    for
      _ <- Sync[F].whenA(!algorithm.isHMAC)(
        Sync[F].raiseError(
          new Exception(s"Invalid algorthim for symmetric key: $algorithm")
        )
      )
      rng <- SecureRandom.javaSecuritySecureRandom[F]
      barr <- rng.nextBytes(len)
      key = JWK.symmetric(ByteVector.view(barr), algorithm)
    yield key

  def rsa[F[_]: Sync](
      algorithm: Algorithm = Algorithm.RS256,
      bits: 2048 | 3072 | 4096 = 2048
  ): F[JWK] =
    for
      _ <- Sync[F].whenA(!algorithm.isRSA)(
        Sync[F].raiseError(new Exception(s"Invalid algorthim for rsa key: $algorithm"))
      )
      gen <- Sync[F].delay(KeyPairGenerator.getInstance("RSA"))
      _ <- Sync[F].delay(gen.initialize(bits, new java.security.SecureRandom))
      kpair <- Sync[F].delay(gen.generateKeyPair())
      key = JWK.rsaPrivate(kpair.getPrivate().asInstanceOf[RSAPrivateCrtKey], algorithm)
    yield key

  def ec[F[_]: Sync](
      algorithm: Algorithm = Algorithm.ES256,
      curve: Curve = Curve.P256
  ): F[JWK] =
    (for
      _ <- Sync[F].whenA(!algorithm.isEC)(
        Sync[F].raiseError(new Exception(s"Invalid algorthim for ec key: $algorithm"))
      )
      gen <- Sync[F].delay {
        val spec = ECGenParameterSpec(curve.name)
        val kg = KeyPairGenerator.getInstance("EC")
        kg.initialize(spec, new java.security.SecureRandom)
        kg
      }
      kpair <- Sync[F].delay(gen.generateKeyPair())
      key = JWK.ecKeyPair(
        kpair.getPrivate().asInstanceOf[ECPrivateKey],
        kpair.getPublic().asInstanceOf[ECPublicKey],
        algorithm
      )
    yield key).rethrow
