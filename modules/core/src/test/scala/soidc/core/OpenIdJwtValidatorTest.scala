package soidc.core

import cats.effect.*

import soidc.borer.given
import soidc.jwt.*
import soidc.jwt.codec.syntax.*

import munit.CatsEffectSuite

class OpenIdJwtValidatorTest extends CatsEffectSuite:

  extension (self: String)
    def uri = Uri.unsafeFromString(self)
    def keyId = KeyId.unsafeFromString(self)

  def createJWS(claims: SimpleClaims, kid: String = "key1"): (DefaultJWS, JWK) =
    val alg = Algorithm.Sign.HS256
    val jwk = JWK.symmetric(Base64String.encodeString("hello"), alg).withKeyId(kid.keyId)
    val jws = JWSDecoded.createSigned(
      JoseHeader.jwt.withAlgorithm(alg).withKeyId(kid.keyId),
      claims,
      jwk
    )
    jws.fold(throw _, (_, jwk))

  test("fetch jwks from given url"):
    val (jws, jwk) = createJWS(SimpleClaims.empty)
    val jwksUri = "http://jwkb".uri
    val client = TestHttpClient.fromMap[IO](
      Map(jwksUri -> JWKSet(jwk).toJsonValue)
    )
    val cfg = OpenIdJwtValidator.Config().withJwksUri(jwksUri)
    JwtValidator
      .openId[IO, JoseHeader, SimpleClaims](cfg, client)
      .flatMap(_.validate(jws))
      .assert(_.exists(_.isValid))

  test("fetch jwks from given openid-config url"):
    val (jws, jwk) = createJWS(SimpleClaims.empty)
    val jwksUri = "http://jwkb".uri
    val oidUri = "http://oid".uri
    val dummyUri = "dummy:none".uri
    val client = TestHttpClient.fromMap[IO](
      Map(
        jwksUri -> JWKSet(jwk).toJsonValue,
        oidUri -> OpenIdConfig(
          dummyUri,
          dummyUri,
          dummyUri,
          dummyUri,
          jwksUri
        ).toJsonValue
      )
    )
    val cfg = OpenIdJwtValidator.Config().withOpenIdConfigUri(oidUri)
    JwtValidator
      .openId[IO, JoseHeader, SimpleClaims](cfg, client)
      .flatMap(_.validate(jws))
      .assert(_.exists(_.isValid))

  test("fetch jwks from issuer url"):
    val issuer = "http://issuer".uri
    val (jws, jwk) = createJWS(SimpleClaims.empty.withIssuer(StringOrUri(issuer.value)))
    val jwksUri = "http://jwkb".uri
    val oidUri = "http://issuer/.well-known/openid-configuration".uri
    val dummyUri = "dummy:none".uri
    val client = TestHttpClient.fromMap[IO](
      Map(
        jwksUri -> JWKSet(jwk).toJsonValue,
        oidUri -> OpenIdConfig(
          dummyUri,
          dummyUri,
          dummyUri,
          dummyUri,
          jwksUri
        ).toJsonValue
      )
    )
    val cfg = OpenIdJwtValidator.Config()
    JwtValidator
      .openId[IO, JoseHeader, SimpleClaims](cfg, client)
      .flatMap(_.validate(jws))
      .assert(_.exists(_.isValid))

  test("validate encrypted jws"):
    val issuer = "http://issuer".uri
    val (jws, jwk) = createJWS(SimpleClaims.empty.withIssuer(StringOrUri(issuer.value)))
    val jwksUri = "http://jwkb".uri
    val oidUri = "http://issuer/.well-known/openid-configuration".uri
    val dummyUri = "dummy:none".uri
    val client = TestHttpClient.fromMap[IO](
      Map(
        jwksUri -> JWKSet(jwk).toJsonValue,
        oidUri -> OpenIdConfig(
          dummyUri,
          dummyUri,
          dummyUri,
          dummyUri,
          jwksUri
        ).toJsonValue
      )
    )
    val cea = ContentEncryptionAlgorithm.A256GCM
    val cfg = OpenIdJwtValidator.Config()
    for
      encKey <- JwkGenerate.symmetricEncrypt[IO](cea)
      validator <- JwtValidator
        .openId[IO, JoseHeader, SimpleClaims](cfg, client)
        .map(_.toDecryptingValidator(encKey))
      jwe <- IO(
        JWE.encryptJWS(
          JoseHeader.jwe(cea = cea, alg = Algorithm.Encrypt.dir),
          jws.jws,
          encKey
        )
      ).rethrow

      res <- validator.decryptValidate(jwe.compact)
      _ = assert(res.toEither.isRight)
    yield ()
