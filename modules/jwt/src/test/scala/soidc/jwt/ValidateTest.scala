package soidc.jwt

import java.time.Instant

import scala.concurrent.duration.Duration

import munit.FunSuite
import scodec.bits.*
import soidc.jwt.Validate.*

class ValidateTest extends FunSuite:

  test("validate not before"):
    val nbf = NumericDate.seconds(5000L)
    val c = SimpleClaims.empty.withNotBefore(nbf)
    assertEquals(
      validateTime(Duration.Zero)(c, Instant.ofEpochSecond(6000)),
      Result.success
    )
    assertEquals(
      validateTime(Duration.Zero)(c, Instant.ofEpochSecond(4000)),
      Result.failed(FailureReason.Inactive(nbf.asInstant))
    )
    assertEquals(
      validateTime(Duration("1500s"))(c, Instant.ofEpochSecond(4000)),
      Result.success
    )

  test("validate expiration"):
    val exp = NumericDate.seconds(5000L)
    val c = SimpleClaims.empty.withExpirationTime(exp)
    assertEquals(
      validateTime(Duration.Zero)(c, Instant.ofEpochSecond(4000)),
      Result.success
    )
    assertEquals(
      validateTime(Duration.Zero)(c, Instant.ofEpochSecond(6000)),
      Result.failed(FailureReason.Expired(exp.asInstant))
    )

  test("validate timing"):
    val nbf = NumericDate.seconds(5000)
    val exp = NumericDate.seconds(8000)
    val c = SimpleClaims.empty.withExpirationTime(exp).withNotBefore(nbf)
    assertEquals(
      validateTime(Duration.Zero)(c, Instant.ofEpochSecond(6000)),
      Result.success
    )
    assertEquals(
      validateTime(Duration.Zero)(c, Instant.ofEpochSecond(4000)),
      Result.failed(FailureReason.Inactive(nbf.asInstant))
    )
    assertEquals(
      validateTime(Duration.Zero)(c, Instant.ofEpochSecond(10500)),
      Result.failed(FailureReason.Expired(exp.asInstant))
    )

  test("validate signature"):
    val jws = Rfc7515.Appendix1.jwsDecoded
    val goodKey = Rfc7515.Appendix1.symmetricKey
    val wrongKey = Rfc7515.Appendix2.rsaKey
    val badKey = JWK.symmetric(hex"caffee", Algorithm.Sign.HS256)
    assertEquals(
      validateSignature(goodKey, jws),
      Result.success
    )
    assertEquals(
      validateSignature(wrongKey, jws),
      Result.failed(
        FailureReason.AlgorithmMismatch(wrongKey.algorithm, jws.header.algorithm)
      )
    )
    assertEquals(
      validateSignature(badKey, jws),
      Result.failed(FailureReason.SignatureInvalid)
    )

  test("validate no key in jwk"):
    val data = Rfc7515.Appendix1
    val jws = data.jwsDecoded
    val key = data.symmetricKey.copy(
      algorithm = None,
      values = data.symmetricKey.values.remove(SymmetricKey.Param.K)
    )
    assertEquals(
      validateSignature(key, jws),
      Result.failed(FailureReason.AlgorithmMismatch(None, jws.header.algorithm))
    )

  test("validate jws"):
    val data = Rfc7515.Appendix1
    val jws = data.jwsDecoded
    val jwkSet = JWKSet(data.symmetricKey)
    assertEquals(
      validateSignature(jwkSet, jws),
      Result.failed(FailureReason.KeyNotFoundInHeader(None))
    )
    val jwsWithKeyId =
      jws.copy(header = jws.header.withKeyId(data.symmetricKey.keyId.get))
    assertEquals(
      validateSignature(jwkSet, jwsWithKeyId),
      Result.success
    )
    assertEquals(
      validateSignature(JWKSet.empty, jwsWithKeyId),
      Result.failed(FailureReason.KeyNotInJWKSet(data.symmetricKey.keyId.get))
    )
