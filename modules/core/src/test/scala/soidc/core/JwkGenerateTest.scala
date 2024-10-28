package soidc.core

import cats.effect.*

import munit.CatsEffectSuite
import soidc.jwt.*

class JwkGenerateTest extends CatsEffectSuite:

  val testCases =
    Algorithm.Sign.values.toList.flatMap {
      case a if a.isHMAC =>
        List((s"$a (len=16)", JwkGenerate.symmetric[IO](16, a)))

      case a if a.isRSA =>
        List(
          (s"$a (2048)", JwkGenerate.rsa[IO](a, 2048)),
          (s"$a (3072)", JwkGenerate.rsa[IO](a, 3072)),
          (s"$a (4096)", JwkGenerate.rsa[IO](a, 4096))
        )

      case a if a.isEC =>
        Curve.values.toList.map(c => (s"$a (crv=${c.name})", JwkGenerate.ec[IO](a, c)))

      case a => fail(s"unexpected case: $a")
    }

  val jws = JWS(Base64String.encodeString("head"), Base64String.encodeString("claims"))

  testCases.foreach { case (name, genJwk) =>
    test(name) {
      genJwk.map { key =>
        val signed = jws.unsafeSignWith(key)
        assert(
          signed.verifySignature(key).fold(throw _, identity),
          "signature verification failed"
        )
      }
    }
  }
