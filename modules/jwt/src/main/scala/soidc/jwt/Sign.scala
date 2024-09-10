package soidc.jwt

import scodec.bits.ByteVector
import javax.crypto.Mac
import javax.crypto.SecretKey
import scala.util.Try
import java.security.Signature

private object Sign:

  def signWith(payload: Array[Byte], key: JWK): Either[OidcError, ByteVector] =
    key.keyType match
      case KeyType.OCT =>
        for
          secret <- key.getSymmetricHmacKey
          mac <- getMac(secret)
          _ <- wrap(mac.update(payload))
          s = ByteVector.view(mac.doFinal())
        yield s

      case KeyType.EC =>
        signAsymmetric(key, payload, EcKey.signAlgoName)

      case KeyType.RSA =>
        signAsymmetric(key, payload, RsaKey.signAlgoName)

      case KeyType.OKP => Left(OidcError.UnsupportedPrivateKey(key.keyType))

  private def getMac(secret: SecretKey): Either[OidcError, Mac] =
    wrap {
      val m = Mac.getInstance(secret.getAlgorithm())
      m.init(secret)
      m
    }

  private def signAsymmetric(
      key: JWK,
      payload: Array[Byte],
      algoName: Algorithm => Either[OidcError, String]
  ) =
    for
      alg <- key.algorithm.toRight(OidcError.DecodeError("No algorithm in JWK"))
      algName <- algoName(alg)
      ppk <- key.getPrivateKey
      signature <- wrap(Signature.getInstance(algName))
      _ <- wrap {
        signature.initSign(ppk)
        signature.update(payload)
      }
      s = ByteVector.view(signature.sign())
    yield s

  private def wrap[A](body: => A): Either[OidcError, A] =
    Try(body).toEither.left.map(OidcError.SecurityApiError.apply)
