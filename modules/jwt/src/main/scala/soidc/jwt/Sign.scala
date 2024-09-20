package soidc.jwt

import java.security.Signature
import javax.crypto.Mac
import javax.crypto.SecretKey

import scodec.bits.ByteVector

object Sign:

  def signWith(payload: Array[Byte], key: JWK): Either[JwtError.SignError, ByteVector] =
    key.keyType match
      case KeyType.OCT =>
        for
          secret <- key.getSymmetricHmacKey.left.map(JwtError.InvalidPrivateKey(_, key))
          mac <- getMac(secret)
          _ <- wrapSecurityApi(mac.update(payload))
          s = ByteVector.view(mac.doFinal())
        yield s

      case KeyType.EC =>
        signAsymmetric(key, payload, EcKey.signAlgoName)

      case KeyType.RSA =>
        signAsymmetric(key, payload, RsaKey.signAlgoName)

      case KeyType.OKP => Left(JwtError.UnsupportedPrivateKey(key.keyType))

  private def getMac(secret: SecretKey): Either[JwtError.SecurityApiError, Mac] =
    wrapSecurityApi {
      val m = Mac.getInstance(secret.getAlgorithm())
      m.init(secret)
      m
    }

  private def signAsymmetric(
      key: JWK,
      payload: Array[Byte],
      algoName: Algorithm => Either[JwtError.UnsupportedSignatureAlgorithm, String]
  ): Either[JwtError.SignError, ByteVector] =
    for
      alg <- key.algorithm.toRight(JwtError.AlgorithmMissing(key))
      algName <- algoName(alg)
      ppk <- key.getPrivateKey.left.map(JwtError.InvalidPrivateKey(_, key))
      signature <- wrapSecurityApi(Signature.getInstance(algName))
      _ <- wrapSecurityApi {
        signature.initSign(ppk)
        signature.update(payload)
      }
      sig <-
        if (alg.isEC)
          key.values
            .requireAs[Curve](EcKey.ECParam.Crv)
            .left
            .map(err => JwtError.InvalidPrivateKey(err, key))
            .map(ecExpectedSignatureLength)
            .flatMap { len =>
              derSignatureToRS(ByteVector.view(signature.sign), len)
            }
        else wrapSecurityApi(ByteVector.view(signature.sign))
    yield sig

  /** Converts a EC signature in DER format into the "R+S" format required by JWT */
  private def derSignatureToRS(
      der: ByteVector,
      outLen: Int
  ): Either[JwtError.InvalidECSignature, ByteVector] =
    EcDerCodec.derSignatureToRS(der, outLen)

  private def ecExpectedSignatureLength(crv: Curve) = crv match
    case Curve.P256 => 64
    case Curve.P384 => 96
    case Curve.P521 => 132
