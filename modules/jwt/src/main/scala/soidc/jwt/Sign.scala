package soidc.jwt

import java.security.Signature
import javax.crypto.Mac
import javax.crypto.SecretKey

import scodec.bits.ByteVector

object Sign:

  def signWith(payload: Array[Byte], key: JWK): Either[JwtError, ByteVector] =
    key.keyType match
      case KeyType.OCT =>
        for
          secret <- key.getSymmetricHmacKey
          mac <- getMac(secret)
          _ <- wrapSecurityApi(mac.update(payload))
          s = ByteVector.view(mac.doFinal())
        yield s

      case KeyType.EC =>
        signAsymmetric(key, payload, EcKey.signAlgoName)

      case KeyType.RSA =>
        signAsymmetric(key, payload, RsaKey.signAlgoName)

      case KeyType.OKP => Left(JwtError.UnsupportedPrivateKey(key.keyType))

  private def getMac(secret: SecretKey): Either[JwtError, Mac] =
    wrapSecurityApi {
      val m = Mac.getInstance(secret.getAlgorithm())
      m.init(secret)
      m
    }

  private def signAsymmetric(
      key: JWK,
      payload: Array[Byte],
      algoName: Algorithm => Either[JwtError, String]
  ) =
    for
      alg <- key.algorithm.toRight(JwtError.DecodeError("No algorithm in JWK"))
      algName <- algoName(alg)
      ppk <- key.getPrivateKey
      signature <- wrapSecurityApi(Signature.getInstance(algName))
      _ <- wrapSecurityApi {
        signature.initSign(ppk)
        signature.update(payload)
      }
      sig <-
        if (alg.isEC) ecExpectedSignatureLength(alg).flatMap { len =>
          derSignatureToRS(ByteVector.view(signature.sign), len)
        }
        else wrapSecurityApi(ByteVector.view(signature.sign))
    yield sig

  /** Converts a EC signature in DER format into the "R+S" format required by JWT */
  def derSignatureToRS(der: ByteVector, outLen: Int): Either[JwtError, ByteVector] =
    (for
      (rem0, _) <- der.consume(1)(bv =>
        Either.cond(bv.head == 0x30, (), s"Invalid DER signature: header byte: $bv")
      )
      offset = if (rem0.head > 0) 2 else 3
      (rem1, rLen) <- rem0.consume(offset + 1)(bv => Right(bv.last.toLong))
      (rem2, r) <- rem1.consume(rLen)(bv =>
        Right(bv.dropWhile(_ == 0).padLeft(outLen / 2))
      )
      (rem3, sLen) <- rem2.consume(2)(bv => Right(bv.last.toLong))
      (rem4, s) <- rem3.consume(sLen)(bv =>
        Right(bv.dropWhile(_ == 0).padLeft(outLen / 2))
      )
      _ <- Either.cond(rem4.isEmpty, (), "Invalid DER signature")
    yield r ++ s).left.map(JwtError.DecodeError(_))

  private def ecExpectedSignatureLength(alg: Algorithm) = alg match
    case Algorithm.ES256 => Right(64)
    case Algorithm.ES384 => Right(96)
    case Algorithm.ES512 => Right(132)
    case _ => Left(JwtError.DecodeError(s"Invalid algorithm for EC signatures: $alg"))
