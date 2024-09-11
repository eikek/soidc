package soidc.jwt

import java.security.Signature

import scodec.bits.ByteVector
import soidc.jwt.JwtError.DecodeError

object Verify:
  def verifyJWS(jws: JWS, key: JWK): Either[JwtError, Boolean] =
    jws.signature
      .map { sig =>
        verifyWith(jws.payload.toArray, sig.decoded.toArray, key)
      }
      .getOrElse(Left(JwtError.SignatureMissing(jws)))

  def verifyWith(
      payload: Array[Byte],
      signature: Array[Byte],
      key: JWK
  ): Either[JwtError, Boolean] =
    key.keyType match
      case KeyType.OCT =>
        for
          sig <- Sign.signWith(payload, key)
          res = sig.equalsConstantTime(ByteVector.view(signature))
        yield res

      case KeyType.EC =>
        verifyAsymmetric(key, payload, signature, EcKey.signAlgoName)

      case KeyType.RSA =>
        verifyAsymmetric(key, payload, signature, RsaKey.signAlgoName)

      case KeyType.OKP =>
        Left(JwtError.UnsupportedPublicKey(key.keyType))

  private def verifyAsymmetric(
      key: JWK,
      payload: Array[Byte],
      sig: Array[Byte],
      algoName: Algorithm => Either[JwtError, String]
  ) =
    for
      alg <- key.algorithm.toRight(JwtError.DecodeError("No algorithm in JWK"))
      algName <- algoName(alg)
      pk <- key.getPublicKey
      signature <- wrapSecurityApi(Signature.getInstance(algName))
      _ <- wrapSecurityApi {
        signature.initVerify(pk)
        signature.update(payload)
      }
      res <-
        if (alg.isEC)
          rsSignatureToDER(ByteVector.view(sig))
            .flatMap(s => wrapSecurityApi(signature.verify(s.toArray)))
        else wrapSecurityApi(signature.verify(sig))
    yield res

  private def rsSignatureToDER(sig: ByteVector): Either[JwtError, ByteVector] =
    def twoc(b: ByteVector) =
      val b1 = b.dropWhile(_ == 0)
      if (b1.nonEmpty && b1.head < 0) 0.toByte +: b1
      else b1

    val (r, s) = {
      val (r1, s1) = sig.splitAt(sig.size / 2)
      (twoc(r1), twoc(s1))
    }
    val len = 2 + r.size + 2 + s.size
    val header = {
      val h = ByteVector(0x30.toByte)
      if (len >= 128) h :+ 0x81.toByte else h
    }
    if (len > 255) Left(DecodeError("Invalid ECDSA signature"))
    else
      Right(
        header ++ ByteVector(len.toByte) ++ ByteVector(
          2.toByte,
          r.length.toByte
        ) ++ r ++ ByteVector(2.toByte, s.length.toByte) ++ s
      )
