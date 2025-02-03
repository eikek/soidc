package soidc.jwt

import java.security.Signature

import scodec.bits.ByteVector

object Verify:
  def verifyJWS(jws: JWS, key: JWK): Either[JwtError.VerifyError, Boolean] =
    jws.signature
      .map { sig =>
        verifyWith(jws.payload.toArray, sig.decoded.toArray, key)
      }
      .getOrElse(Left(JwtError.SignatureMissing(jws)))

  def verifyWith(
      payload: Array[Byte],
      signature: Array[Byte],
      key: JWK
  ): Either[JwtError.VerifyError, Boolean] =
    key.keyType match
      case KeyType.OCT =>
        for
          sig <- Sign
            .signWith(payload, key)
            .left
            .map(JwtError.SignatureCreationError.apply)
          res = sig.equalsConstantTime(ByteVector.view(signature))
        yield res

      case KeyType.EC =>
        verifyAsymmetric(key, payload, signature, EcKey.signAlgo)

      case KeyType.RSA =>
        verifyAsymmetric(key, payload, signature, RsaKey.signAlgo)

      case KeyType.OKP =>
        Left(JwtError.UnsupportedPublicKey(key.keyType))

  private def verifyAsymmetric(
      key: JWK,
      payload: Array[Byte],
      sig: Array[Byte],
      algoName: Algorithm => Either[JwtError.VerifyError, Algorithm.Sign]
  ): Either[JwtError.VerifyError, Boolean] =
    for
      alg <- key.algorithm.toRight(JwtError.AlgorithmMissing(key))
      sigAlg <- algoName(alg)
      pk <- key.getPublicKey.left.map(JwtError.InvalidPublicKey(_, key))
      signature <- wrapSecurityApi {
        val sig = Signature.getInstance(sigAlg.id)
        sig.initVerify(pk)
        sig.update(payload)
        sig
      }
      res <-
        if (sigAlg.isEC)
          rsSignatureToDER(ByteVector.view(sig))
            .flatMap(s => wrapSecurityApi(signature.verify(s.toArray)))
        else wrapSecurityApi(signature.verify(sig))
    yield res

  private def rsSignatureToDER(
      sig: ByteVector
  ): Either[JwtError.InvalidECSignature, ByteVector] =
    EcDerCodec.rsSignatureToDER(sig)
