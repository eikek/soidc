package soidc.jwt

import scala.util.control.NoStackTrace

import scodec.bits.ByteVector

trait JwtError extends Throwable

object JwtError:
  sealed trait VerifyError extends JwtError
  sealed trait SignError extends JwtError

  final case class DecodeError(message: String, cause: Option[Throwable] = None)
      extends RuntimeException(message)
      with JwtError:
    cause.foreach(initCause)

  final case class SecurityApiError(cause: Throwable)
      extends RuntimeException(cause)
      with JwtError
      with VerifyError
      with SignError

  final case class UnsupportedPublicKey(keyType: KeyType)
      extends RuntimeException(s"Unsupported key type for creating public key: $keyType")
      with JwtError
      with VerifyError
      with NoStackTrace

  final case class UnsupportedSymmetricKey(keyType: KeyType)
      extends RuntimeException(
        s"Unsupported key type for creating a symmetric key: $keyType"
      )
      with JwtError
      with NoStackTrace

  final case class UnsupportedPrivateKey(keyType: KeyType)
      extends RuntimeException(s"Unsupported key type for creating private key: $keyType")
      with JwtError
      with SignError
      with NoStackTrace

  final case class UnsupportedHmacAlgorithm(alg: Algorithm)
      extends RuntimeException(
        s"Unsupported algorithm for creating a secret HMAC key: $alg"
      )
      with JwtError
      with NoStackTrace

  final case class SignatureMissing(jws: JWS)
      extends RuntimeException("No signature in JWS")
      with NoStackTrace
      with VerifyError

  final case class AlgorithmMissing(jwk: JWK)
      extends RuntimeException("No algorithm in JWK")
      with NoStackTrace
      with VerifyError
      with SignError

  final case class UnsupportedSignatureAlgorithm(alg: Algorithm)
      extends RuntimeException(
        s"Unsupported algorithm for creating a signature: $alg"
      )
      with VerifyError
      with SignError
      with NoStackTrace

  final case class InvalidPublicKey(cause: JwtError, jwk: JWK)
      extends RuntimeException("Invalid public key")
      with VerifyError
      with NoStackTrace

  final case class InvalidPrivateKey(cause: JwtError, jwk: JWK)
      extends RuntimeException("Invalid private key")
      with SignError
      with NoStackTrace

  final case class InvalidECSignature(
      signature: ByteVector,
      message: Option[String] = None
  ) extends RuntimeException(s"Invalid ECDSA signature: ${message}}")
      with NoStackTrace
      with VerifyError
      with SignError

  final case class SignatureCreationError(cause: SignError)
      extends RuntimeException("Error re-creating signature", cause)
      with JwtError
      with VerifyError
      with NoStackTrace
