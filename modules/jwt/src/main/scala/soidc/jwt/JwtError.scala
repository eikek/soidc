package soidc.jwt

import scala.util.control.NoStackTrace

trait JwtError extends Throwable

object JwtError:

  final case class DecodeError(message: String, cause: Option[Throwable] = None)
      extends RuntimeException(message)
      with JwtError:
    cause.foreach(initCause)

  final case class SecurityApiError(cause: Throwable)
      extends RuntimeException(cause)
      with JwtError

  final case class UnsupportedPublicKey(keyType: KeyType)
      extends RuntimeException(s"Unsupported key type for creating public key: $keyType")
      with JwtError
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
      with NoStackTrace

  final case class UnsupportedHmacAlgorithm(alg: Algorithm)
      extends RuntimeException(
        s"Unsupported algorithm for creating a secret HMAC key: $alg"
      )
      with JwtError
      with NoStackTrace

  final case class UnsupportedSignatureAlgorithm(alg: Algorithm)
      extends RuntimeException(
        s"Unsupported algorithm for creating a signature: $alg"
      )
      with JwtError
      with NoStackTrace

  final case class SignatureMissing(jws: JWS) extends NoStackTrace with JwtError
