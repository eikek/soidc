package soidc.jwt

//import scala.util.control.NoStackTrace

trait OidcError extends Throwable

object OidcError:

  final case class DecodeError(message: String, cause: Option[Throwable] = None)
      extends RuntimeException(message)
      with OidcError:
    cause.foreach(initCause)

  final case class SecurityApiError(cause: Throwable)
      extends RuntimeException(cause)
      with OidcError

  final case class UnsupportedPublicKey(keyType: KeyType)
      extends RuntimeException(s"Unsupported key type for creating public key: $keyType")
      with OidcError:
    override def fillInStackTrace(): Throwable = this

  final case class UnsupportedSymmetricKey(keyType: KeyType)
      extends RuntimeException(
        s"Unsupported key type for creating a symmetric key: $keyType"
      )
      with OidcError:
    override def fillInStackTrace(): Throwable = this

  final case class UnsupportedPrivateKey(keyType: KeyType)
      extends RuntimeException(s"Unsupported key type for creating private key: $keyType")
      with OidcError:
    override def fillInStackTrace(): Throwable = this

  final case class UnsupportedHmacAlgorithm(alg: Algorithm)
      extends RuntimeException(
        s"Unsupported algorithm for creating a secret HMAC key: $alg"
      )
      with OidcError:
    override def fillInStackTrace(): Throwable = this

  final case class UnsupportedSignatureAlgorithm(alg: Algorithm)
      extends RuntimeException(
        s"Unsupported algorithm for creating a signature: $alg"
      )
      with OidcError:
    override def fillInStackTrace(): Throwable = this
