package soidc.core

import scala.util.control.NoStackTrace

trait OidcError extends Throwable

object OidcError:

  final case class DecodeError(message: String, cause: Option[Throwable] = None)
      extends NoStackTrace
      with OidcError:
    cause.foreach(initCause)

  final case class SecurityApiError(cause: Throwable)
      extends RuntimeException(cause)
      with OidcError

  final case class UnsupportedPublicKey(keyType: KeyType)
      extends RuntimeException(s"Unsupported key type for creating public key: $keyType")
      with OidcError:
    override def fillInStackTrace(): Throwable = this
