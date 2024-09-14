package soidc.jwt

import java.time.Instant

import scala.concurrent.duration.Duration

object Validate:

  enum FailureReason:
    case Expired(exp: Instant)
    case Inactive(nbf: Instant)
    case SignatureVerifyError(cause: JwtError.VerifyError)
    case SignatureInvalid
    case KeyNotFoundInHeader(jti: Option[String])
    case KeyNotInJWKSet(kid: KeyId)
    case AlgorithmMismatch(key: Option[Algorithm], jws: Option[Algorithm])
    case GenericReason(msg: String, cause: Option[Throwable] = None)

  opaque type Result = Set[FailureReason]
  object Result {
    def failed(f: FailureReason, fn: FailureReason*): Result =
      fn.toSet + f

    def success: Result = Set.empty

    def cond(test: Boolean, f: => FailureReason, fn: => FailureReason*): Result =
      if (test) Result.success
      else fn.toSet + f

    object Success {
      def unapply(r: Result): Option[Unit] =
        if (r.isEmpty) Some(()) else None
    }
    object Failure {
      def unapply(r: Result): Option[Set[FailureReason]] =
        if (r.isEmpty) None else Some(r)
    }

    extension (self: Result)
      def isInvalid = self.nonEmpty
      def isValid = self.isEmpty
      def combine(other: Result): Result =
        self ++ other

      private def exp = self
      export exp.toList

      infix def +(other: Result): Result = combine(other)
  }

  def validateTime[C](
      leeway: Duration
  )(c: C, currentTime: Instant)(using claims: StandardClaims[C]): Result =
    val min = claims.notBefore(c).map(_.asInstant.minusMillis(leeway.toMillis))
    val max = claims.expirationTime(c).map(_.asInstant.plusMillis(leeway.toMillis))
    val v1 = min.map { nbf =>
      Result.cond(currentTime.isAfter(nbf), FailureReason.Inactive(nbf))
    }
    val v2 = max.map { exp =>
      Result.cond(currentTime.isBefore(exp), FailureReason.Expired(exp))
    }
    v1.getOrElse(Result.success) ++ v2.getOrElse(Result.success)

  def validateSignature[H, C](key: JWK, jws: JWSDecoded[H, C])(using
      StandardHeader[H]
  ): Result =
    val jwsAlg = StandardHeader[H].algorithm(jws.header)
    if (key.algorithm != jwsAlg)
      Result.failed(FailureReason.AlgorithmMismatch(key.algorithm, jwsAlg))
    else
      jws.verifySignature(key) match
        case Right(result) => Result.cond(result, FailureReason.SignatureInvalid)
        case Left(err)     => Result.failed(FailureReason.SignatureVerifyError(err))

  def validateSignature[H, C](keySet: JWKSet, jws: JWSDecoded[H, C])(using
      StandardHeader[H],
      StandardClaims[C]
  ): Result =
    StandardHeader[H].keyId(jws.header) match
      case None =>
        val jti = StandardClaims[C].jwtId(jws.claims)
        Result.failed(FailureReason.KeyNotFoundInHeader(jti))
      case Some(key) =>
        keySet.get(key) match
          case None =>
            Result.failed(FailureReason.KeyNotInJWKSet(key))
          case Some(jwk) => validateSignature(jwk, jws)
