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

  enum Result:
    case Valid
    case Invalid(reason: FailureReason, more: FailureReason*)

    def fold[A](valid: => A, invalid: Invalid => A): A = this match
      case Valid      => valid
      case e: Invalid => invalid(e)

    def isValid: Boolean = fold(true, _ => false)
    def isInvalid: Boolean = !isValid
    infix def +(other: Result): Result = combine(other)

    def combine(other: Result): Result =
      fold(
        other,
        inv1 =>
          other.fold(inv1, inv2 => Invalid(inv1.reason, (inv2.all - inv1.reason).toSeq*))
      )

  object Result {
    def failed(f: FailureReason, fn: FailureReason*): Result =
      Result.Invalid(f, fn*)

    def success: Result = Result.Valid

    def cond(test: Boolean, f: => FailureReason, fn: => FailureReason*): Result =
      if (test) Result.success
      else failed(f, fn*)

    object Success {
      def unapply(r: Result): Option[Unit] =
        if (r.isValid) Some(()) else None
    }
    object Failure {
      def unapply(r: Result): Option[Set[FailureReason]] =
        r.fold(None, inv => Some(inv.all))
    }

    extension (self: Result.Invalid)
      def all: Set[FailureReason] = self.more.toSet + self.reason
  }

  def validateTime[C](
      leeway: Duration
  )(c: C, currentTime: Instant)(using claims: StandardClaimsRead[C]): Result =
    val min = claims.notBefore(c).map(_.asInstant.minusMillis(leeway.toMillis))
    val max = claims.expirationTime(c).map(_.asInstant.plusMillis(leeway.toMillis))
    val v1 = min.map { nbf =>
      Result.cond(currentTime.isAfter(nbf), FailureReason.Inactive(nbf))
    }
    val v2 = max.map { exp =>
      Result.cond(currentTime.isBefore(exp), FailureReason.Expired(exp))
    }
    v1.getOrElse(Result.success) + v2.getOrElse(Result.success)

  def validateSignature[H, C](key: JWK, jws: JWSDecoded[H, C])(using
      StandardHeaderRead[H]
  ): Result =
    val jwsAlg = StandardHeaderRead[H].algorithm(jws.header)
    if (key.algorithm != jwsAlg)
      Result.failed(FailureReason.AlgorithmMismatch(key.algorithm, jwsAlg))
    else
      jws.verifySignature(key) match
        case Right(result) => Result.cond(result, FailureReason.SignatureInvalid)
        case Left(err)     => Result.failed(FailureReason.SignatureVerifyError(err))

  def validateSignature[H, C](keySet: JWKSet, jws: JWSDecoded[H, C])(using
      StandardHeaderRead[H],
      StandardClaimsRead[C]
  ): Result =
    StandardHeaderRead[H].keyId(jws.header) match
      case None =>
        val jti = StandardClaimsRead[C].jwtId(jws.claims)
        Result.failed(FailureReason.KeyNotFoundInHeader(jti))
      case Some(key) =>
        keySet.get(key) match
          case None =>
            Result.failed(FailureReason.KeyNotInJWKSet(key))
          case Some(jwk) => validateSignature(jwk, jws)
