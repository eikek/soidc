package soidc.jwt

import java.time.Instant

import scala.concurrent.duration.Duration

object Validate:

  def validateTime[C](
      leeway: Duration
  )(c: C, currentTime: Instant)(using claims: StandardClaims[C]): Boolean =
    val min = claims.notBefore(c).map(_.asInstant.minusMillis(leeway.toMillis))
    val max = claims.expirationTime(c).map(_.asInstant.plusMillis(leeway.toMillis))
    min.forall(_.isBefore(currentTime)) && max.forall(_.isAfter(currentTime))
