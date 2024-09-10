package soidc.jwt

import java.time.Instant

import soidc.jwt.json.{FromJson, ToJson}

opaque type NumericDate = Long

object NumericDate:
  def seconds(n: Long): NumericDate = n
  def millis(n: Long): NumericDate = n / 1000

  def instant(i: Instant): NumericDate =
    seconds(i.getEpochSecond())

  given FromJson[NumericDate] = FromJson.num(d => Right(seconds(d.toLong)))
  given ToJson[NumericDate] = ToJson.forNum.contramap(BigDecimal(_))

  extension (self: NumericDate)
    def asInstant: Instant =
      Instant.ofEpochSecond(self)
    def toSeconds: Long = self
