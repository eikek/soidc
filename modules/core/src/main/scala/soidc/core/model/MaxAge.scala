package soidc.core.model

import java.util.concurrent.TimeUnit

import scala.concurrent.duration.Duration
import scala.concurrent.duration.FiniteDuration

opaque type MaxAge = Long

object MaxAge:
  def seconds(n: Long): MaxAge = n
  def apply(d: Duration): MaxAge = d.toSeconds

  extension (self: MaxAge)
    def toDuration: FiniteDuration = Duration(self, TimeUnit.SECONDS)
    def toSeconds: Long = self
    def render: String = self.toString
