package soidc.core.model

import soidc.jwt.codec.{FromJson, ToJson}

opaque type DeviceCode = String

object DeviceCode:
  def apply(s: String): DeviceCode = s

  given FromJson[DeviceCode] = FromJson.str(Right(_))
  given ToJson[DeviceCode] = ToJson.forString

  extension (self: DeviceCode) def value: String = self
