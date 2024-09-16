package soidc.core.auth

import cats.Order

//https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
//https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims
//https://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess

enum Scope(val name: String):
  case OpenId extends Scope("openid")
  case Profile extends Scope("profile")
  case Email extends Scope("email")
  case Address extends Scope("address")
  case Phone extends Scope("phone")
  case OfflineAccess extends Scope("offline_access")
  case Custom(override val name: String) extends Scope(name)

object Scope:

  given Ordering[Scope] = Ordering.by(_.name)
  given Order[Scope] = Order.by(_.name)
