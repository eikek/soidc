package soidc.http4s.routes

import soidc.jwt.JWSDecoded

sealed trait JwtContext[H, C]:
  def isAuthenticated: Boolean
  def getToken: Option[JWSDecoded[H, C]]

object JwtContext:

  final case class Authenticated[H, C](token: JWSDecoded[H, C]) extends JwtContext[H, C]:
    export token.*
    val isAuthenticated = true
    val getToken: Option[JWSDecoded[H, C]] = Some(token)
    private[routes] def toMaybeAuthenticated: MaybeAuthenticated[H, C] =
      MaybeAuthenticated(Some(token))

  final case class MaybeAuthenticated[H, C](token: Option[JWSDecoded[H, C]])
      extends JwtContext[H, C]:
    val isAuthenticated = token.isDefined
    val getToken = None
    val claims = token.map(_.claims)
