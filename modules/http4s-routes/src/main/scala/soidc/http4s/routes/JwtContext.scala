package soidc.http4s.routes

import soidc.jwt.JWSDecoded

sealed trait JwtContext[H, C]:
  def toAuthenticated: Option[JwtContext.Authenticated[H,C]]
  def isAuthenticated: Boolean = toAuthenticated.isDefined
  def getToken: Option[JWSDecoded[H, C]] = toAuthenticated.map(_.token)
  def widen: JwtContext[H, C] = this


object JwtContext:
  def notAuthenticated[H, C]: JwtContext[H, C] =
    NotAuthenticated.asInstanceOf[JwtContext[H, C]]
  def apply[H, C](token: JWSDecoded[H, C]): Authenticated[H, C] = Authenticated(token)

  final case class Authenticated[H, C](token: JWSDecoded[H, C]) extends JwtContext[H, C]:
    export token.*
    val toAuthenticated = Some(this)

  case object NotAuthenticated extends JwtContext[Nothing, Nothing]:
    val toAuthenticated = None
