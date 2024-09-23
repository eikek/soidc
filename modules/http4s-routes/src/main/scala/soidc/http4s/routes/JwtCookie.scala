package soidc.http4s.routes

import org.http4s.ResponseCookie
import org.http4s.SameSite
import org.http4s.Uri
import soidc.jwt.JWS

object JwtCookie:

  def create(name: String, jwt: JWS, uri: Uri): ResponseCookie =
    val path = Option(uri.path.renderString)
      .filter(_.nonEmpty)
      .fold("/")(identity)
    ResponseCookie(
      name = name,
      content = jwt.compact,
      sameSite = Some(SameSite.Strict),
      path = Some(path),
      secure = uri.scheme.exists(_.value.endsWith("s")),
      httpOnly = uri.scheme.exists(_.value.startsWith("http"))
    )

  def remove(name: String, uri: Uri): ResponseCookie =
    val path = Option(uri.path.renderString)
      .filter(_.nonEmpty)
      .fold("/")(identity)
    ResponseCookie(
      name = name,
      content = "",
      sameSite = Some(SameSite.Strict),
      path = Some(path),
      secure = uri.scheme.exists(_.value.endsWith("s")),
      httpOnly = uri.scheme.exists(_.value.startsWith("http"))
    ).clearCookie
