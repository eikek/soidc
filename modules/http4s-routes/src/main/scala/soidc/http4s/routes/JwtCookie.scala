package soidc.http4s.routes

import org.http4s.ResponseCookie
import org.http4s.SameSite
import org.http4s.Uri
import soidc.jwt.JWS

object JwtCookie:

  def create(name: String, jwt: JWS, uri: Uri): ResponseCookie =
//    val path = Option.when(uri.path.nonEmpty)(uri.path.renderString)
    ResponseCookie(
      name = name,
      content = jwt.compact,
      sameSite = Some(SameSite.Strict),
      path = Some("/"),
      secure = uri.scheme.exists(_.value.endsWith("s")),
      httpOnly = uri.scheme.exists(_.value.startsWith("http"))
    )
