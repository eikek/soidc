package soidc.http4s.routes

import org.http4s.ResponseCookie
import org.http4s.SameSite
import org.http4s.Uri
import soidc.jwt.JWS

object JwtCookie:

  def create(name: String, jwt: JWS, uri: Uri): ResponseCookie =
    val domain = uri.authority.map(_.host.renderString)
    val path = Option.when(uri.path.nonEmpty)(uri.path.renderString)
    ResponseCookie(
      name = name,
      content = jwt.compact,
      domain = domain,
      sameSite = Some(SameSite.Strict),
      path = path,
      secure = uri.scheme.exists(_.value.endsWith("s")),
      httpOnly = uri.scheme.exists(_.value.startsWith("http"))
    )
