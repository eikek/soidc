package soidc.http4s.routes

import soidc.jwt.JWS
import soidc.jwt.JWSDecoded
import soidc.jwt.StandardClaimsRead

import org.http4s.HttpDate
import org.http4s.ResponseCookie
import org.http4s.SameSite
import org.http4s.Uri

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

  def createDecoded[H, C](name: String, jwt: JWSDecoded[H, C], uri: Uri)(using
      StandardClaimsRead[C]
  ): ResponseCookie =
    create(name, jwt.jws, uri).copy(
      expires = StandardClaimsRead[C]
        .expirationTime(jwt.claims)
        .flatMap(d => HttpDate.fromEpochSecond(d.toSeconds).toOption)
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
