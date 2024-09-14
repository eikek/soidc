package soidc.http4s.routes

import org.http4s.*
import org.http4s.headers.Authorization

/** Obtain a token (string) from a request. */
type GetToken[F[_]] = Request[F] => Option[String]

object GetToken:
  def authorizationToken[F[_]](scheme: AuthScheme): GetToken[F] = { req =>
    req.headers.get[Authorization].map(_.credentials).flatMap {
      case Credentials.Token(s, token) if s == scheme => Some(token)
      case _                                          => None
    }
  }

  def bearer[F[_]]: GetToken[F] = authorizationToken(AuthScheme.Bearer)

  def cookie[F[_]](cookieName: String): GetToken[F] = { req =>
    req.cookies.find(_.name == cookieName).map(_.content)
  }

  def noToken[F[_]]: GetToken[F] =
    _ => None

  def constant[F[_]](token: String): GetToken[F] =
    _ => Some(token)

  extension [F[_]](self: GetToken[F])
    def orElse(next: GetToken[F]): GetToken[F] = { req =>
      self(req).orElse(next(req))
    }
