package soidc.http4s.routes

import scala.concurrent.duration.FiniteDuration

import cats.Monad
import cats.data.Kleisli
import cats.effect.kernel.Clock
import cats.syntax.all.*

import org.http4s.*
import soidc.jwt.JWK
import soidc.jwt.JoseHeader
import soidc.jwt.NumericDate
import soidc.jwt.SimpleClaims
import soidc.jwt.codec.ByteEncoder

/** When a token is used in a cookie, generates a new one into the response */
final class CookieUpdateMiddleware[F[_]: Monad, H, C](
    cookieName: String,
    cookieUrl: Request[F] => Uri,
    key: JWK
)(using ByteEncoder[H], ByteEncoder[C]):

  def updateClaims[A <: JwtContext[H, C]](
      claimModify: C => F[C],
      cookieModify: (C, ResponseCookie) => ResponseCookie = (_, b) => b
  ): JwtContextAuthRoutesMiddleware[F, H, C, A] =
    in =>
      Kleisli { ctxReq =>
        in.run(ctxReq).semiflatMap { resp =>
          if (resp.cookies.exists(_.name == cookieName)) resp.pure[F]
          else
            ctxReq.context.getToken match
              case None => resp.pure[F]
              case Some(token) =>
                val url = cookieUrl(ctxReq.req)
                val domain = url.authority.map(_.host.renderString)
                val path = Option.when(url.path.nonEmpty)(url.path.renderString)
                claimModify(token.claims).map(token.withClaims(key, _)).map {
                  case Right(nt) =>
                    val cookie = ResponseCookie(
                      name = cookieName,
                      content = nt.compact,
                      domain = domain,
                      sameSite = Some(SameSite.Strict),
                      path = path,
                      secure = url.scheme.exists(_.value.endsWith("s")),
                      httpOnly = url.scheme.exists(_.value.startsWith("http"))
                    )
                    resp.addCookie(cookieModify(nt.claims, cookie))
                  case Left(err) => Response(status = Status.InternalServerError)
                }
        }
      }

object CookieUpdateMiddleware:

  def default[F[_]: Monad](
      cookieName: String,
      cookieUrl: Request[F] => Uri,
      key: JWK
  )(using
      ByteEncoder[JoseHeader],
      ByteEncoder[SimpleClaims]
  ): CookieUpdateMiddleware[F, JoseHeader, SimpleClaims] =
    CookieUpdateMiddleware(cookieName, cookieUrl, key)

  extension [F[_]: Monad, H](self: CookieUpdateMiddleware[F, H, SimpleClaims])
    def refresh[A <: JwtContext[H, SimpleClaims]](
        clock: Clock[F],
        validity: FiniteDuration
    ): JwtContextAuthRoutesMiddleware[F, H, SimpleClaims, A] =
      self.updateClaims(
        c =>
          clock.realTimeInstant.map(now =>
            c.withExpirationTime(NumericDate.instant(now) + validity)
          ),
        (claims, cookie) =>
          claims.expirationTime match {
            case Some(exp) =>
              cookie.copy(
                maxAge = validity.toSeconds.some,
                expires = HttpDate.unsafeFromEpochSecond(exp.toSeconds).some
              )
            case None => cookie
          }
      )
