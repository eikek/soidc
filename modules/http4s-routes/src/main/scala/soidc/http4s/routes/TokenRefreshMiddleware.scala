package soidc.http4s.routes

import java.time.temporal.ChronoUnit

import scala.concurrent.duration.*

import cats.Applicative
import cats.data.Kleisli
import cats.effect.*
import cats.syntax.all.*

import org.http4s.HttpApp
import org.http4s.Response
import org.http4s.Uri
import soidc.core.JwtRefresh
import soidc.jwt.JWSDecoded
import soidc.jwt.StandardClaims

object TokenRefreshMiddleware extends RequestAttributeSyntax:

  final case class Config[F[_], H, C](
      _refresh: JwtRefresh[F, H, C],
      expirationGap: FiniteDuration = 2.minutes,
      updateResponse: (Response[F], JWSDecoded[H, C]) => Response[F] =
        (r: Response[F], _: JWSDecoded[H, C]) => r
  ):
    export _refresh.refresh

    def appendResponseUpdate(
        f: (Response[F], JWSDecoded[H, C]) => Response[F]
    ): Config[F, H, C] =
      copy(updateResponse = (resp, token) => f(updateResponse(resp, token), token))

    def updateCookie(cookieName: String, cookieUri: Uri): Config[F, H, C] =
      appendResponseUpdate((resp, token) =>
        resp.addCookie(JwtCookie.create(cookieName, token.jws, cookieUri))
      )

    def updateHeader(name: String): Config[F, H, C] =
      appendResponseUpdate((resp, token) => resp.putHeaders(name -> token.jws.compact))

  def apply[F[_]: Sync, H, C](using
      StandardClaims[C]
  )(cfg: Config[F, H, C])(app: HttpApp[F]): HttpApp[F] =
    Kleisli { req =>
      req.attributes.lookup(TokenAttribute.key[H, C]) match
        case Some(token) =>
          expirationClose(token, cfg.expirationGap).flatMap {
            case true =>
              val nr = req.withAttribute(TokenAttribute.key[H, C], token)
              app(nr).flatMap { resp =>
                cfg.refresh(token).map { newToken =>
                  cfg.updateResponse(resp, newToken)
                }
              }
            case false => app(req)
          }
        case None => app(req)
    }

  private def expirationClose[F[_]: Clock: Applicative, H, C](
      token: JWSDecoded[H, C],
      gap: FiniteDuration
  )(using StandardClaims[C]): F[Boolean] =
    StandardClaims[C].expirationTime(token.claims) match
      case None => false.pure[F]
      case Some(exp) =>
        Clock[F].realTimeInstant.map { now =>
          val diff = exp.asInstant.until(now, ChronoUnit.SECONDS)
          diff <= gap.toSeconds
        }
