package soidc.http4s.routes

import java.time.temporal.ChronoUnit

import scala.concurrent.duration.*

import cats.Applicative
import cats.Monad
import cats.data.Kleisli
import cats.effect.*
import cats.syntax.all.*

import org.http4s.Response
import org.http4s.Uri
import soidc.core.JwtRefresh
import soidc.jwt.JWSDecoded
import soidc.jwt.StandardClaimsRead

/** Refreshes an existing token if it gets near expiry. */
object TokenRefreshMiddleware:

  final case class Config[F[_], H, C](
      _refresh: JwtRefresh[F, H, C],
      expirationGap: FiniteDuration = 5.minutes,
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
  end Config

  def forAuthenticated[F[_]: Monad: Clock, H, C](using
      StandardClaimsRead[C]
  )(cfg: Config[F, H, C])(routes: JwtAuthRoutes[F, H, C]): JwtAuthRoutes[F, H, C] =
    Kleisli { req =>
      routes(req).semiflatMap { resp =>
        handleToken(cfg, req.context.token, resp)
      }
    }

  def forMaybeAuthenticated[F[_]: Monad: Clock, H, C](using
      StandardClaimsRead[C]
  )(
      cfg: Config[F, H, C]
  )(routes: JwtMaybeAuthRoutes[F, H, C]): JwtMaybeAuthRoutes[F, H, C] =
    Kleisli { req =>
      routes(req).semiflatMap { resp =>
        req.context.token match
          case Some(token) => handleToken[F, H, C](cfg, token, resp)
          case None        => resp.pure[F]
      }
    }

  private def handleToken[F[_]: Clock: Monad, H, C](
      cfg: Config[F, H, C],
      token: JWSDecoded[H, C],
      resp: Response[F]
  )(using StandardClaimsRead[C]) =
    expirationClose(token, cfg.expirationGap).flatMap {
      case true =>
        cfg.refresh(token).map { newToken =>
          if (newToken.jws == token.jws) resp
          else cfg.updateResponse(resp, newToken)
        }
      case false => resp.pure[F]
    }

  private def expirationClose[F[_]: Clock: Applicative, H, C](
      token: JWSDecoded[H, C],
      gap: FiniteDuration
  )(using sc: StandardClaimsRead[C]): F[Boolean] =
    sc.expirationTime(token.claims) match
      case None => false.pure[F]
      case Some(exp) =>
        Clock[F].realTimeInstant.map { now =>
          val diff = now.until(exp.asInstant, ChronoUnit.SECONDS)
          diff <= gap.toSeconds
        }
