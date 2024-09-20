package soidc.http4s.routes

import cats.data.Kleisli
import cats.effect.SyncIO

import org.http4s.*
import org.typelevel.vault.Key
import soidc.jwt.JWSDecoded

object TokenAttribute extends RequestAttributeSyntax:

  private val ctxKey: Key[JWSDecoded[Any, Any]] =
    Key.newKey[SyncIO, JWSDecoded[Any, Any]].unsafeRunSync()
  def key[H, C]: Key[JWSDecoded[H, C]] = ctxKey.asInstanceOf[Key[JWSDecoded[H, C]]]

  def forAutenticated[F[_], H, C]: JwtAuthenticatedRoutesMiddleware[F, H, C] =
    service =>
      Kleisli { case ContextRequest(ctx, req) =>
        val nr = req.withAttribute(key[H, C], ctx.token)
        service(ContextRequest(ctx, nr))
      }

  def forMaybeAuthenticated[F[_], H, C]: JwtMaybeAuthRoutesMiddleware[F, H, C] =
    service =>
      Kleisli { case r @ ContextRequest(ctx, req) =>
        ctx.token match
          case Some(token) =>
            val nr = req.withAttribute(key[H, C], token)
            service(ContextRequest(ctx, nr))
          case None =>
            service(r)
      }
