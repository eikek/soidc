package soidc.http4s.routes

import org.http4s.Request
import org.typelevel.vault.Key

private trait RequestAttributeSyntax:

  extension [F[_]](self: Request[F])
    def withAttribute[A](key: Key[A], value: A): Request[F] =
      Request(
        self.method,
        self.uri,
        self.httpVersion,
        self.headers,
        self.body,
        self.attributes.insert(key, value)
      )
