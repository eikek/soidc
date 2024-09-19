package soidc.core

import soidc.core.auth.*
import soidc.jwt.Uri
import soidc.jwt.codec.*

trait HttpClient[F[_]]:
  def get[A](url: Uri)(using ByteDecoder[A]): F[A]

  def post(url: Uri, body: TokenRequest)(using
      ByteDecoder[TokenResponse]
  ): F[TokenResponse]
