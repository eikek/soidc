package soidc.core

import soidc.jwt.Uri
import soidc.jwt.codec.*

trait HttpClient[F[_]]:
  def get[A](url: Uri)(using ByteDecoder[A]): F[A]
