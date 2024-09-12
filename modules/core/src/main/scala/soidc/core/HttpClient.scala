package soidc.core

import soidc.jwt.Uri
import soidc.jwt.json.JsonDecoder

trait HttpClient[F[_]]:
  def get[A](url: Uri)(using JsonDecoder[A]): F[A]
