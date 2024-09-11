package soidc

import scala.util.Try

import soidc.jwt.JwtError.{DecodeError, SecurityApiError}
import soidc.jwt.json.FromJson.syntax.*
import soidc.jwt.json.{FromJson, JsonValue}

package object jwt {
  private def wrapSecurityApi[A](code: => A): Either[SecurityApiError, A] =
    Try(code).toEither.left.map(SecurityApiError.apply)

  extension (self: Option[JsonValue])
    private def traverseConvert[A: FromJson]: Either[DecodeError, Option[A]] =
      self.map(_.as[A]).map(_.map(Some(_))).getOrElse(Right(None))

}
