package soidc

import soidc.jwt.json.{JsonValue, FromJson}
import soidc.jwt.json.FromJson.syntax.*
import soidc.jwt.OidcError.DecodeError

package object jwt {

  extension (self: Option[JsonValue])
    private def traverseConvert[A: FromJson]: Either[DecodeError, Option[A]] =
      self.map(_.as[A]).map(_.map(Some(_))).getOrElse(Right(None))

}
