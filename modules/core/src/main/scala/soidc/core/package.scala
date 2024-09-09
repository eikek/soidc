package soidc

import soidc.core.json.{JsonValue, FromJson}
import soidc.core.json.FromJson.syntax.*
import soidc.core.OidcError.DecodeError

package object core {

  extension (self: Option[JsonValue])
    private def traverseConvert[A: FromJson]: Either[DecodeError, Option[A]] =
      self.map(_.as[A]).map(_.map(Some(_))).getOrElse(Right(None))

}
