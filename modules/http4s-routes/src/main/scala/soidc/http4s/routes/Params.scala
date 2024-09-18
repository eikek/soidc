package soidc.http4s.routes

import soidc.core.auth.State

private object Params:

  object StateParam {
    def unapply(v: Map[String, collection.Seq[String]]): Option[Option[State]] =
      v.get("state").map(_.headOption) match
        case Some(Some(str)) => Some(Some(State.fromString(str)))
        case _               => Some(None)
  }
