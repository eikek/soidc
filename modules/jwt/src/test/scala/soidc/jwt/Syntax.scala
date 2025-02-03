package soidc.jwt

trait Syntax:

  extension (self: String) def noWhitespace = self.replaceAll("\\s+", "")

  extension [A <: Throwable, B](eab: Either[A, B])
    def value: B = eab.fold(throw _, identity)

object Syntax extends Syntax
