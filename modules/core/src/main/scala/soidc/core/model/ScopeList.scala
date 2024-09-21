package soidc.core.model

import scala.collection.immutable.SortedSet

import cats.data.NonEmptySet

import soidc.jwt.codec.FromJson
import soidc.jwt.codec.ToJson

final case class ScopeList private (private val moreScopes: SortedSet[Scope]):
  lazy val scopes: NonEmptySet[Scope] = NonEmptySet(Scope.OpenId, moreScopes)

  infix def +(s: Scope): ScopeList =
    copy(moreScopes + s)

  def render: String =
    scopes.toNonEmptyList.map(_.name).toList.mkString(" ")

object ScopeList:

  /** Create a scope list. The `openid` scope is added automatically. */
  def apply(scope: Scope*): ScopeList =
    ScopeList(SortedSet.from(scope.toSet))

  given FromJson[ScopeList] =
    FromJson[String].map(s => apply(s.split("\\s+").toList.map(Scope.fromString)*))
  given ToJson[ScopeList] =
    ToJson[String].contramap(_.render)
