package soidc.core.auth

import scala.collection.immutable.SortedSet

import cats.data.NonEmptySet

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
