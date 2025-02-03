package soidc.core.model

import scala.collection.immutable.SortedSet

import cats.Order
import cats.data.NonEmptySet

enum Prompt:
  case None
  case Values(values: NonEmptySet[Prompt.PromptValue])

  def render: String = this match
    case None       => "none"
    case Values(vs) => vs.toNonEmptyList.toList.map(_.render).mkString(" ")

object Prompt:

  val none: Prompt = Prompt.None

  def of(v: PromptValue, vs: PromptValue*): Prompt =
    Prompt.Values(NonEmptySet(v, SortedSet.from(vs)))

  enum PromptValue:
    case Login
    case Consent
    case SelectAccount

    lazy val render: String = Util.snakeCase(productPrefix)
  object PromptValue:
    given Ordering[PromptValue] = Ordering.by(_.render)
    given Order[PromptValue] = Order.by(_.render)
