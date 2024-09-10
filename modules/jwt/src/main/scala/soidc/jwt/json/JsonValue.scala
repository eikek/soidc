package soidc.jwt.json

import soidc.jwt.ParameterName
import soidc.jwt.json.ToJson.syntax.*

/** Simplified json ast for use with this library */
sealed trait JsonValue:
  def widen: JsonValue = this

object JsonValue:
  final case class Str(value: String) extends JsonValue
  final case class Bool(value: Boolean) extends JsonValue
  final case class Num(value: BigDecimal) extends JsonValue
  final case class Arr(value: List[JsonValue]) extends JsonValue
  final case class Obj(value: Map[String, JsonValue]) extends JsonValue:
    def get(name: ParameterName): Option[JsonValue] =
      value.get(name.key)

    def replace[V: ToJson](name: ParameterName, v: V): Obj =
      Obj(value.updated(name.key, v.toJsonValue))

    def remove(name: ParameterName): Obj =
      Obj(value.removed(name.key))

  val emptyObj: Obj = Obj(Map.empty)
  val emptyArr: Arr = Arr(Nil)

  def str(value: String): JsonValue = Str(value)
  def num(value: BigDecimal): JsonValue = Num(value)
  def bool(value: Boolean): JsonValue = Bool(value)
  def arr(v: JsonValue*): JsonValue = Arr(v.toList)
  def obj(v: (String, JsonValue)*): JsonValue = Obj(v.toMap)
