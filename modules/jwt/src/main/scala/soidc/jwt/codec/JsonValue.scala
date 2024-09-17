package soidc.jwt.codec

import soidc.jwt.JwtError.DecodeError
import soidc.jwt.ParameterName
import soidc.jwt.codec.syntax.*

/** Simplified json ast for use with this library */
sealed trait JsonValue:
  def widen: JsonValue = this

object JsonValue:
  sealed trait JsonPrimitive extends JsonValue

  final case class Str(value: String) extends JsonPrimitive
  final case class Bool(value: Boolean) extends JsonPrimitive
  final case class Num(value: BigDecimal) extends JsonPrimitive
  final case class Arr(value: List[JsonValue]) extends JsonValue
  final case class Obj(value: Map[String, JsonValue]) extends JsonValue:
    def get(name: ParameterName): Option[JsonValue] =
      value.get(name.key)

    def getAs[A](name: ParameterName)(using
        dec: FromJson[A]
    ): Either[DecodeError, Option[A]] =
      get(name).map(_.as[A]).map(_.map(Some(_))).getOrElse(Right(None))

    def requireAs[A](name: ParameterName)(using FromJson[A]): Either[DecodeError, A] =
      getAs[A](name).flatMap(
        _.toRight(DecodeError(s"Missing json property: ${name.key}\n${value}"))
      )

    def hasParameter(name: ParameterName): Boolean =
      value.contains(name.key)

    def replace[V: ToJson](name: ParameterName, v: V): Obj =
      Obj(value.updated(name.key, v.toJsonValue))

    def replaceIfDefined[V: ToJson](name: ParameterName, v: Option[V]): Obj =
      v.map(replace(name, _)).getOrElse(this)

    def remove(name: ParameterName): Obj =
      Obj(value.removed(name.key))

  val emptyObj: Obj = Obj(Map.empty)
  val emptyArr: Arr = Arr(Nil)

  def str(value: String): JsonValue = Str(value)
  def num(value: BigDecimal): JsonValue = Num(value)
  def bool(value: Boolean): JsonValue = Bool(value)
  def arr(v: JsonValue*): JsonValue = Arr(v.toList)
  def obj[A: ToJson](v: (String, A)*): JsonValue = Obj(
    v.map(t => (t._1, t._2.toJsonValue)).toMap
  )
