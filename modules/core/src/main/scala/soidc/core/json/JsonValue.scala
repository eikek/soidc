package soidc.core.json

/** Simplified json ast for use with this library */
sealed trait JsonValue:
  def widen: JsonValue = this

object JsonValue:
  final case class Str(value: String) extends JsonValue
  final case class Bool(value: Boolean) extends JsonValue
  final case class Num(value: BigDecimal) extends JsonValue
  final case class Arr(value: List[JsonValue]) extends JsonValue
  final case class Obj(value: List[(String, JsonValue)]) extends JsonValue:
    def get(name: String): Option[JsonValue] =
      value.find(_._1 == name).map(_._2)

    def prepend(name: String, v: JsonValue): Obj =
      Obj((name -> v) :: value)

    def append(name: String, v: JsonValue): Obj =
      Obj(value :+ (name -> v))

    def remove(name: String): Obj =
      Obj(value.filter(_._1 != name))

    def replace(name: String, v: JsonValue): Obj =
      val init: (Boolean, List[(String, JsonValue)]) = (false, Nil)
      val (replaced, next) = value.foldRight(init) {
        case ((elKey, elVal), (found, result)) =>
          if (elKey == name) (true, (name -> v) :: result)
          else (found, (elKey -> elVal) :: result)
      }
      Obj(if (replaced) next else value :+ (name -> v))

  val emptyObj: Obj = Obj(Nil)
  val emptyArr: Arr = Arr(Nil)

  def str(value: String): JsonValue = Str(value)
  def num(value: BigDecimal): JsonValue = Num(value)
  def bool(value: Boolean): JsonValue = Bool(value)
  def arr(v: JsonValue*): JsonValue = Arr(v.toList)
  def obj(v: (String, JsonValue)*): JsonValue = Obj(v.toList)
