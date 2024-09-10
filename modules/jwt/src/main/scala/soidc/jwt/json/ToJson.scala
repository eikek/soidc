package soidc.jwt.json

trait ToJson[A]:
  self =>

  def toJson(value: A): JsonValue

  def contramap[B](f: B => A): ToJson[B] =
    ToJson.instance(b => self.toJson(f(b)))

object ToJson:
  def apply[A](using t: ToJson[A]): ToJson[A] = t

  def instance[A](f: A => JsonValue): ToJson[A] =
    (a: A) => f(a)

  val forString: ToJson[String] = instance(JsonValue.Str.apply)
  val id: ToJson[JsonValue] = instance(identity)
  val forNum: ToJson[BigDecimal] = instance(JsonValue.Num.apply)
  val forBool: ToJson[Boolean] = instance(JsonValue.Bool.apply)

  given ToJson[JsonValue] = id
  given ToJson[String] = forString
  given ToJson[BigDecimal] = forNum
  given ToJson[Boolean] = forBool
  given ToJson[Long] = forNum.contramap(BigDecimal(_))
  given ToJson[Int] = forNum.contramap(BigDecimal(_))

  given [A](using t: ToJson[A]): ToJson[List[A]] =
    ToJson.instance(list => JsonValue.Arr(list.map(t.toJson)))

  given ToJson[Map[String, JsonValue]] =
    ToJson.instance(JsonValue.Obj.apply)

  trait Syntax {
    extension [A: ToJson](self: A)
      def toJsonValue: JsonValue = summon[ToJson[A]].toJson(self)
  }
  object syntax extends Syntax
