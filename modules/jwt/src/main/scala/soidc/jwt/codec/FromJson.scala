package soidc.jwt.codec

import soidc.jwt.JwtError.DecodeError

trait FromJson[A]:
  self =>
  def from(v: JsonValue): Either[DecodeError, A]

  def map[B](f: A => B): FromJson[B] =
    FromJson.instance(v => self.from(v).map(f))

  def mapEither[B](f: A => Either[DecodeError, B]): FromJson[B] =
    FromJson.instance(v => self.from(v).flatMap(f))

  def orElse(next: FromJson[A]): FromJson[A] =
    FromJson.instance(v => self.from(v).orElse(next.from(v)))

  def widen[B >: A]: FromJson[B] = self.asInstanceOf[FromJson[B]]

object FromJson:
  def apply[A](using f: FromJson[A]): FromJson[A] = f

  def instance[A](f: JsonValue => Either[DecodeError, A]): FromJson[A] =
    (v: JsonValue) => f(v)

  def str[A](f: String => Either[DecodeError, A]): FromJson[A] =
    instance {
      case JsonValue.Str(v) => f(v)
      case v                => Left(DecodeError(s"Not a string: $v"))
    }

  def strm[A](f: String => Either[String, A]): FromJson[A] =
    str[A](s => f(s).left.map(DecodeError(_)))

  def num[A](f: BigDecimal => Either[DecodeError, A]): FromJson[A] =
    instance {
      case JsonValue.Num(v) => f(v)
      case v                => Left(DecodeError(s"Not a number: $v"))
    }

  def obj[A](f: JsonValue.Obj => Either[DecodeError, A]): FromJson[A] =
    instance {
      case v: JsonValue.Obj => f(v)
      case v                => Left(DecodeError(s"Not an object: $v"))
    }

  def bool[A](f: Boolean => Either[DecodeError, A]): FromJson[A] =
    instance {
      case JsonValue.Bool(v) => f(v)
      case v                 => Left(DecodeError(s"Not a boolean: $v"))
    }

  given FromJson[JsonValue] = instance(Right(_))
  given FromJson[String] = str(Right(_))
  given FromJson[BigDecimal] = num(Right(_))
  given FromJson[Boolean] = bool(Right(_))

  given FromJson[Long] = FromJson[BigDecimal].map(_.toLong)
  given FromJson[Int] = FromJson[BigDecimal].map(_.toInt)
  given FromJson[Double] = FromJson[BigDecimal].map(_.toDouble)
  given FromJson[Float] = FromJson[BigDecimal].map(_.toFloat)

  given [A](using f: FromJson[A]): FromJson[List[A]] =
    instance {
      case JsonValue.Arr(vs) =>
        val init: Either[DecodeError, List[A]] = Right(Nil)
        vs.foldRight(init) { (v, res) =>
          res.flatMap(r => f.from(v).map(e => e :: r))
        }
      case v => f.from(v).map(List(_))
    }

  given [A](using f: FromJson[A]): FromJson[Option[A]] =
    instance {
      case JsonValue.JsonNull      => Right(None)
      case JsonValue.Arr(Nil)      => Right(None)
      case JsonValue.Arr(h :: Nil) => f.from(h).map(Some(_))
      case v => f.from(v).map(Some(_))
    }

  trait Syntax {
    extension (self: JsonValue)
      def as[A](using d: FromJson[A]): Either[DecodeError, A] = d.from(self)
      def unsafeAs[A](using FromJson[A]): A = self.as[A].fold(throw _, identity)
  }
  object syntax extends Syntax
