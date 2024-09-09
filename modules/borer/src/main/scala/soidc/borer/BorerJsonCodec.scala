package soidc.borer

import scala.collection.immutable.ListMap

import io.bullet.borer.*
import soidc.core.*
import soidc.core.json.*

trait BorerJsonCodec:

  given Encoder[Uri] = Encoder.forString.contramap(_.value)
  given Decoder[Uri] = Decoder.forString.mapEither(Uri.fromString)

  given Encoder[KeyId] = Encoder.forString.contramap(_.value)
  given Decoder[KeyId] = Decoder.forString.mapEither(KeyId.fromString)

  given Encoder[Algorithm] = Encoder.forString.contramap(_.name)
  given Decoder[Algorithm] = Decoder.forString.mapEither(Algorithm.fromString)

  given Encoder[StringOrUri] = Encoder.forString.contramap(_.value)
  given Decoder[StringOrUri] = Decoder.forString.map(StringOrUri.apply)

  given Encoder[Base64String] = Encoder.forString.contramap(_.value)
  given Decoder[Base64String] = Decoder.forString.mapEither(Base64String.of)

  given Encoder[NumericDate] = Encoder.forLong.contramap(_.toSeconds)
  given Decoder[NumericDate] = Decoder.forLong.map(NumericDate.seconds)

  given Encoder[JsonValue] =
    new Encoder[JsonValue] {
      def write(w: Writer, value: JsonValue): Writer = value match
        case JsonValue.Str(v)  => w.writeString(v)
        case JsonValue.Num(v)  => w.write(v)
        case JsonValue.Bool(v) => w.writeBoolean(v)
        case JsonValue.Arr(vs) =>
          w.writeArrayOpen(vs.size)
          vs.foreach(v => w.write(v))
          w.writeArrayClose()
        case JsonValue.Obj(vs) =>
          w.writeMapOpen(vs.size)
          vs.foreach { case (k, v) =>
            w.write(k)
            w.write(v)
          }
          w.writeMapClose()
    }

  given Decoder[JsonValue] =
    new Decoder[JsonValue] {
      private val numberItem =
        DataItem.Long | DataItem.Int | DataItem.Double | DataItem.Float | DataItem.Float16 | DataItem.OverLong | DataItem.NumberString

      def read(r: Reader): JsonValue =
        if (r.hasBoolean) JsonValue.Bool(r.readBoolean())
        else if (r.hasString) JsonValue.Str(r.readString())
        else if (r.hasAnyOf(numberItem)) JsonValue.Num(r.read[BigDecimal]())
        else if (r.hasArrayHeader) JsonValue.Arr(r.read[List[JsonValue]]())
        else if (r.hasMapStart || r.hasMapHeader)
          JsonValue.obj(r.read[ListMap[String, JsonValue]]().toList*)
        else r.unexpectedDataItem("JsonValue")
    }

object BorerJsonCodec extends BorerJsonCodec
