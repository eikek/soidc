import sbt._

object Dependencies {

  object V {
    val scala3 = "3.5.0"
    val borer = "1.14.1"
    val catsCore = "2.12.0"
    val catsEffect = "3.5.4"
    val http4s = "0.23.27"
    val munit = "1.0.0"
    val munitCatsEffect = "2.0.0"
    val scribe = "3.15.0"
    val scodecBits = "1.2.1"
    val jwtScala = "10.0.1";
  }

  val scodecBits = Seq(
    "org.scodec" %% "scodec-bits" % V.scodecBits
  )

  val borer = Seq(
    "io.bullet" %% "borer-core" % V.borer,
    "io.bullet" %% "borer-derivation" % V.borer,
    "io.bullet" %% "borer-compat-cats" % V.borer,
    "io.bullet" %% "borer-compat-scodec" % V.borer
  )

  val jwtScala = Seq(
    "com.github.jwt-scala" %% "jwt-core" % V.jwtScala
  )

  val scribe = Seq(
    "com.outr" %% "scribe" % V.scribe,
    "com.outr" %% "scribe-slf4j2" % V.scribe,
    "com.outr" %% "scribe-cats" % V.scribe
  )

  val http4sCore = Seq(
    "org.http4s" %% "http4s-core" % V.http4s
  )
  val http4sServer = Seq(
    "org.http4s" %% "http4s-server" % V.http4s
  )
  val http4sDsl = Seq(
    "org.http4s" %% "http4s-dsl" % V.http4s
  )
  val http4sEmberServer = Seq(
    "org.http4s" %% "http4s-ember-server" % V.http4s
  )
  val http4sClient = Seq(
    "org.http4s" %% "http4s-ember-client" % V.http4s
  )

  val catsCore = Seq(
    "org.typelevel" %% "cats-core" % V.catsCore
  )

  val catsEffect = Seq(
    "org.typelevel" %% "cats-effect" % V.catsEffect
  )

  val munit = Seq(
    "org.scalameta" %% "munit" % V.munit,
    "org.scalameta" %% "munit-scalacheck" % V.munit,
    "org.typelevel" %% "munit-cats-effect" % V.munitCatsEffect
  )
}
