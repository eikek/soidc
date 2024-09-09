import Dependencies.V
import com.github.sbt.git.SbtGit.GitKeys._

addCommandAlias("ci", "Test/compile; lint; test; publishLocal")
addCommandAlias(
  "lint",
  "scalafmtSbtCheck; scalafmtCheckAll; Compile/scalafix --check; Test/scalafix --check"
)
addCommandAlias("fix", "Compile/scalafix; Test/scalafix; scalafmtSbt; scalafmtAll")

val sharedSettings = Seq(
  organization := "com.github.eikek",
  scalaVersion := V.scala3,
  scalacOptions ++=
    Seq(
      "-feature",
      "-deprecation",
      "-unchecked",
      "-encoding",
      "UTF-8",
      "-language:higherKinds",
      "-Xkind-projector:underscores",
      "-Werror",
      "-indent",
      "-print-lines",
      "-Wunused:all"
    ),
  Compile / console / scalacOptions := Seq(),
  Test / console / scalacOptions := Seq(),
  licenses := Seq(
    "Apache-2.0" -> url("https://spdx.org/licenses/Apache-2.0.html")
  ),
  homepage := Some(url("https://github.com/eikek/soidc")),
  versionScheme := Some("early-semver")
) ++ publishSettings

lazy val publishSettings = Seq(
  developers := List(
    Developer(
      id = "eikek",
      name = "Eike Kettner",
      url = url("https://github.com/eikek"),
      email = ""
    )
  ),
  Test / publishArtifact := false
)

lazy val noPublish = Seq(
  publish := {},
  publishLocal := {},
  publishArtifact := false
)

val testSettings = Seq(
  libraryDependencies ++= Dependencies.munit.map(_ % Test),
  testFrameworks += TestFrameworks.MUnit
)

val scalafixSettings = Seq(
  semanticdbEnabled := true, // enable SemanticDB
  semanticdbVersion := scalafixSemanticdb.revision // use Scalafix compatible version
)

val buildInfoSettings = Seq(
  buildInfoKeys := Seq[BuildInfoKey](
    name,
    version,
    scalaVersion,
    sbtVersion,
    gitHeadCommit,
    gitHeadCommitDate,
    gitUncommittedChanges,
    gitDescribedVersion
  ),
  buildInfoOptions ++= Seq(BuildInfoOption.ToMap, BuildInfoOption.BuildTime),
  buildInfoPackage := "keeper"
)

val core = project
  .in(file("modules/core"))
  .settings(sharedSettings)
  .settings(testSettings)
  .settings(scalafixSettings)
  .settings(
    name := "soidc-core",
    description := "Core module",
    libraryDependencies ++=
      Dependencies.jwtScala ++ Dependencies.scodecBits
  )

val borer = project
  .in(file("modules/borer"))
  .settings(sharedSettings)
  .settings(testSettings)
  .settings(scalafixSettings)
  .settings(
    name := "soidc-borer",
    description := "Provides borer json codec",
    libraryDependencies ++= Dependencies.borer
  )
  .dependsOn(core % "compile->compile,test->test")

val http4sClient = project
  .in(file("modules/http4s-client"))
  .disablePlugins(RevolverPlugin)
  .settings(sharedSettings)
  .settings(testSettings)
  .settings(scalafixSettings)
  .settings(
    name := "soidc-http4s-client",
    description := "http client based on http4s",
    libraryDependencies ++=
      Dependencies.http4sCore ++ Dependencies.http4sClient
  )
  .dependsOn(core % "compile->compile,test->test")

val http4sRoutes = project
  .in(file("modules/http4s-routes"))
  .disablePlugins(RevolverPlugin)
  .settings(sharedSettings)
  .settings(testSettings)
  .settings(scalafixSettings)
  .settings(
    name := "soidc-http4s-routes",
    description := "Http4s routes for code flow",
    libraryDependencies ++=
      Dependencies.http4sCore ++ Dependencies.http4sDsl
  )
  .dependsOn(core % "compile->compile,test->test")

val updateReadme = inputKey[Unit]("Update readme")
lazy val readme = project
  .in(file("modules/readme"))
  .enablePlugins(MdocPlugin)
  .settings(sharedSettings)
  .settings(scalafixSettings)
  .settings(noPublish)
  .settings(
    name := "soidc-readme",
    mdocIn := (LocalRootProject / baseDirectory).value / "docs" / "readme.md",
    mdocOut := (LocalRootProject / baseDirectory).value / "README.md",
    fork := true,
    updateReadme := {
      mdoc.evaluated
      ()
    }
  )
  .dependsOn(core, borer, http4sClient, http4sRoutes)

val root = project
  .in(file("."))
  .disablePlugins(RevolverPlugin)
  .settings(sharedSettings)
  .settings(noPublish)
  .settings(
    name := "soidc-root"
  )
  .aggregate(core, borer, http4sClient, http4sRoutes)
