name := "extractors"

version := "0.0.1-SNAPSHOT"

scalaVersion := "2.10.2"

scalacOptions := Seq(
  "-unchecked", "-deprecation", "-feature", "-Xfatal-warnings"
)

libraryDependencies ++= Seq(
  "org.scalatest" %% "scalatest" % "1.9.1" % "test"
)
