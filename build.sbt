name := "extractors"

version := "0.0.1-SNAPSHOT"

scalaVersion := "2.10.2"

scalacOptions := Seq(
  "-unchecked", "-deprecation", "-feature", "-Xfatal-warnings"
)

libraryDependencies ++= Seq(
  "org.scalatest" %% "scalatest" % "1.9.1" % "test"
)

initialCommands in console := """
  |import morph.ast._
  |import morph.ast.Implicits._
  |import morph.ast.DSL._
  |import morph.parser._
  |import morph.parser.Interface._
  |import morph.extractor.Interface._
  |import morph.utils.Utils._
  |import gov.ornl.stucco.extractors._
  """.stripMargin

