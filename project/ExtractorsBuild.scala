import sbt._
import Keys._

object ExtractorsBuild extends Build {
  lazy val root = Project("extractors", file("."))
    .dependsOn(morph)

  lazy val morph = GitHub("stucco", "morph", "master")

  def GitHub(user: String, project: String, tag: String) =
    RootProject(
      uri("https://github.com/%s/%s.git#%s".format(user, project, tag))
    )
}
