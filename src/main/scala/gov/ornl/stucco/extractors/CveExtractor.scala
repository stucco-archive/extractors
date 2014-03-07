package gov.ornl.stucco.extractors

import gov.ornl.stucco.morph.ast._
import gov.ornl.stucco.morph.extractor.Extractor

/**
 * CVE data extractor.
 *
 * @author Anish Athalye
 */
object CveExtractor extends Extractor {

  def extract(node: ValueNode): ValueNode = ^(
    "vertices" -> (node ~> "cve" ~> "item" %%-> { item =>
      ^(
        "_id" -> item ~> "@name",

        "_type" -> "vertex",

        "source" -> "CVE",

        "comments" -> item ~> "comments" ~> "comment" %%-> { _ ~> "#text" },

        "description" -> item ~> "desc",

        "phase" -> (item ~> "phase" ~> "#text"),
        "phaseDate" -> (item ~> "phase" ~> "@date"),

        "references" -> (
          item ~> "refs" ~> "ref" %%-> { obj =>
            obj ~> "@url" orElse Safely {
              (obj ~> "@source").asString + ":" +
                (obj ~> "#text").asString
            }
          }
        ).encapsulate,

        "status" -> item ~> "status"
      )
    }).encapsulate
  )
}
