package gov.ornl.stucco.extractors

import morph.ast._
import morph.extractor.Extractor

/**
 * NVD data extractor.
 *
 * @author Mike Iannacone
 * @author Anish Athalye
 */
object NvdExtractor extends Extractor {

  def extract(node: ValueNode): ValueNode = {
    ^(
      "vertices" -> ((node ~> "nvd" ~> "entry" %%-> { item =>
        ^(
          "_id" -> item ~> "@id",
          "_type" -> "vertex",
          "vertexType" -> "vulnerability",
          "source" -> "NVD",
          "description" -> item ~> "vuln:summary",
          "publishedDate" -> item ~> "vuln:published-datetime",
          "modifiedDate" -> item ~> "vuln:last-modified-datetime",
          "cweNumber" -> item ~> "vuln:cwe" ~> "@id",
          
          "cvssScore" -> item ~> "vuln:cvss" ~> "cvss:base_metrics" ~> "cvss:score",
          "accessVector" -> item ~> "vuln:cvss" ~> "cvss:base_metrics" ~> "cvss:access-vector",
          "accessComplexity" -> item ~> "vuln:cvss" ~> "cvss:base_metrics" ~> "cvss:access-complexity",
          "accessAuthentication" -> item ~> "vuln:cvss" ~> "cvss:base_metrics" ~> "cvss:authentication",
          "confidentialityImpact" -> item ~> "vuln:cvss" ~> "cvss:base_metrics" ~> "cvss:confidentiality-impact",
          "integrityImpact" -> item ~> "vuln:cvss" ~> "cvss:base_metrics" ~> "cvss:integrity-impact",
          "availabilityImpact" -> item ~> "vuln:cvss" ~> "cvss:base_metrics" ~> "cvss:availability-impact",
          "cvssDate" -> item ~> "vuln:cvss" ~> "cvss:base_metrics" ~> "cvss:generated-on-datetime",

          "references" -> ((
            item ~> "vuln:references" %%-> { obj =>
              obj ~> "vuln:reference" ~> "@href" orElse Safely {
                (obj ~> "vuln:source").asString + ":" +
                (obj ~> "vuln:reference" ~> "#text").asString
              }
            }) map {
              case arr: ArrayNode => arr
              case other => ArrayNode(other)
            })
        )
      }) map {
            case arr: ArrayNode => arr
            case other => ArrayNode(other)
      }),

      "edges" -> ((node ~> "nvd" ~> "entry" %%-> { nvdItem => 
        (nvdItem ~> "vuln:vulnerable-software-list" ~> "vuln:product" %%-> { cpeItem =>
          ^(
            "_id" -> nvdItem ~> "@id",
            "_type" -> "edge",
            "inVType" -> "vulnerability",
            "outVType" -> "software",
            "source" -> "NVD",
            "_inV" -> nvdItem ~> "@id",
            "_outV" -> cpeItem,
            "_label" -> ( cpeItem.asString + "_to_" + (nvdItem ~> "@id").asString )
          )
        }) map { //ensures that single elements are contained in a list of length one. (eg. NVD entries with one CPE)
            case arr: ArrayNode => arr
            case other => ArrayNode(other)
        }
      }) flatMap { arr =>
        Safely { 
          ArrayNode(arr.asList flatMap { _.asList })
        } orElse arr //if there is only one list, it can't be flattened (eg. of the NVD entries, only one has any CPE(s))
      })
    )
  }
}
