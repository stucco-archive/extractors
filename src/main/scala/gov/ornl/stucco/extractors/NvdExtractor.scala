package gov.ornl.stucco.extractors

import gov.ornl.stucco.morph.ast._
import gov.ornl.stucco.morph.extractor.Extractor

/**
 * NVD data extractor.
 *
 * @author Mike Iannacone
 * @author Anish Athalye
 */
object NvdExtractor extends Extractor {

  val format = new java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX")
  
  def makeCpeDesc(node: Option[ValueNode]): Option[ValueNode] = {
    val substrings = node.asString split ":"
    val vendor = (substrings lift 2)
    val product = (substrings lift 3)
    val version = (substrings lift 4)
    val update = (substrings lift 5)
    val edition = (substrings lift 6)
    val language = (substrings lift 7)
    var res = ""
    if(vendor.isDefined){
      res = vendor.get + " "
    }
    if(product.isDefined){
      res += product.get
      if(version.isDefined){
        res += " version " + version.get
        if(update.isDefined){
          res += " " + update.get
          if(edition.isDefined){
            res += " " + edition.get
          }
        }
      }
      if(language.isDefined){
        res += ", " + language.get + " language version"
      }
    }
    if(res != "")
      Some(res)
    else
      None
  }

  def extract(node: ValueNode): ValueNode = ^(
    "vertices" -> (node ~> "nvd" ~> "entry" %%-> { item =>
      *(
        ^(
          "_id" -> item ~> "@id",
          "name" -> item ~> "@id",
          "_type" -> "vertex",
          "vertexType" -> "vulnerability",
          "source" -> "NVD",
          "description" -> item ~> "vuln:summary",
          "publishedDate" -> Safely{ format.parse( (item ~> "vuln:published-datetime").asString ).getTime() },
          "modifiedDate" -> Safely{ format.parse( (item ~> "vuln:last-modified-datetime").asString ).getTime() },
          "cweNumber" -> item ~> "vuln:cwe" ~> "@id",

          "cvssScore" -> item ~> "vuln:cvss" ~> "cvss:base_metrics" ~> "cvss:score",
          "accessVector" -> {item ~> "vuln:cvss" ~> "cvss:base_metrics" ~> "cvss:access-vector" ~> "#text" orElse item ~> "vuln:cvss" ~> "cvss:base_metrics" ~> "cvss:access-vector"},
          "accessComplexity" -> item ~> "vuln:cvss" ~> "cvss:base_metrics" ~> "cvss:access-complexity",
          "accessAuthentication" -> item ~> "vuln:cvss" ~> "cvss:base_metrics" ~> "cvss:authentication",
          "confidentialityImpact" -> item ~> "vuln:cvss" ~> "cvss:base_metrics" ~> "cvss:confidentiality-impact",
          "integrityImpact" -> item ~> "vuln:cvss" ~> "cvss:base_metrics" ~> "cvss:integrity-impact",
          "availabilityImpact" -> item ~> "vuln:cvss" ~> "cvss:base_metrics" ~> "cvss:availability-impact",
          "cvssDate" -> Safely{ format.parse( (item ~> "vuln:cvss" ~> "cvss:base_metrics" ~> "cvss:generated-on-datetime").asString ).getTime() },

          "references" -> (
            item ~> "vuln:references" %%-> { obj =>
              obj ~> "vuln:reference" ~> "@href" orElse Safely {
                (obj ~> "vuln:source").asString + ":" +
                  (obj ~> "vuln:reference" ~> "#text").asString
              }
            }).encapsulate
        ),
        (item ~> "vuln:vulnerable-software-list" ~> "vuln:product" %%-> { cpeItem =>
          ^(
            "_id" -> (cpeItem.asString),
            "name" -> (cpeItem.asString),
            "description" -> makeCpeDesc(cpeItem),
            "_type" -> "vertex",
            "vertexType" -> "software",
            "source" -> "NVD"
          )
        })
      )
    }).autoFlatten.autoFlatten,

    "edges" -> (node ~> "nvd" ~> "entry" %%-> { nvdItem =>
      (nvdItem ~> "vuln:vulnerable-software-list" ~> "vuln:product" %%-> { cpeItem =>
        ^(
          "_id" -> (cpeItem.asString + "_to_" + (nvdItem ~> "@id").asString),
          "description" -> (makeCpeDesc(cpeItem).asString + " to " + (nvdItem ~> "@id").asString),
          "_type" -> "edge",
          "inVType" -> "vulnerability",
          "outVType" -> "software",
          "source" -> "NVD",
          "_inV" -> nvdItem ~> "@id",
          "_outV" -> cpeItem,
          "_label" -> "hasVulnerability"
        )
      }).encapsulate
    }).autoFlatten
  )
}
