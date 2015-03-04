package gov.ornl.stucco.extractors

import gov.ornl.stucco.morph.ast._
import gov.ornl.stucco.morph.extractor.Extractor

/**
 * Package-list data extractor.
 *
 * @auther Zach Beech
 * @author Mike Iannacone
 */
object PackageListExtractor extends Extractor {

  // to make testing easier
  val O = ObjectNode
  val A = ArrayNode
  val S = StringNode
  val N = NumberNode

  //TODO: also this is c&p from hone extractor, no good...
  def notEmpty(node: Option[ValueNode]): Boolean = {
    node != None && node != Some(S(""))
  }

  def extract(node: ValueNode): ValueNode = {

    val headers = *("hostname","package","version")

    val h = headers.asList.zipWithIndex.map { a => a }.toMap
    
    ^(
      "vertices" -> (node mapPartial {
        //this will ignore header row and will ignore last row if it is just an empty string.
        case item if (item ~> 0 != headers ~> 0) && (item ~> 1 != None) =>
          *(
            {
              if ((item ~> h("hostname")).nodeNonEmpty)
              ^(
                "_id" -> item ~> h("hostname"),
                "name" -> item ~> h("hostname"),
                "description" -> item ~> h("hostname"),
                "_type" -> "vertex",
                "source" -> "PackageList",
                "vertexType" -> "host"
              )
              else None
            },
            {
              if ((item ~> h("package")).nodeNonEmpty && (item ~> h("version")).nodeNonEmpty)
              ^(
                "_id" -> Safely { (item ~> h("package")).asString + "_" + (item ~> h("version")).asString },
                "name" -> Safely { (item ~> h("package")).asString + "_" + (item ~> h("version")).asString },
                "description" -> Safely { (item ~> h("package")).asString + " version " + (item ~> h("version")).asString },
                "_type" -> "vertex",
                "source" -> "PackageList",
                "vertexType" -> "software",
                "product" -> item ~> h("package"),
                "version" -> item ~> h("version")
              )
              else None
            }
          )
        }).autoFlatten,

      "edges" -> (node mapPartial {
        //this will ignore header row and will ignore last row if it is just an empty string.
        case item if (item ~> 0 != headers ~> 0) && (item ~> 1 != None) =>
          *(
            {
              //TODO: I'm not sure if the version should be appended to the package name like this
              if ((item ~> h("hostname")).nodeNonEmpty && (item ~> h("package")).nodeNonEmpty && (item ~> h("version")).nodeNonEmpty)
              ^(
                "_id" -> Safely { (item ~> h("hostname")).asString + "_runs_" + (item ~> h("package")).asString + "_" + (item ~> h("version")).asString },
                "description" -> Safely { (item ~> h("hostname")).asString + " runs " + (item ~> h("package")).asString + "_" + (item ~> h("version")).asString },
                "_outV" -> item ~> h("hostname"),
                "_inV" -> Safely { (item ~> h("package")).asString + "_" + (item ~> h("version")).asString },
                "_type" -> "edge",
                "_label" -> "runs",
                "source" -> "PackageList",
                "outVType" -> "host",
                "inVType" -> "software"
              )
              else None
            }
          )
        }).autoFlatten
    )
  }
}
