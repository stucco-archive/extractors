package gov.ornl.stucco.extractors

import gov.ornl.stucco.morph.ast._
import gov.ornl.stucco.morph.extractor.Extractor

/**
 * services list extractor.
 *
 * @author Mike Iannacone
 */
object ServiceListExtractor extends Extractor {

  // to make testing easier
  val O = ObjectNode
  val A = ArrayNode
  val S = StringNode
  val N = NumberNode

  //TODO: it would be useful to also check non-strings here.
  //TODO: also this is c&p from hone extractor, no good...
  def notEmpty(node: Option[ValueNode]): Boolean = {
    node != None && node != Some(S(""))
  }

  def getTime(node: Option[ValueNode]): Option[ValueNode] = {
    val dateString = node.asString
    if(dateString != ""){
      return (dateString.toDouble * 1000).toLong
    }else{
      return None
    }
  }

  def extract(node: ValueNode): ValueNode = {

    val headers = *("Service Name","Port Number","Transport Protocol","Description","Assignee","Contact","Registration Date","Modification Date","Reference","Service Code","Known Unauthorized Uses","Assignment Notes")

    val h = headers.asList.zipWithIndex.map { a => a }.toMap

    ^(
      "vertices" -> (node mapPartial {
        //this will ignore header row and will ignore last row if it is just an empty string.
        case item if (item ~> 0 != headers ~> 0) && (item ~> 1 != None) =>
          *(
            {
              val n = ^(
                "_id" -> Safely{(item ~> h("Service Name")).asString.replace(' ', '_')},
                "name" -> Safely{(item ~> h("Service Name")).asString},
                "description" -> Safely{(item ~> h("Description")).asString},
                "reference" -> (item ~> h("Reference")),
                "notes" -> (item ~> h("Assignment Notes")),
                "_type" -> "vertex",
                "vertexType" -> "service",
                "source" -> "service_list"
              )
              if ((item ~> h("Service Name")).nodeNonEmpty && (item ~> h("Port Number")).nodeNonEmpty &&
                  notEmpty(n ~> "_id")) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely{(item ~> h("Port Number")).asString},
                "name" -> Safely{(item ~> h("Port Number")).asString},
                "description" -> Safely{(item ~> h("Port Number")).asString},
                "_type" -> "vertex",
                "vertexType" -> "port",
                "source" -> "service_list"
              )
              if ((item ~> h("Port Number")).nodeNonEmpty && (item ~> h("Service Name")).nodeNonEmpty &&
                  notEmpty(n ~> "_id")) n
              else None
            }
          )
        }).autoFlatten,

      "edges" -> (node mapPartial {
        //this will ignore header row and will ignore last row if it is just an empty string.
        case item if (item ~> 0 != headers ~> 0) && (item ~> 1 != None) =>
          *(
            {
              val n = ^(
                "_id" -> Safely {
                  (item ~> h("Port Number")).asString + "_hasKnownService_" +
                  (item ~> h("Service Name")).asString.replace(' ', '_')
                },
                "description" -> Safely {
                  (item ~> h("Port Number")).asString + " has service " +
                  (item ~> h("Service Name")).asString
                },
                "_outV" -> Safely {
                  (item ~> h("Port Number")).asString
                },
                "_inV" -> Safely{(item ~> h("Service Name")).asString.replace(' ', '_')},
                "_type" -> "edge",
                "_label" -> "hasKnownService",
                "source" -> "service_list",
                "outVType" -> "port",
                "inVType" -> "service"
              )
              if ((item ~> h("Port Number")).nodeNonEmpty && (item ~> h("Service Name")).nodeNonEmpty &&
                  notEmpty(n ~> "_inV") && notEmpty(n ~> "_outV")) n
              else None
            }
          )
      }).autoFlatten
    )
  }
}
