package gov.ornl.stucco.extractors

import gov.ornl.stucco.morph.ast._
import gov.ornl.stucco.morph.extractor.Extractor

/**
 * Login-event data extractor.
 *
 * @auther Zach Beech
 * @author Mike Iannacone
 */
object LoginEventExtractor extends Extractor {

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

    //Sep 24 15:10:59,WE24565,sshd,Failed,zach,::1
    //Sep 24 15:11:03,WE24565,sshd,Accepted,zach,::1
    val headers = *("date_time","hostname","login_software","status","user","from_ip")

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
                "_type" -> "vertex",
                "source" -> "LoginEvent",
                "vertexType" -> "host"
              )
              else None
            },
            {
              if ((item ~> h("user")).nodeNonEmpty)
              ^(
                "_id" -> item ~> h("user")
                "_type" -> "vertex",
                "source" -> "LoginEvent",
                "vertexType" -> "account",
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
              if ((item ~> h("hostname")).nodeNonEmpty && (item ~> h("user")).nodeNonEmpty)
              ^(
                "_id" -> Safely { (item ~> h("user")).asString + "_loginsTo_" + (item ~> h("hostname")).asString },
                "_outV" -> item ~> h("user"),
                "_inV" -> item ~> h("hostname"),
                "_type" -> "edge",
                "_label" -> "loginsTo",
                "source" -> "LoginEvent",
                "outVType" -> "account",
                "inVType" -> "host"
              )
              else None
            }
      }).autoFlatten
    )
  }
}
