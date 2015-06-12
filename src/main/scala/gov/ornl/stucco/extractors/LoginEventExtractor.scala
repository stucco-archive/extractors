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

  val format = new java.text.SimpleDateFormat("yyyy MMM dd HH:mm:ss XXX")

  def getCurrYear(): String = {
    val yearFormat = new java.text.SimpleDateFormat("yyyy")
    val yearString = yearFormat.format(new java.util.Date())
    return yearString
  }

  def getPrevYear(): String = {
    val yearString = (Integer.parseInt(getCurrYear()) - 1).toString()
    return yearString
  }

  def getTime(node: Option[ValueNode]): Option[ValueNode] = {
    var dateString = node.asString
    if(dateString != ""){
      var ts = format.parse( getCurrYear() + " " + dateString + " +00:00"  ).getTime()
      if(ts > new java.util.Date().getTime() )
        ts = format.parse( getPrevYear() + " " + dateString + " +00:00"  ).getTime()
      return ts
    }else{
      return None
    }
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
                "name" -> item ~> h("hostname"),
                "description" -> item ~> h("hostname"),
                "_type" -> "vertex",
                "source" -> "LoginEvent",
                "vertexType" -> "host"
              )
              else None
            },
            {
              if ((item ~> h("user")).nodeNonEmpty)
              ^(
                "_id" -> item ~> h("user"),
                "name" -> item ~> h("user"),
                "description" -> item ~> h("user"),
                "_type" -> "vertex",
                "source" -> "LoginEvent",
                "vertexType" -> "account"
              )
              else None
            },
            {
              if ((item ~> h("login_software")).nodeNonEmpty)
              ^(
                "_id" -> item ~> h("login_software"),
                "name" -> item ~> h("login_software"),
                "description" -> item ~> h("login_software"),
                "_type" -> "vertex",
                "source" -> "LoginEvent",
                "vertexType" -> "software",
                "product" -> item ~> h("login_software")
              )
              else None
            },
            {
              if ((item ~> h("from_ip")).nodeNonEmpty)
              ^(
                "_id" -> item ~> h("from_ip"),
                "name" -> item ~> h("from_ip"),
                "description" -> item ~> h("from_ip"),
                "_type" -> "vertex",
                "source" -> "LoginEvent",
                "vertexType" -> "IP"
              )
              else None
            },
            {
              if ((item ~> h("from_ip")).nodeNonEmpty)
              ^(
                "_id" -> Safely { "host_at_" + (item ~> h("from_ip")).asString },
                "name" -> Safely { "host_at_" + (item ~> h("from_ip")).asString },
                "description" -> Safely { "host at " + (item ~> h("from_ip")).asString },
                "_type" -> "vertex",
                "source" -> "LoginEvent",
                "vertexType" -> "host"
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
                "_id" -> Safely { (item ~> h("user")).asString + "_logsInTo_" + (item ~> h("hostname")).asString },
                "description" -> Safely { (item ~> h("user")).asString + " logs in to " + (item ~> h("hostname")).asString },
                "_outV" -> item ~> h("user"),
                "_inV" -> item ~> h("hostname"),
                "_type" -> "edge",
                "_label" -> "logsInTo",
                "source" -> "LoginEvent",
                "outVType" -> "account",
                "inVType" -> "host",
                "timeStamp" -> getTime(item ~> h("date_time")),
                "status" -> item ~> h("status")
              )
              else None
            },
            {
              if ((item ~> h("hostname")).nodeNonEmpty && (item ~> h("user")).nodeNonEmpty)
              ^(
                "_id" -> Safely { (item ~> h("user")).asString + "_logsInFrom_" + "host_at_" + (item ~> h("from_ip")).asString },
                "description" -> Safely { (item ~> h("user")).asString + " logs in from " + "host at " + (item ~> h("from_ip")).asString },
                "_outV" -> item ~> h("user"),
                "_inV" -> Safely { "host_at_" + (item ~> h("from_ip")).asString },
                "_type" -> "edge",
                "_label" -> "logsInFrom",
                "source" -> "LoginEvent",
                "outVType" -> "account",
                "inVType" -> "host",
                "timeStamp" -> getTime(item ~> h("date_time")),
                "status" -> item ~> h("status")
              )
              else None
            },
            {
              if ((item ~> h("hostname")).nodeNonEmpty && (item ~> h("user")).nodeNonEmpty)
              ^(
                "_id" -> Safely { "host_at_" + (item ~> h("from_ip")).asString + "_hasIP_" + (item ~> h("from_ip")).asString },
                "description" -> Safely { "host at " + (item ~> h("from_ip")).asString + " has IP " + (item ~> h("from_ip")).asString },
                "_outV" -> Safely { "host_at_" + (item ~> h("from_ip")).asString },
                "_inV" -> Safely { (item ~> h("from_ip")).asString },
                "_type" -> "edge",
                "_label" -> "hasIP",
                "source" -> "LoginEvent",
                "outVType" -> "host",
                "inVType" -> "IP"
              )
              else None
            },
            {
              if ((item ~> h("hostname")).nodeNonEmpty && (item ~> h("login_software")).nodeNonEmpty)
              ^(
                "_id" -> Safely { (item ~> h("hostname")).asString + "_runs_" + (item ~> h("login_software")).asString },
                "description" -> Safely { (item ~> h("hostname")).asString + " runs " + (item ~> h("login_software")).asString },
                "_outV" -> item ~> h("hostname"),
                "_inV" -> item ~> h("login_software"),
                "_type" -> "edge",
                "_label" -> "runs",
                "source" -> "LoginEvent",
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
