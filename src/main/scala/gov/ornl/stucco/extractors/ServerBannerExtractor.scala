package gov.ornl.stucco.extractors

import gov.ornl.stucco.morph.ast._
import gov.ornl.stucco.morph.extractor.Extractor

/**
 * server banner data extractor.
 *
 * @author Mike Iannacone
 */
object ServerBannerExtractor extends Extractor {

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

    val headers = *("filename","recnum","file_type","amp_version","site","banner","addr","server_port","app_protocol","times_seen","first_seen_timet","last_seen_timet","countrycode","organization","lat","long")

    val h = headers.asList.zipWithIndex.map { a => a }.toMap

    ^(
      "vertices" -> (node mapPartial {
        //this will ignore header row and will ignore last row if it is just an empty string.
        case item if (item ~> 0 != headers ~> 0) && (item ~> 1 != None) =>
          *(
            {
              val n = ^(
                "_id" -> Safely {
                      (item ~> h("addr")).asString + ":" + (item ~> h("app_protocol")).asString
                    },
                "name" -> Safely {
                      (item ~> h("addr")).asString + ":" + (item ~> h("app_protocol")).asString
                    },
                "description" -> Safely {
                      (item ~> h("addr")).asString + ", port " + (item ~> h("app_protocol")).asString
                    },
                "_type" -> "vertex",
                "vertexType" -> "address",
                "source" -> "server_banner"
              )
              if ((item ~> h("addr")).nodeNonEmpty && (item ~> h("app_protocol")).nodeNonEmpty &&
                  notEmpty(n ~> "_id")) n
              else None
            },
            {
              val n = ^(
                "_id" -> item ~> h("addr"),
                "name" -> item ~> h("addr"),
                "description" -> item ~> h("addr"),
                "_type" -> "vertex",
                "vertexType" -> "IP",
                "source" -> "server_banner"
              )
              if ((item ~> h("addr")).nodeNonEmpty &&
                  notEmpty(n ~> "_id")) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely{(item ~> h("app_protocol")).asString},
                "name" -> Safely{(item ~> h("app_protocol")).asString},
                "description" -> Safely{(item ~> h("app_protocol")).asString},
                "_type" -> "vertex",
                "vertexType" -> "port",
                "source" -> "server_banner"
              )
              if ((item ~> h("app_protocol")).nodeNonEmpty &&
                  notEmpty(n ~> "_id")) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely{(item ~> h("banner")).asString.replace(' ', '_')},
                "name" -> Safely{(item ~> h("banner")).asString},
                "description" -> Safely{(item ~> h("banner")).asString},
                "_type" -> "vertex",
                "vertexType" -> "service",
                "source" -> "server_banner"
              )
              if ((item ~> h("banner")).nodeNonEmpty &&
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
                  (item ~> h("addr")).asString + ":" + (item ~> h("app_protocol")).asString + "_hasIP_" +
                  (item ~> h("addr")).asString
                },
                "description" -> Safely {
                  (item ~> h("addr")).asString + ", port " + (item ~> h("app_protocol")).asString + " has IP " +
                  (item ~> h("addr")).asString
                },
                "_outV" -> Safely {
                  (item ~> h("addr")).asString + ":" + (item ~> h("app_protocol")).asString
                },
                "_inV" -> item ~> h("addr"),
                "_type" -> "edge",
                "_label" -> "hasIP",
                "source" -> "server_banner",
                "outVType" -> "address",
                "inVType" -> "IP"
              )
              if ((item ~> h("addr")).nodeNonEmpty && (item ~> h("app_protocol")).nodeNonEmpty &&
                  notEmpty(n ~> "_inV") && notEmpty(n ~> "_outV")) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely {
                  (item ~> h("addr")).asString + ":" + (item ~> h("app_protocol")).asString + "_hasPort_" +
                  (item ~> h("app_protocol")).asString
                },
                "description" -> Safely {
                  (item ~> h("addr")).asString + ", port " + (item ~> h("app_protocol")).asString + " has port " +
                  (item ~> h("app_protocol")).asString
                },
                "_outV" -> Safely {
                  (item ~> h("addr")).asString + ":" + (item ~> h("app_protocol")).asString
                },
                "_inV" -> Safely{(item ~> h("app_protocol")).asString},
                "_type" -> "edge",
                "_label" -> "hasPort",
                "source" -> "server_banner",
                "outVType" -> "address",
                "inVType" -> "port"
              )
              if ((item ~> h("addr")).nodeNonEmpty && (item ~> h("app_protocol")).nodeNonEmpty &&
                  notEmpty(n ~> "_inV") && notEmpty(n ~> "_outV")) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely {
                  (item ~> h("addr")).asString + ":" + (item ~> h("app_protocol")).asString + "_hasKnownService_" +
                  (item ~> h("banner")).asString.replace(' ', '_')
                },
                "description" -> Safely {
                  (item ~> h("addr")).asString + ", port " + (item ~> h("app_protocol")).asString + " has service " +
                  (item ~> h("banner")).asString
                },
                "_outV" -> Safely {
                  (item ~> h("addr")).asString + ":" + (item ~> h("app_protocol")).asString
                },
                "_inV" -> Safely{(item ~> h("banner")).asString.replace(' ', '_')},
                "_type" -> "edge",
                "_label" -> "hasKnownService",
                "source" -> "server_banner",
                "outVType" -> "address",
                "inVType" -> "service"
              )
              if ((item ~> h("addr")).nodeNonEmpty && (item ~> h("app_protocol")).nodeNonEmpty && (item ~> h("banner")).nodeNonEmpty &&
                  notEmpty(n ~> "_inV") && notEmpty(n ~> "_outV")) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely {
                  (item ~> h("app_protocol")).asString + "_hasKnownService_" +
                  (item ~> h("banner")).asString.replace(' ', '_')
                },
                "description" -> Safely {
                  (item ~> h("app_protocol")).asString + " has service " +
                  (item ~> h("banner")).asString
                },
                "_outV" -> Safely {
                  (item ~> h("app_protocol")).asString
                },
                "_inV" -> Safely{(item ~> h("banner")).asString.replace(' ', '_')},
                "_type" -> "edge",
                "_label" -> "hasKnownService",
                "source" -> "server_banner",
                "outVType" -> "port",
                "inVType" -> "service"
              )
              if ((item ~> h("app_protocol")).nodeNonEmpty && (item ~> h("banner")).nodeNonEmpty &&
                  notEmpty(n ~> "_inV") && notEmpty(n ~> "_outV")) n
              else None
            }
          )
      }).autoFlatten
    )
  }
}
