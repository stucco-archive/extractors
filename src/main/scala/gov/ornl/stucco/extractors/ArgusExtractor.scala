package gov.ornl.stucco.extractors

import gov.ornl.stucco.morph.ast._
import gov.ornl.stucco.morph.extractor.Extractor

/**
 * Argus data extractor.
 *
 * @author Mike Iannacone
 */
object ArgusExtractor extends Extractor {

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

    val headers = *("StartTime","Flgs","Proto","SrcAddr","Sport","Dir","DstAddr","Dport","TotPkts","TotBytes","State")

    val h = headers.asList.zipWithIndex.map { a => a }.toMap
    
    ^(
      "vertices" -> (node mapPartial {
        //this will ignore header row and will ignore last row if it is just an empty string.
        case item if (item ~> 0 != headers ~> 0) && (item ~> 1 != None)  && (item ~> h("Proto") != Some(S("man"))) =>
          *(
            {
              val n = ^(
                "_id" -> Safely {
                      (item ~> h("SrcAddr")).asString + ":" + (item ~>h("Sport")).asString + "::" +
                        (item ~> h("DstAddr")).asString + ":" + (item ~> h("Dport")).asString
                    },
                "name" -> Safely {
                      (item ~> h("SrcAddr")).asString + ":" + (item ~>h("Sport")).asString + "::" +
                        (item ~> h("DstAddr")).asString + ":" + (item ~> h("Dport")).asString
                    },
                "description" -> Safely {
                      (item ~> h("SrcAddr")).asString + ", port " + (item ~>h("Sport")).asString + " to " +
                        (item ~> h("DstAddr")).asString + ", port " + (item ~> h("Dport")).asString
                    },
                "_type" -> "vertex",
                "vertexType" -> "flow",
                "source" -> "Argus", 
                "proto" -> item ~> h("Proto"),
                "appBytes" -> item ~> h("TotBytes"),        
                "state" -> item ~> h("State"),
                "startTime" -> getTime(item ~> h("StartTime")),
  //              "appByteRatio" -> item ~> "@AppByteRatio",
                "dir" -> item ~> h("Dir"),
                "flags" -> item ~> h("Flgs")
  //              "duration" -> item ~> "@Duration",
  //              "dstPkts" -> item ~> "@DstPkts",
  //              "srcPkts" -> item ~> "@SrcPkts"
              )

              if ((item ~> h("SrcAddr")).nodeNonEmpty && (item ~> h("Sport")).nodeNonEmpty &&
                  (item ~> h("DstAddr")).nodeNonEmpty && (item ~> h("Dport")).nodeNonEmpty &&
                  notEmpty(n ~> "_id")) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely {
                      (item ~> h("SrcAddr")).asString + ":" + (item ~> h("Sport")).asString
                    },
                "name" -> Safely {
                      (item ~> h("SrcAddr")).asString + ":" + (item ~> h("Sport")).asString
                    },
                "description" -> Safely {
                      (item ~> h("SrcAddr")).asString + ", port " + (item ~> h("Sport")).asString
                    },
                "_type" -> "vertex",
                "vertexType" -> "address",
                "source" -> "Argus"
              )
              if ((item ~> h("SrcAddr")).nodeNonEmpty && (item ~> h("Sport")).nodeNonEmpty &&
                  notEmpty(n ~> "_id")) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely {
                      (item ~> h("DstAddr")).asString + ":" + (item ~> h("Dport")).asString
                    },
                "name" -> Safely {
                      (item ~> h("DstAddr")).asString + ":" + (item ~> h("Dport")).asString
                    },
                "description" -> Safely {
                      (item ~> h("DstAddr")).asString + ", port " + (item ~> h("Dport")).asString
                    },
                "_type" -> "vertex",
                "vertexType" -> "address",
                "source" -> "Argus"
              )
              if ((item ~> h("DstAddr")).nodeNonEmpty && (item ~> h("Dport")).nodeNonEmpty &&
                  notEmpty(n ~> "_id")) n
              else None
            },
            {
              val n = ^(
                "_id" -> item ~> h("SrcAddr"),
                "name" -> item ~> h("SrcAddr"),
                "description" -> item ~> h("SrcAddr"),
                "_type" -> "vertex",
                "vertexType" -> "IP",
                "source" -> "Argus"
              )
              if ((item ~> h("SrcAddr")).nodeNonEmpty &&
                  notEmpty(n ~> "_id")) n
              else None
            },
            {
              val n = ^(
                "_id" -> item ~> h("DstAddr"),
                "name" -> item ~> h("DstAddr"),
                "description" -> item ~> h("DstAddr"),
                "_type" -> "vertex",
                "vertexType" -> "IP",
                "source" -> "Argus"
              )
              if ((item ~> h("DstAddr")).nodeNonEmpty &&
                  notEmpty(n ~> "_id")) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely{(item ~> h("Sport")).asString},
                "name" -> Safely{(item ~> h("Sport")).asString},
                "description" -> Safely{(item ~> h("Sport")).asString},
                "_type" -> "vertex",
                "vertexType" -> "port",
                "source" -> "Argus"
              )
              if ((item ~> h("Sport")).nodeNonEmpty &&
                  notEmpty(n ~> "_id")) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely{(item ~> h("Dport")).asString},
                "name" -> Safely{(item ~> h("Dport")).asString},
                "description" -> Safely{(item ~> h("Dport")).asString},
                "_type" -> "vertex",
                "vertexType" -> "port",
                "source" -> "Argus"
              )
              if ((item ~> h("Dport")).nodeNonEmpty &&
                  notEmpty(n ~> "_id")) n
              else None
            }
          )
        }).autoFlatten,

      "edges" -> (node mapPartial {
        //this will ignore header row and will ignore last row if it is just an empty string.
        case item if (item ~> 0 != headers ~> 0) && (item ~> 1 != None)   && (item ~> h("Proto") != Some(S("man")))=>
          *(
            {
              val n = ^(
                "_id" -> Safely {
                  (item ~> h("SrcAddr")).asString + ":" + (item ~> h("Sport")).asString + "::" +
                  (item ~> h("DstAddr")).asString + ":" + (item ~> h("Dport")).asString + "_srcAddress_" +
                  (item ~> h("SrcAddr")).asString + ":" + (item ~> h("Sport")).asString
                },
                "description" -> Safely {
                  (item ~> h("SrcAddr")).asString + ", port " + (item ~> h("Sport")).asString + " to " +
                  (item ~> h("DstAddr")).asString + ", port " + (item ~> h("Dport")).asString + " has source address " +
                  (item ~> h("SrcAddr")).asString + ", port " + (item ~> h("Sport")).asString
                },
                "_outV" -> Safely {
                  (item ~> h("SrcAddr")).asString + ":" + (item ~> h("Sport")).asString + "::" +
                  (item ~> h("DstAddr")).asString + ":" + (item ~> h("Dport")).asString
                },
                "_inV" -> Safely {
                  (item ~> h("SrcAddr")).asString + ":" + (item ~> h("Sport")).asString
                },
                "_type" -> "edge",
                "_label" -> "srcAddress",
                "source" -> "Argus",
                "outVType" -> "flow",
                "inVType" -> "address"
              )
              if ((item ~> h("SrcAddr")).nodeNonEmpty && (item ~> h("Sport")).nodeNonEmpty &&
                  (item ~> h("DstAddr")).nodeNonEmpty && (item ~> h("Dport")).nodeNonEmpty &&
                  notEmpty(n ~> "_inV") && notEmpty(n ~> "_outV")) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely {
                  (item ~> h("SrcAddr")).asString + ":" + (item ~> h("Sport")).asString + "::" +
                  (item ~> h("DstAddr")).asString + ":" + (item ~> h("Dport")).asString + "_dstAddress_" +
                  (item ~> h("DstAddr")).asString + ":" + (item ~> h("Dport")).asString
                },
                "description" -> Safely {
                  (item ~> h("SrcAddr")).asString + ", port " + (item ~> h("Sport")).asString + " to " +
                  (item ~> h("DstAddr")).asString + ", port " + (item ~> h("Dport")).asString + " has destination address " +
                  (item ~> h("DstAddr")).asString + ", port " + (item ~> h("Dport")).asString
                },
                "_outV" -> Safely {
                  (item ~> h("SrcAddr")).asString + ":" + (item ~> h("Sport")).asString + "::" +
                  (item ~> h("DstAddr")).asString + ":" + (item ~> h("Dport")).asString
                },
                "_inV" -> Safely {
                  (item ~> h("DstAddr")).asString + ":" + (item ~> h("Dport")).asString
                },
                "_type" -> "edge",
                "_label" -> "dstAddress",
                "source" -> "Argus",
                "outVType" -> "flow",
                "inVType" -> "address"
              )
              if ((item ~> h("SrcAddr")).nodeNonEmpty && (item ~> h("Sport")).nodeNonEmpty &&
                  (item ~> h("DstAddr")).nodeNonEmpty && (item ~> h("Dport")).nodeNonEmpty &&
                  notEmpty(n ~> "_inV") && notEmpty(n ~> "_outV")) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely {
                  (item ~> h("SrcAddr")).asString + ":" + (item ~> h("Sport")).asString + "_hasIP_" +
                  (item ~> h("SrcAddr")).asString
                },
                "description" -> Safely {
                  (item ~> h("SrcAddr")).asString + ", port " + (item ~> h("Sport")).asString + " has IP " +
                  (item ~> h("SrcAddr")).asString
                },
                "_outV" -> Safely {
                  (item ~> h("SrcAddr")).asString + ":" + (item ~> h("Sport")).asString
                },
                "_inV" -> item ~> h("SrcAddr"),
                "_type" -> "edge",
                "_label" -> "hasIP",
                "source" -> "Argus",
                "outVType" -> "address",
                "inVType" -> "IP"
              )
              if ((item ~> h("SrcAddr")).nodeNonEmpty && (item ~> h("Sport")).nodeNonEmpty &&
                  notEmpty(n ~> "_inV") && notEmpty(n ~> "_outV")) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely {
                  (item ~> h("DstAddr")).asString + ":" + (item ~> h("Dport")).asString + "_hasIP_" +
                  (item ~> h("DstAddr")).asString
                },
                "description" -> Safely {
                  (item ~> h("DstAddr")).asString + ", port " + (item ~> h("Dport")).asString + " has IP " +
                  (item ~> h("DstAddr")).asString
                },
                "_outV" -> Safely {
                  (item ~> h("DstAddr")).asString + ":" + (item ~> h("Dport")).asString
                },
                "_inV" -> item ~> h("DstAddr"),
                "_type" -> "edge",
                "_label" -> "hasIP",
                "source" -> "Argus",
                "outVType" -> "address",
                "inVType" -> "IP"
              )
              if ((item ~> h("DstAddr")).nodeNonEmpty && (item ~> h("Dport")).nodeNonEmpty &&
                  notEmpty(n ~> "_inV") && notEmpty(n ~> "_outV")) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely {
                  (item ~> h("SrcAddr")).asString + ":" + (item ~> h("Sport")).asString + "_hasPort_" +
                  (item ~> h("Sport")).asString
                },
                "description" -> Safely {
                  (item ~> h("SrcAddr")).asString + ", port " + (item ~> h("Sport")).asString + " has port " +
                  (item ~> h("Sport")).asString
                },
                "_outV" -> Safely {
                  (item ~> h("SrcAddr")).asString + ":" + (item ~> h("Sport")).asString
                },
                "_inV" -> Safely{(item ~> h("Sport")).asString},
                "_type" -> "edge",
                "_label" -> "hasPort",
                "source" -> "Argus",
                "outVType" -> "address",
                "inVType" -> "port"
              )
              if ((item ~> h("SrcAddr")).nodeNonEmpty && (item ~> h("Sport")).nodeNonEmpty &&
                  notEmpty(n ~> "_inV") && notEmpty(n ~> "_outV")) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely {
                  (item ~> h("DstAddr")).asString + ":" + (item ~> h("Dport")).asString + "_hasPort_" +
                  (item ~> h("Dport")).asString
                },
                "description" -> Safely {
                  (item ~> h("DstAddr")).asString + ", port " + (item ~> h("Dport")).asString + " has port " +
                  (item ~> h("Dport")).asString
                },
                "_outV" -> Safely {
                  (item ~> h("DstAddr")).asString + ":" + (item ~> h("Dport")).asString
                },
                "_inV" -> Safely{(item ~> h("Dport")).asString},
                "_type" -> "edge",
                "_label" -> "hasPort",
                "source" -> "Argus",
                "outVType" -> "address",
                "inVType" -> "port"
              )
              if ((item ~> h("DstAddr")).nodeNonEmpty && (item ~> h("Dport")).nodeNonEmpty &&
                  notEmpty(n ~> "_inV") && notEmpty(n ~> "_outV")) n
              else None
            }
          )
      }).autoFlatten
    )
  }
}
