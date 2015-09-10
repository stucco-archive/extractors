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

  def getSrcPort(flow: Option[ValueNode], h: Map[ValueNode,Int]): String = {
    val protoString = (flow ~>h("Proto")).asString
    if(protoString != "icmp" && protoString != "1"){
      return (flow ~>h("Sport")).asString
    }else{
      return "0" //TODO: could return "ICMP" or something else descriptive instead.
    }
  }

  def getDstPort(flow: Option[ValueNode], h: Map[ValueNode,Int]): String = {
    val protoString = (flow ~>h("Proto")).asString
    if(protoString != "icmp" && protoString != "1"){
      return (flow ~>h("Dport")).asString
    }else{
      return "0" //TODO: could return "ICMP" or something else descriptive instead.
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
                      (item ~> h("SrcAddr")).asString + ":" + getSrcPort(item, h) + "::" +
                        (item ~> h("DstAddr")).asString + ":" + getDstPort(item, h)
                    },
                "name" -> Safely {
                      (item ~> h("SrcAddr")).asString + ":" + getSrcPort(item, h) + "::" +
                        (item ~> h("DstAddr")).asString + ":" + getDstPort(item, h)
                    },
                "description" -> Safely {
                      (item ~> h("SrcAddr")).asString + ", port " + getSrcPort(item, h) + " to " +
                        (item ~> h("DstAddr")).asString + ", port " + getDstPort(item, h)
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
                  //(item ~> h("State") != Some(S("ECO"))) &&
                  notEmpty(n ~> "_id")) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely {
                      (item ~> h("SrcAddr")).asString + ":" + getSrcPort(item, h)
                    },
                "name" -> Safely {
                      (item ~> h("SrcAddr")).asString + ":" + getSrcPort(item, h)
                    },
                "description" -> Safely {
                      (item ~> h("SrcAddr")).asString + ", port " + getSrcPort(item, h)
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
                      (item ~> h("DstAddr")).asString + ":" + getDstPort(item, h)
                    },
                "name" -> Safely {
                      (item ~> h("DstAddr")).asString + ":" + getDstPort(item, h)
                    },
                "description" -> Safely {
                      (item ~> h("DstAddr")).asString + ", port " + getDstPort(item, h)
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
                "_id" -> getSrcPort(item, h),
                "name" -> getSrcPort(item, h),
                "description" -> getSrcPort(item, h),
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
                "_id" -> getDstPort(item, h),
                "name" -> getDstPort(item, h),
                "description" -> getDstPort(item, h),
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
                  (item ~> h("SrcAddr")).asString + ":" + getSrcPort(item, h) + "::" +
                  (item ~> h("DstAddr")).asString + ":" + getDstPort(item, h) + "_srcAddress_" +
                  (item ~> h("SrcAddr")).asString + ":" + getSrcPort(item, h)
                },
                "description" -> Safely {
                  (item ~> h("SrcAddr")).asString + ", port " + getSrcPort(item, h) + " to " +
                  (item ~> h("DstAddr")).asString + ", port " + getDstPort(item, h) + " has source address " +
                  (item ~> h("SrcAddr")).asString + ", port " + getSrcPort(item, h)
                },
                "_outV" -> Safely {
                  (item ~> h("SrcAddr")).asString + ":" + getSrcPort(item, h) + "::" +
                  (item ~> h("DstAddr")).asString + ":" + getDstPort(item, h)
                },
                "_inV" -> Safely {
                  (item ~> h("SrcAddr")).asString + ":" + getSrcPort(item, h)
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
                  (item ~> h("SrcAddr")).asString + ":" + getSrcPort(item, h) + "::" +
                  (item ~> h("DstAddr")).asString + ":" + getDstPort(item, h) + "_dstAddress_" +
                  (item ~> h("DstAddr")).asString + ":" + getDstPort(item, h)
                },
                "description" -> Safely {
                  (item ~> h("SrcAddr")).asString + ", port " + getSrcPort(item, h) + " to " +
                  (item ~> h("DstAddr")).asString + ", port " + getDstPort(item, h) + " has destination address " +
                  (item ~> h("DstAddr")).asString + ", port " + getDstPort(item, h)
                },
                "_outV" -> Safely {
                  (item ~> h("SrcAddr")).asString + ":" + getSrcPort(item, h) + "::" +
                  (item ~> h("DstAddr")).asString + ":" + getDstPort(item, h)
                },
                "_inV" -> Safely {
                  (item ~> h("DstAddr")).asString + ":" + getDstPort(item, h)
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
                  (item ~> h("SrcAddr")).asString + ":" + getSrcPort(item, h) + "_hasIP_" +
                  (item ~> h("SrcAddr")).asString
                },
                "description" -> Safely {
                  (item ~> h("SrcAddr")).asString + ", port " + getSrcPort(item, h) + " has IP " +
                  (item ~> h("SrcAddr")).asString
                },
                "_outV" -> Safely {
                  (item ~> h("SrcAddr")).asString + ":" + getSrcPort(item, h)
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
                  (item ~> h("DstAddr")).asString + ":" + getDstPort(item, h) + "_hasIP_" +
                  (item ~> h("DstAddr")).asString
                },
                "description" -> Safely {
                  (item ~> h("DstAddr")).asString + ", port " + getDstPort(item, h) + " has IP " +
                  (item ~> h("DstAddr")).asString
                },
                "_outV" -> Safely {
                  (item ~> h("DstAddr")).asString + ":" + getDstPort(item, h)
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
                  (item ~> h("SrcAddr")).asString + ":" + getSrcPort(item, h) + "_hasPort_" +
                  getSrcPort(item, h)
                },
                "description" -> Safely {
                  (item ~> h("SrcAddr")).asString + ", port " + getSrcPort(item, h) + " has port " +
                  getSrcPort(item, h)
                },
                "_outV" -> Safely {
                  (item ~> h("SrcAddr")).asString + ":" + getSrcPort(item, h)
                },
                "_inV" -> getSrcPort(item, h),
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
                  (item ~> h("DstAddr")).asString + ":" + getDstPort(item, h) + "_hasPort_" +
                  getDstPort(item, h)
                },
                "description" -> Safely {
                  (item ~> h("DstAddr")).asString + ", port " + getDstPort(item, h) + " has port " +
                  getDstPort(item, h)
                },
                "_outV" -> Safely {
                  (item ~> h("DstAddr")).asString + ":" + getDstPort(item, h)
                },
                "_inV" -> getDstPort(item, h),
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
