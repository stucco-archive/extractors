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

  def extract(node: ValueNode): ValueNode = {

    val headers = *("seq","stime","ltime","saddr","sport","dir","daddr","dport",
      "proto","pkts","bytes")

    val h = headers.asList.zipWithIndex.map { a => a }.toMap
    
    ^(
      "vertices" -> (node mapPartial {
        //this will ignore header row and will ignore last row if it is just an empty string.
        case item if (item ~> 0 != headers ~> 0) && (item ~> 1 != None) =>
          *(
            {
              val n = ^(
                "_id" -> Safely {
                      (item ~> h("saddr")).asString + ":" + (item ~>h("sport")).asString + "::" +
                        (item ~> h("daddr")).asString + ":" + (item ~> h("dport")).asString
                    },
                "_type" -> "vertex",
                "vertexType" -> "flow",
                "source" -> "Argus", 
                "proto" -> item ~> h("proto"),
                "appBytes" -> item ~> h("bytes"),        
  //              "state" -> item ~> "@State",
                "startTime" -> item ~> h("stime"),
  //              "appByteRatio" -> item ~> "@AppByteRatio",
                "dir" -> item ~> h("dir")
  //              "flags" -> item ~> "@Flags",
  //              "duration" -> item ~> "@Duration",
  //              "dstPkts" -> item ~> "@DstPkts",
  //              "srcPkts" -> item ~> "@SrcPkts"
              )

              if ((item ~> h("saddr")).nodeNonEmpty && (item ~> h("sport")).nodeNonEmpty &&
                  (item ~> h("daddr")).nodeNonEmpty && (item ~> h("dport")).nodeNonEmpty &&
                  notEmpty(n ~> "_id")) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely {
                      (item ~> h("saddr")).asString + ":" + (item ~> h("sport")).asString
                    },
                "_type" -> "vertex",
                "vertexType" -> "address",
                "source" -> "Argus"
              )
              if ((item ~> h("saddr")).nodeNonEmpty && (item ~> h("sport")).nodeNonEmpty &&
                  notEmpty(n ~> "_id")) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely {
                      (item ~> h("daddr")).asString + ":" + (item ~> h("dport")).asString
                    },
                "_type" -> "vertex",
                "vertexType" -> "address",
                "source" -> "Argus"
              )
              if ((item ~> h("daddr")).nodeNonEmpty && (item ~> h("dport")).nodeNonEmpty &&
                  notEmpty(n ~> "_id")) n
              else None
            },
            {
              val n = ^(
                "_id" -> item ~> h("saddr"),
                "_type" -> "vertex",
                "vertexType" -> "IP",
                "source" -> "Argus"
              )
              if ((item ~> h("saddr")).nodeNonEmpty &&
                  notEmpty(n ~> "_id")) n
              else None
            },
            {
              val n = ^(
                "_id" -> item ~> h("daddr"),
                "_type" -> "vertex",
                "vertexType" -> "IP",
                "source" -> "Argus"
              )
              if ((item ~> h("daddr")).nodeNonEmpty &&
                  notEmpty(n ~> "_id")) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely{(item ~> h("sport")).asString},
                "_type" -> "vertex",
                "vertexType" -> "port",
                "source" -> "Argus"
              )
              if ((item ~> h("sport")).nodeNonEmpty &&
                  notEmpty(n ~> "_id")) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely{(item ~> h("dport")).asString},
                "_type" -> "vertex",
                "vertexType" -> "port",
                "source" -> "Argus"
              )
              if ((item ~> h("dport")).nodeNonEmpty &&
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
                  (item ~> h("saddr")).asString + ":" + (item ~> h("sport")).asString + "::" +
                  (item ~> h("daddr")).asString + ":" + (item ~> h("dport")).asString + "_srcAddress_" +
                  (item ~> h("saddr")).asString + ":" + (item ~> h("sport")).asString
                },
                "_outV" -> Safely {
                  (item ~> h("saddr")).asString + ":" + (item ~> h("sport")).asString + "::" +
                  (item ~> h("daddr")).asString + ":" + (item ~> h("dport")).asString
                },
                "_inV" -> Safely {
                  (item ~> h("saddr")).asString + ":" + (item ~> h("sport")).asString
                },
                "_type" -> "edge",
                "_label" -> "srcAddress",
                "source" -> "Argus",
                "outVType" -> "flow",
                "inVType" -> "address"
              )
              if ((item ~> h("saddr")).nodeNonEmpty && (item ~> h("sport")).nodeNonEmpty &&
                  (item ~> h("daddr")).nodeNonEmpty && (item ~> h("dport")).nodeNonEmpty &&
                  notEmpty(n ~> "_inV") && notEmpty(n ~> "_outV")) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely {
                  (item ~> h("saddr")).asString + ":" + (item ~> h("sport")).asString + "::" +
                  (item ~> h("daddr")).asString + ":" + (item ~> h("dport")).asString + "_dstAddress_" +
                  (item ~> h("daddr")).asString + ":" + (item ~> h("dport")).asString
                },
                "_outV" -> Safely {
                  (item ~> h("saddr")).asString + ":" + (item ~> h("sport")).asString + "::" +
                  (item ~> h("daddr")).asString + ":" + (item ~> h("dport")).asString
                },
                "_inV" -> Safely {
                  (item ~> h("daddr")).asString + ":" + (item ~> h("dport")).asString
                },
                "_type" -> "edge",
                "_label" -> "dstAddress",
                "source" -> "Argus",
                "outVType" -> "flow",
                "inVType" -> "address"
              )
              if ((item ~> h("saddr")).nodeNonEmpty && (item ~> h("sport")).nodeNonEmpty &&
                  (item ~> h("daddr")).nodeNonEmpty && (item ~> h("dport")).nodeNonEmpty &&
                  notEmpty(n ~> "_inV") && notEmpty(n ~> "_outV")) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely {
                  (item ~> h("saddr")).asString + ":" + (item ~> h("sport")).asString + "_hasIP_" +
                  (item ~> h("saddr")).asString
                },
                "_outV" -> Safely {
                  (item ~> h("saddr")).asString + ":" + (item ~> h("sport")).asString
                },
                "_inV" -> item ~> h("saddr"),
                "_type" -> "edge",
                "_label" -> "hasIP",
                "source" -> "Argus",
                "outVType" -> "address",
                "inVType" -> "IP"
              )
              if ((item ~> h("saddr")).nodeNonEmpty && (item ~> h("sport")).nodeNonEmpty &&
                  notEmpty(n ~> "_inV") && notEmpty(n ~> "_outV")) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely {
                  (item ~> h("daddr")).asString + ":" + (item ~> h("dport")).asString + "_hasIP_" +
                  (item ~> h("daddr")).asString
                },
                "_outV" -> Safely {
                  (item ~> h("daddr")).asString + ":" + (item ~> h("dport")).asString
                },
                "_inV" -> item ~> h("daddr"),
                "_type" -> "edge",
                "_label" -> "hasIP",
                "source" -> "Argus",
                "outVType" -> "address",
                "inVType" -> "IP"
              )
              if ((item ~> h("daddr")).nodeNonEmpty && (item ~> h("dport")).nodeNonEmpty &&
                  notEmpty(n ~> "_inV") && notEmpty(n ~> "_outV")) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely {
                  (item ~> h("saddr")).asString + ":" + (item ~> h("sport")).asString + "_hasPort_" +
                  (item ~> h("sport")).asString
                },
                "_outV" -> Safely {
                  (item ~> h("saddr")).asString + ":" + (item ~> h("sport")).asString
                },
                "_inV" -> Safely{(item ~> h("sport")).asString},
                "_type" -> "edge",
                "_label" -> "hasPort",
                "source" -> "Argus",
                "outVType" -> "address",
                "inVType" -> "port"
              )
              if ((item ~> h("saddr")).nodeNonEmpty && (item ~> h("sport")).nodeNonEmpty &&
                  notEmpty(n ~> "_inV") && notEmpty(n ~> "_outV")) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely {
                  (item ~> h("daddr")).asString + ":" + (item ~> h("dport")).asString + "_hasPort_" +
                  (item ~> h("dport")).asString
                },
                "_outV" -> Safely {
                  (item ~> h("daddr")).asString + ":" + (item ~> h("dport")).asString
                },
                "_inV" -> Safely{(item ~> h("dport")).asString},
                "_type" -> "edge",
                "_label" -> "hasPort",
                "source" -> "Argus",
                "outVType" -> "address",
                "inVType" -> "port"
              )
              if ((item ~> h("daddr")).nodeNonEmpty && (item ~> h("dport")).nodeNonEmpty &&
                  notEmpty(n ~> "_inV") && notEmpty(n ~> "_outV")) n
              else None
            }
          )
      }).autoFlatten
    )
  }
}
