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
                      (item ~> h("saddr")).asString + ":" + (item ~>h("sport")).asNumber + "::" +
                        (item ~> h("daddr")).asString + ":" + (item ~> h("dport")).asNumber
                    },
                "_type" -> "vertex",
                "vertexType" -> "flow",
                "source" -> "Argus",
                
                "proto" -> item ~> h("proto"),
                "appBytes" -> item ~> h("bytes"),        
  //              "state" -> item ~> "@State",
                "startTime" -> item ~> h("stime"),
  //              "appByteRatio" -> item ~> "@AppByteRatio",
                "dir" -> item ~> h("dir"),
  //              "flags" -> item ~> "@Flags",
  //              "duration" -> item ~> "@Duration",
  //              "dstPkts" -> item ~> "@DstPkts",
  //              "srcPkts" -> item ~> "@SrcPkts"
              )
              if (notEmpty(item ~> h("saddr")) && notEmpty(item ~> h("sport")) &&
                  notEmpty(item ~> h("daddr")) && notEmpty(item ~> h("dport")) &&
                  notEmpty(n ~> "_id")) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely {
                      (item ~> h("saddr")).asString + ":" + (item ~> h("sport")).asNumber.toString
                    },
                "_type" -> "vertex",
                "vertexType" -> "address",
                "source" -> "Argus"
              )
              if (notEmpty(item ~> h("saddr")) && notEmpty(item ~> h("sport")) &&
                  notEmpty(n ~> "_id")) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely {
                      (item ~> h("daddr")).asString + ":" + (item ~> h("dport")).asNumber.toString
                    },
                "_type" -> "vertex",
                "vertexType" -> "address",
                "source" -> "Argus"
              )
              if (notEmpty(item ~> h("daddr")) && notEmpty(item ~> h("dport")) &&
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
              if (notEmpty(item ~> h("saddr")) &&
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
              if (notEmpty(item ~> h("daddr")) &&
                  notEmpty(n ~> "_id")) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely{(item ~> h("sport")).asNumber.toString},
                "_type" -> "vertex",
                "vertexType" -> "port",
                "source" -> "Argus"
              )
              if (notEmpty(item ~> h("sport")) &&
                  notEmpty(n ~> "_id")) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely{(item ~> h("dport")).asNumber.toString},
                "_type" -> "vertex",
                "vertexType" -> "port",
                "source" -> "Argus"
              )
              if (notEmpty(item ~> h("dport")) &&
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
                  (item ~> h("saddr")).asString + ":" + (item ~> h("sport")).asNumber + "::" +
                  (item ~> h("daddr")).asString + ":" + (item ~> h("dport")).asNumber + "_srcAddress_" +
                  (item ~> h("saddr")).asString + ":" + (item ~> h("sport")).asNumber
                },
                "_outV" -> Safely {
                  (item ~> h("saddr")).asString + ":" + (item ~> h("sport")).asNumber + "::" +
                  (item ~> h("daddr")).asString + ":" + (item ~> h("dport")).asNumber
                },
                "_inV" -> Safely {
                  (item ~> h("saddr")).asString + ":" + (item ~> h("sport")).asNumber
                },
                "_type" -> "edge",
                "_label" -> "srcAddress",
                "source" -> "Argus",
                "outVType" -> "flow",
                "inVType" -> "address"
              )
              if (notEmpty(item ~> h("saddr")) && notEmpty(item ~> h("sport")) &&
                  notEmpty(item ~> h("daddr")) && notEmpty(item ~> h("dport")) &&
                  notEmpty(n ~> "_inV") && notEmpty(n ~> "_outV")) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely {
                  (item ~> h("saddr")).asString + ":" + (item ~> h("sport")).asNumber + "::" +
                  (item ~> h("daddr")).asString + ":" + (item ~> h("dport")).asNumber + "_dstAddress_" +
                  (item ~> h("daddr")).asString + ":" + (item ~> h("dport")).asNumber
                },
                "_outV" -> Safely {
                  (item ~> h("saddr")).asString + ":" + (item ~> h("sport")).asNumber + "::" +
                  (item ~> h("daddr")).asString + ":" + (item ~> h("dport")).asNumber
                },
                "_inV" -> Safely {
                  (item ~> h("daddr")).asString + ":" + (item ~> h("dport")).asNumber
                },
                "_type" -> "edge",
                "_label" -> "dstAddress",
                "source" -> "Argus",
                "outVType" -> "flow",
                "inVType" -> "address"
              )
              if (notEmpty(item ~> h("saddr")) && notEmpty(item ~> h("sport")) &&
                  notEmpty(item ~> h("daddr")) && notEmpty(item ~> h("dport")) &&
                  notEmpty(n ~> "_inV") && notEmpty(n ~> "_outV")) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely {
                  (item ~> h("saddr")).asString + ":" + (item ~> h("sport")).asNumber + "_hasIP_" +
                  (item ~> h("saddr")).asString
                },
                "_outV" -> Safely {
                  (item ~> h("saddr")).asString + ":" + (item ~> h("sport")).asNumber
                },
                "_inV" -> item ~> h("saddr"),
                "_type" -> "edge",
                "_label" -> "hasIP",
                "source" -> "Argus",
                "outVType" -> "address",
                "inVType" -> "IP"
              )
              if (notEmpty(item ~> h("saddr")) && notEmpty(item ~> h("sport")) &&
                  notEmpty(n ~> "_inV") && notEmpty(n ~> "_outV")) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely {
                  (item ~> h("daddr")).asString + ":" + (item ~> h("dport")).asNumber + "_hasIP_" +
                  (item ~> h("daddr")).asString
                },
                "_outV" -> Safely {
                  (item ~> h("daddr")).asString + ":" + (item ~> h("dport")).asNumber
                },
                "_inV" -> item ~> h("daddr"),
                "_type" -> "edge",
                "_label" -> "hasIP",
                "source" -> "Argus",
                "outVType" -> "address",
                "inVType" -> "IP"
              )
              if (notEmpty(item ~> h("daddr")) && notEmpty(item ~> h("dport")) &&
                  notEmpty(n ~> "_inV") && notEmpty(n ~> "_outV")) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely {
                  (item ~> h("saddr")).asString + ":" + (item ~> h("sport")).asNumber + "_hasPort_" +
                  (item ~> h("sport")).asNumber
                },
                "_outV" -> Safely {
                  (item ~> h("saddr")).asString + ":" + (item ~> h("sport")).asNumber
                },
                "_inV" -> Safely{(item ~> h("sport")).asNumber.toString},
                "_type" -> "edge",
                "_label" -> "hasPort",
                "source" -> "Argus",
                "outVType" -> "address",
                "inVType" -> "port"
              )
              if (notEmpty(item ~> h("saddr")) && notEmpty(item ~> h("sport")) &&
                  notEmpty(n ~> "_inV") && notEmpty(n ~> "_outV")) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely {
                  (item ~> h("daddr")).asString + ":" + (item ~> h("dport")).asNumber + "_hasPort_" +
                  (item ~> h("dport")).asNumber
                },
                "_outV" -> Safely {
                  (item ~> h("daddr")).asString + ":" + (item ~> h("dport")).asNumber
                },
                "_inV" -> Safely{(item ~> h("dport")).asNumber.toString},
                "_type" -> "edge",
                "_label" -> "hasPort",
                "source" -> "Argus",
                "outVType" -> "address",
                "inVType" -> "port"
              )
              if (notEmpty(item ~> h("daddr")) && notEmpty(item ~> h("dport")) &&
                  notEmpty(n ~> "_inV") && notEmpty(n ~> "_outV")) n
              else None
            }
          )
      }).autoFlatten
    )
  }
}
