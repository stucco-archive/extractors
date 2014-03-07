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

  def extract(node: ValueNode): ValueNode = ^(
    "vertices" -> (node ~> "ArgusDataStream" ~> "ArgusFlowRecord" %%-> { item =>
      *(
        {
          val n = ^(
            "_id" -> Safely {
                  (item ~> "@SrcAddr").asString + ":" + (item ~> "@SrcPort").asNumber + "::" +
                    (item ~> "@DstAddr").asString + ":" + (item ~> "@DstPort").asNumber
                },
            "_type" -> "vertex",
            "vertexType" -> "flow",
            "source" -> "Argus",
            
            "keyStrokeNStroke" -> item ~> "@KeyStrokeNStroke", //SSH Keystroke Detection stuff - unused here for now.
            "proto" -> item ~> "@Proto",
            "appBytes" -> item ~> "@AppBytes",        
            "state" -> item ~> "@State",
            "startTime" -> item ~> "@StartTime",
            "appByteRatio" -> item ~> "@AppByteRatio",
            "dir" -> item ~> "@Dir",
            "flags" -> item ~> "@Flags",
            "duration" -> item ~> "@Duration",
            "dstPkts" -> item ~> "@DstPkts",
            "srcPkts" -> item ~> "@SrcPkts"
          )
          if (notEmpty(item ~> "@SrcAddr") && notEmpty(item ~> "@SrcPort") &&
              notEmpty(item ~> "@DstAddr") && notEmpty(item ~> "@DstPort") &&
              notEmpty(n ~> "_id")) n
          else None
        },
        {
          val n = ^(
            "_id" -> Safely {
                  (item ~> "@SrcAddr").asString + ":" + (item ~> "@SrcPort").asNumber.toString
                },
            "_type" -> "vertex",
            "vertexType" -> "address",
            "source" -> "Argus"
          )
          if (notEmpty(item ~> "@SrcAddr") && notEmpty(item ~> "@SrcPort") &&
              notEmpty(n ~> "_id")) n
          else None
        },
        {
          val n = ^(
            "_id" -> Safely {
                  (item ~> "@DstAddr").asString + ":" + (item ~> "@DstPort").asNumber.toString
                },
            "_type" -> "vertex",
            "vertexType" -> "address",
            "source" -> "Argus"
          )
          if (notEmpty(item ~> "@DstAddr") && notEmpty(item ~> "@DstPort") &&
              notEmpty(n ~> "_id")) n
          else None
        },
        {
          val n = ^(
            "_id" -> item ~> "@SrcAddr",
            "_type" -> "vertex",
            "vertexType" -> "IP",
            "source" -> "Argus"
          )
          if (notEmpty(item ~> "@SrcAddr") &&
              notEmpty(n ~> "_id")) n
          else None
        },
        {
          val n = ^(
            "_id" -> item ~> "@DstAddr",
            "_type" -> "vertex",
            "vertexType" -> "IP",
            "source" -> "Argus"
          )
          if (notEmpty(item ~> "@DstAddr") &&
              notEmpty(n ~> "_id")) n
          else None
        },
        {
          val n = ^(
            "_id" -> Safely{(item ~> "@SrcPort").asNumber.toString},
            "_type" -> "vertex",
            "vertexType" -> "port",
            "source" -> "Argus"
          )
          if (notEmpty(item ~> "@SrcPort") &&
              notEmpty(n ~> "_id")) n
          else None
        },
        {
          val n = ^(
            "_id" -> Safely{(item ~> "@DstPort").asNumber.toString},
            "_type" -> "vertex",
            "vertexType" -> "port",
            "source" -> "Argus"
          )
          if (notEmpty(item ~> "@DstPort") &&
              notEmpty(n ~> "_id")) n
          else None
        }
      )
    }).autoFlatten,

    "edges" -> (node ~> "ArgusDataStream" ~> "ArgusFlowRecord" %%-> { item =>

      *(
        {
          val n = ^(
            "_id" -> Safely {
              (item ~> "@SrcAddr").asString + ":" + (item ~> "@SrcPort").asNumber + "::" +
              (item ~> "@DstAddr").asString + ":" + (item ~> "@DstPort").asNumber + "_srcAddress_" +
              (item ~> "@SrcAddr").asString + ":" + (item ~> "@SrcPort").asNumber
            },
            "_outV" -> Safely {
              (item ~> "@SrcAddr").asString + ":" + (item ~> "@SrcPort").asNumber + "::" +
              (item ~> "@DstAddr").asString + ":" + (item ~> "@DstPort").asNumber
            },
            "_inV" -> Safely {
              (item ~> "@SrcAddr").asString + ":" + (item ~> "@SrcPort").asNumber
            },
            "_type" -> "edge",
            "_label" -> "srcAddress",
            "source" -> "Argus",
            "outVType" -> "flow",
            "inVType" -> "address"
          )
          if (notEmpty(item ~> "@SrcAddr") && notEmpty(item ~> "@SrcPort") &&
              notEmpty(item ~> "@DstAddr") && notEmpty(item ~> "@DstPort") &&
              notEmpty(n ~> "_inV") && notEmpty(n ~> "_outV")) n
          else None
        },
        {
          val n = ^(
            "_id" -> Safely {
              (item ~> "@SrcAddr").asString + ":" + (item ~> "@SrcPort").asNumber + "::" +
              (item ~> "@DstAddr").asString + ":" + (item ~> "@DstPort").asNumber + "_dstAddress_" +
              (item ~> "@DstAddr").asString + ":" + (item ~> "@DstPort").asNumber
            },
            "_outV" -> Safely {
              (item ~> "@SrcAddr").asString + ":" + (item ~> "@SrcPort").asNumber + "::" +
              (item ~> "@DstAddr").asString + ":" + (item ~> "@DstPort").asNumber
            },
            "_inV" -> Safely {
              (item ~> "@DstAddr").asString + ":" + (item ~> "@DstPort").asNumber
            },
            "_type" -> "edge",
            "_label" -> "dstAddress",
            "source" -> "Argus",
            "outVType" -> "flow",
            "inVType" -> "address"
          )
          if (notEmpty(item ~> "@SrcAddr") && notEmpty(item ~> "@SrcPort") &&
              notEmpty(item ~> "@DstAddr") && notEmpty(item ~> "@DstPort") &&
              notEmpty(n ~> "_inV") && notEmpty(n ~> "_outV")) n
          else None
        },
        {
          val n = ^(
            "_id" -> Safely {
              (item ~> "@SrcAddr").asString + ":" + (item ~> "@SrcPort").asNumber + "_hasIP_" +
              (item ~> "@SrcAddr").asString
            },
            "_outV" -> Safely {
              (item ~> "@SrcAddr").asString + ":" + (item ~> "@SrcPort").asNumber
            },
            "_inV" -> item ~> "@SrcAddr",
            "_type" -> "edge",
            "_label" -> "hasIP",
            "source" -> "Argus",
            "outVType" -> "address",
            "inVType" -> "IP"
          )
          if (notEmpty(item ~> "@SrcAddr") && notEmpty(item ~> "@SrcPort") &&
              notEmpty(n ~> "_inV") && notEmpty(n ~> "_outV")) n
          else None
        },
        {
          val n = ^(
            "_id" -> Safely {
              (item ~> "@DstAddr").asString + ":" + (item ~> "@DstPort").asNumber + "_hasIP_" +
              (item ~> "@DstAddr").asString
            },
            "_outV" -> Safely {
              (item ~> "@DstAddr").asString + ":" + (item ~> "@DstPort").asNumber
            },
            "_inV" -> item ~> "@DstAddr",
            "_type" -> "edge",
            "_label" -> "hasIP",
            "source" -> "Argus",
            "outVType" -> "address",
            "inVType" -> "IP"
          )
          if (notEmpty(item ~> "@DstAddr") && notEmpty(item ~> "@DstPort") &&
              notEmpty(n ~> "_inV") && notEmpty(n ~> "_outV")) n
          else None
        },
        {
          val n = ^(
            "_id" -> Safely {
              (item ~> "@SrcAddr").asString + ":" + (item ~> "@SrcPort").asNumber + "_hasPort_" +
              (item ~> "@SrcPort").asNumber
            },
            "_outV" -> Safely {
              (item ~> "@SrcAddr").asString + ":" + (item ~> "@SrcPort").asNumber
            },
            "_inV" -> Safely{(item ~> "@SrcPort").asNumber.toString},
            "_type" -> "edge",
            "_label" -> "hasPort",
            "source" -> "Argus",
            "outVType" -> "address",
            "inVType" -> "port"
          )
          if (notEmpty(item ~> "@SrcAddr") && notEmpty(item ~> "@SrcPort") &&
              notEmpty(n ~> "_inV") && notEmpty(n ~> "_outV")) n
          else None
        },
        {
          val n = ^(
            "_id" -> Safely {
              (item ~> "@DstAddr").asString + ":" + (item ~> "@DstPort").asNumber + "_hasPort_" +
              (item ~> "@DstPort").asNumber
            },
            "_outV" -> Safely {
              (item ~> "@DstAddr").asString + ":" + (item ~> "@DstPort").asNumber
            },
            "_inV" -> Safely{(item ~> "@DstPort").asNumber.toString},
            "_type" -> "edge",
            "_label" -> "hasPort",
            "source" -> "Argus",
            "outVType" -> "address",
            "inVType" -> "port"
          )
          if (notEmpty(item ~> "@DstAddr") && notEmpty(item ~> "@DstPort") &&
              notEmpty(n ~> "_inV") && notEmpty(n ~> "_outV")) n
          else None
        }
      )
    }).autoFlatten
  )
}
