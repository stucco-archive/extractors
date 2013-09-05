package gov.ornl.stucco.extractors

import morph.ast._
import morph.extractor.Extractor

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
            notEmpty(item ~> "@DstAddr") && notEmpty(item ~> "@DstPort")) n
          else None
        },
        {
          val n = ^(
            "_id" -> Safely {
                  (item ~> "@SrcAddr").asString + ":" + (item ~> "@SrcPort").asNumber
                },
            "_type" -> "vertex",
            "vertexType" -> "address",
            "source" -> "Argus"
          )
          if (notEmpty(item ~> "@SrcAddr") && notEmpty(item ~> "@SrcPort")) n
          else None
        },
        {
          val n = ^(
            "_id" -> Safely {
                  (item ~> "@DstAddr").asString + ":" + (item ~> "@DstPort").asNumber
                },
            "_type" -> "vertex",
            "vertexType" -> "address",
            "source" -> "Argus"
          )
          if (notEmpty(item ~> "@DstAddr") && notEmpty(item ~> "@DstPort")) n
          else None
        },
        {
          val n = ^(
            "_id" -> item ~> "@SrcAddr",
            "_type" -> "vertex",
            "vertexType" -> "IP",
            "source" -> "Argus"
          )
          if (notEmpty(item ~> "@SrcAddr")) n
          else None
        },
        {
          val n = ^(
            "_id" -> item ~> "@DstAddr",
            "_type" -> "vertex",
            "vertexType" -> "IP",
            "source" -> "Argus"
          )
          if (notEmpty(item ~> "@DstAddr")) n
          else None
        },
        {
          val n = ^(
            "_id" -> item ~> "@SrcPort",
            "_type" -> "vertex",
            "vertexType" -> "port",
            "source" -> "Argus"
          )
          if (notEmpty(item ~> "@SrcPort")) n
          else None
        },
        {
          val n = ^(
            "_id" -> item ~> "@DstPort",
            "_type" -> "vertex",
            "vertexType" -> "port",
            "source" -> "Argus"
          )
          if (notEmpty(item ~> "@DstPort")) n
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
            notEmpty(item ~> "@DstAddr") && notEmpty(item ~> "@DstPort")) n
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
            notEmpty(item ~> "@DstAddr") && notEmpty(item ~> "@DstPort")) n
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
          if (notEmpty(item ~> "@SrcAddr") && notEmpty(item ~> "@SrcPort")) n
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
          if (notEmpty(item ~> "@DstAddr") && notEmpty(item ~> "@DstPort")) n
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
            "_inV" -> item ~> "@SrcPort",
            "_type" -> "edge",
            "_label" -> "hasPort",
            "source" -> "Argus",
            "outVType" -> "address",
            "inVType" -> "port"
          )
          if (notEmpty(item ~> "@SrcAddr") && notEmpty(item ~> "@SrcPort")) n
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
            "_inV" -> item ~> "@DstPort",
            "_type" -> "edge",
            "_label" -> "hasPort",
            "source" -> "Argus",
            "outVType" -> "address",
            "inVType" -> "port"
          )
          if (notEmpty(item ~> "@DstAddr") && notEmpty(item ~> "@DstPort")) n
          else None
        }
      )
    }).autoFlatten
  )
}
