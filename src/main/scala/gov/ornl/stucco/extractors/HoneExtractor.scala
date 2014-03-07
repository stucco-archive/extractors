package gov.ornl.stucco.extractors

import gov.ornl.stucco.morph.ast._
import gov.ornl.stucco.morph.extractor.Extractor

object HoneExtractor extends Extractor {

  // to make testing easier
  val O = ObjectNode
  val A = ArrayNode
  val S = StringNode
  val N = NumberNode

  //TODO: it would be useful to also check non-strings here.
  def notEmpty(node: Option[ValueNode]): Boolean = {
    node != None && node != Some(S(""))
  }

  def extract(node: ValueNode): ValueNode = extract(node, Map[String, String]("hostName" -> ""))

  //hostName will come from the metadata, is not included in the data itself
  def extract(node: ValueNode, metaData: Map[String, String]): ValueNode = {
    val hostName = metaData("hostName")
    //user,uid,proc_pid,proc_ppid,path,argv,conn_id,timestamp_epoch_ms,source_port,dest_port,ip_version,source_ip,dest_ip,byte_cnt,packet_cnt
    //TODO:conn_id?
    val headers = node.get(0)
    val h = headers.asList.zipWithIndex.map { a => a }.toMap
    ^(
      "vertices" -> (node mapPartial {
        //this will ignore header row and will ignore last row if it is just an empty string.
        case item if (item ~> 0 != headers ~> 0) && (item ~> 1 != None) =>
          *(
            {
              val n = ^(
                "_id" -> hostName,
                "_type" -> "vertex",
                "source" -> "Hone",
                "vertexType" -> "host"
              )
              if (notEmpty(n ~> "_id")) n
              else None
            },
            {
              val n = ^(
                "_id" -> item ~> h("path"),
                "_type" -> "vertex",
                "source" -> "Hone",
                "vertexType" -> "software",
                "processPath" -> item ~> h("path"),
                "processPid" -> item ~> h("proc_pid"),
                "processPpid" -> item ~> h("proc_ppid"),
                "processArgs" -> item ~> h("argv")
              )
              if (notEmpty(n ~> "_id")) n
              else None
            },
            {
              val n = ^(
                "_id" -> item ~> hostName,
                "_type" -> "vertex",
                "source" -> "Hone",
                "vertexType" -> "host",
                "hostName" -> hostName
              )
              if (notEmpty(n ~> "_id")) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely { (item ~> h("source_ip")).asString + ":" + (item ~> h("source_port")).asString },
                "_type" -> "vertex",
                "source" -> "Hone",
                "vertexType" -> "address"
              )
              if (notEmpty(item ~> h("source_ip")) && notEmpty(item ~> h("source_port"))) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely { (item ~> h("dest_ip")).asString + ":" + (item ~> h("dest_port")).asString },
                "_type" -> "vertex",
                "source" -> "Hone",
                "vertexType" -> "address"
              )
              if (notEmpty(item ~> h("dest_ip")) && notEmpty(item ~> h("dest_port"))) n
              else None
            },
            {
              val n = ^(
                "_id" -> item ~> h("source_ip"),
                "_type" -> "vertex",
                "source" -> "Hone",
                "vertexType" -> "IP"
              )
              if (notEmpty(n ~> "_id")) n
              else None
            },
            {
              val n = ^(
                "_id" -> item ~> h("dest_ip"),
                "_type" -> "vertex",
                "source" -> "Hone",
                "vertexType" -> "IP"
              )
              if (notEmpty(n ~> "_id")) n
              else None
            },
            {
              val n = ^(
                "_id" -> item ~> h("source_port"),
                "_type" -> "vertex",
                "source" -> "Hone",
                "vertexType" -> "port"
              )
              if (notEmpty(n ~> "_id")) n
              else None
            },
            {
              val n = ^(
                "_id" -> item ~> h("dest_port"),
                "_type" -> "vertex",
                "source" -> "Hone",
                "vertexType" -> "port"
              )
              if (notEmpty(n ~> "_id")) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely {
                  (item ~> h("source_ip")).asString + ":" + (item ~> h("source_port")).asString + "::" +
                    (item ~> h("dest_ip")).asString + ":" + (item ~> h("dest_port")).asString
                },
                "_type" -> "vertex",
                "source" -> "Hone",
                "vertexType" -> "flow",
                "startTime" -> item ~> h("timestamp_epoch_ms"),
                "totalBytes" -> item ~> h("byte_cnt"),
                "totalPkts" -> item ~> h("packet_cnt")
              )
              if (notEmpty(item ~> h("source_ip")) && notEmpty(item ~> h("source_port")) &&
                notEmpty(item ~> h("dest_ip")) && notEmpty(item ~> h("dest_port"))) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely { hostName + ":" + (item ~> h("uid")).asString },
                "_type" -> "vertex",
                "source" -> "Hone",
                "vertexType" -> "account",
                "uid" -> item ~> h("uid"),
                "userName" -> item ~> h("user")
              )
              if (hostName != "" && notEmpty(item ~> h("uid"))) n
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
                "_id" -> Safely { hostName + "_runs_" + (item ~> h("path")).asString },
                "_outV" -> hostName,
                "_inV" -> item ~> h("path"),
                "_type" -> "edge",
                "_label" -> "runs",
                "source" -> "Hone",
                "outVType" -> "host",
                "inVType" -> "software"
              )
              if (hostName != "" && notEmpty(item ~> h("path"))) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely {
                  hostName + "_usesAddress_" +
                    (item ~> h("source_ip")).asString + ":" + (item ~> h("source_port")).asString
                },
                "_outV" -> hostName,
                "_inV" -> Safely { (item ~> h("source_ip")).asString + ":" + (item ~> h("source_port")).asString },
                "_type" -> "edge",
                "_label" -> "usesAddress",
                "source" -> "Hone",
                "outVType" -> "host",
                "inVType" -> "address"
              )
              if (hostName != "" && notEmpty(item ~> h("source_ip")) && notEmpty(item ~> h("source_port"))) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely {
                  (item ~> h("source_ip")).asString + ":" + (item ~> h("source_port")).asString +
                    "_hasIP_" + (item ~> h("source_ip")).asString
                },
                "_outV" -> Safely { (item ~> h("source_ip")).asString + ":" + (item ~> h("source_port")).asString },
                "_inV" -> item ~> h("source_ip"),
                "_type" -> "edge",
                "_label" -> "hasIP",
                "source" -> "Hone",
                "outVType" -> "address",
                "inVType" -> "IP"
              )
              if (notEmpty(item ~> h("source_ip")) && notEmpty(item ~> h("source_port"))) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely {
                  (item ~> h("dest_ip")).asString + ":" + (item ~> h("dest_port")).asString +
                    "_hasIP_" + (item ~> h("dest_ip")).asString
                },
                "_outV" -> Safely { (item ~> h("dest_ip")).asString + ":" + (item ~> h("dest_port")).asString },
                "_inV" -> item ~> h("dest_ip"),
                "_type" -> "edge",
                "_label" -> "hasIP",
                "source" -> "Hone",
                "outVType" -> "address",
                "inVType" -> "IP"
              )
              if (notEmpty(item ~> h("dest_ip")) && notEmpty(item ~> h("dest_port"))) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely {
                  (item ~> h("source_ip")).asString + ":" + (item ~> h("source_port")).asString +
                    "_hasPort_" + (item ~> h("source_port")).asString
                },
                "_outV" -> Safely { (item ~> h("source_ip")).asString + ":" + (item ~> h("source_port")).asString },
                "_inV" -> item ~> h("source_port"),
                "_type" -> "edge",
                "_label" -> "hasPort",
                "source" -> "Hone",
                "outVType" -> "address",
                "inVType" -> "port"
              )
              if (notEmpty(item ~> h("source_ip")) && notEmpty(item ~> h("source_port"))) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely {
                  (item ~> h("dest_ip")).asString + ":" + (item ~> h("dest_port")).asString +
                    "_hasPort_" + (item ~> h("dest_port")).asString
                },
                "_outV" -> Safely { (item ~> h("dest_ip")).asString + ":" + (item ~> h("dest_port")).asString },
                "_inV" -> item ~> h("dest_port"),
                "_type" -> "edge",
                "_label" -> "hasPort",
                "source" -> "Hone",
                "outVType" -> "address",
                "inVType" -> "port"
              )
              if (notEmpty(item ~> h("dest_ip")) && notEmpty(item ~> h("dest_port"))) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely {
                  (item ~> h("source_ip")).asString + ":" + (item ~> h("source_port")).asString + "::" +
                    (item ~> h("dest_ip")).asString + ":" + (item ~> h("dest_port")).asString + "_dstAddress_" +
                    (item ~> h("dest_ip")).asString + ":" + (item ~> h("dest_port")).asString
                },
                "_outV" -> Safely {
                  (item ~> h("source_ip")).asString + ":" + (item ~> h("source_port")).asString + "::" +
                    (item ~> h("dest_ip")).asString + ":" + (item ~> h("dest_port")).asString
                },
                "_inV" -> Safely { (item ~> h("dest_ip")).asString + ":" + (item ~> h("dest_port")).asString },
                "_type" -> "edge",
                "_label" -> "dstAddress",
                "source" -> "Hone",
                "outVType" -> "flow",
                "inVType" -> "address"
              )
              if (notEmpty(item ~> h("source_ip")) && notEmpty(item ~> h("source_port")) &&
                notEmpty(item ~> h("dest_ip")) && notEmpty(item ~> h("dest_port"))) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely {
                  (item ~> h("source_ip")).asString + ":" + (item ~> h("source_port")).asString + "::" +
                    (item ~> h("dest_ip")).asString + ":" + (item ~> h("dest_port")).asString + "_srcAddress_" +
                    (item ~> h("source_ip")).asString + ":" + (item ~> h("source_port")).asString
                },
                "_outV" -> Safely {
                  (item ~> h("source_ip")).asString + ":" + (item ~> h("source_port")).asString + "::" +
                    (item ~> h("dest_ip")).asString + ":" + (item ~> h("dest_port")).asString
                },
                "_inV" -> Safely { (item ~> h("source_ip")).asString + ":" + (item ~> h("source_port")).asString },
                "_type" -> "edge",
                "_label" -> "srcAddress",
                "source" -> "Hone",
                "outVType" -> "flow",
                "inVType" -> "address"
              )
              if (notEmpty(item ~> h("source_ip")) && notEmpty(item ~> h("source_port")) &&
                notEmpty(item ~> h("dest_ip")) && notEmpty(item ~> h("dest_port"))) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely {
                  (item ~> h("path")).asString + "_hasFlow_" +
                    (item ~> h("source_ip")).asString + ":" + (item ~> h("source_port")).asString + "::" +
                    (item ~> h("dest_ip")).asString + ":" + (item ~> h("dest_port")).asString
                },
                "_outV" -> item ~> h("path"),
                "_inV" -> Safely {
                  (item ~> h("source_ip")).asString + ":" + (item ~> h("source_port")).asString + "::" +
                    (item ~> h("dest_ip")).asString + ":" + (item ~> h("dest_port")).asString
                },
                "_type" -> "edge",
                "_label" -> "hasFlow",
                "source" -> "Hone",
                "outVType" -> "software",
                "inVType" -> "flow"
              )
              if (notEmpty(item ~> h("source_ip")) && notEmpty(item ~> h("source_port")) &&
                notEmpty(item ~> h("dest_ip")) && notEmpty(item ~> h("dest_port")) &&
                notEmpty(item ~> h("path"))) n
              else None
            },
            {
              val n = ^(
                "_id" -> Safely {
                  (item ~> h("path")).asString + "_runsAs_" +
                    hostName + ":" + (item ~> h("uid")).asString
                },
                "_outV" -> item ~> h("path"),
                "_inV" -> Safely {
                  hostName + ":" + (item ~> h("uid")).asString
                },
                "_type" -> "edge",
                "_label" -> "runsAs",
                "source" -> "Hone",
                "outVType" -> "software",
                "inVType" -> "account"
              )
              if ((notEmpty(item ~> h("path")) && notEmpty(item ~> h("uid")) && hostName != "")) n
              else None
            }
          )
      }).autoFlatten
    )
  }

}

