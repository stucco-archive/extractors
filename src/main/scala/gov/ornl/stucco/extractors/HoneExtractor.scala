import morph.ast._
import morph.extractor.Extractor

object HoneExtractor extends Extractor {

  def extract(node: ValueNode): ValueNode = extract(node, Map[String,String]("hostName" -> ""))

  //hostName will come from the metadata, is not included in the data itself
  def extract(node: ValueNode, metaData: Map[String,String]): ValueNode = {
    val hostName = metaData("hostName")
    //user,uid,process_pid,process_path,timestamp_epoch_ms,source_port,dest_port,ip_version,source_ip,dest_ip
    val headers = node.get(0)
    val h = headers.asList.zipWithIndex.map{ a => a }.toMap
    //print (h)
    //print (h.get("process_path"))
    ^(
      "vertices" -> (node mapPartial { 
      //this will ignore header row and will ignore last row if it is just an empty string.
      case item if (item ~> 0 != headers ~> 0) && (item ~> 1 != None) =>
        *(
          ^(
            "_id" -> item ~> h("process_path"),
            "_type" -> "vertex",
            "source" -> "Hone",
            "vertexType" -> "software",
            "processPath" -> item ~> h("process_path"),
            "processPid" -> item ~> h("process_pid")
          ),
          ^(
            "_id" -> item ~> hostName,
            "_type" -> "vertex",
            "source" -> "Hone",
            "vertexType" -> "host",
            "hostName" -> hostName //how to find relation to s/dip?
          ),
          ^(
            "_id" -> Safely{ (item ~> h("source_ip")).asString + ":" + (item ~> h("source_port")).asString },
            "_type" -> "vertex",
            "source" -> "Hone",
            "vertexType" -> "address"
          ),
          ^(
            "_id" -> Safely{ (item ~> h("dest_ip")).asString + ":" + (item ~> h("dest_port")).asString },
            "_type" -> "vertex",
            "source" -> "Hone",
            "vertexType" -> "address"
          ),
          ^(
            "_id" -> item ~> h("source_ip"),
            "_type" -> "vertex",
            "source" -> "Hone",
            "vertexType" -> "IP"
          ),
          ^(
            "_id" -> item ~> h("dest_ip"),
            "_type" -> "vertex",
            "source" -> "Hone",
            "vertexType" -> "IP"
          ),
          ^(
            "_id" -> item ~> h("source_port"),
            "_type" -> "vertex",
            "source" -> "Hone",
            "vertexType" -> "port"
          ),
          ^(
            "_id" -> item ~> h("dest_port"),
            "_type" -> "vertex",
            "source" -> "Hone",
            "vertexType" -> "port"
          ),
          ^(
            "_id" -> Safely{
              (item ~> h("source_ip")).asString + ":" + (item ~> h("source_port")).asString + "::" + 
              (item ~> h("dest_ip")).asString + ":" + (item ~> h("dest_port")).asString
            },
            "_type" -> "vertex",
            "source" -> "Hone",
            "vertexType" -> "flow",
            "startTime" -> item ~> h("timestamp_epoch_ms")
          ),
          ^(
            "_id" -> Safely{ hostName + ":" + (item ~> h("uid")).asString },
            "_type" -> "vertex",
            "source" -> "Hone",
            "vertexType" -> "account",
            "uid" -> item ~> h("uid"),
            "userName" -> item ~> h("user")
          )
        )
      }).autoFlatten,
      "edges" -> (node mapPartial { 
      //this will ignore header row and will ignore last row if it is just an empty string.
      case item if (item ~> 0 != headers ~> 0) && (item ~> 1 != None) =>
        *(
          ^(
            "_id" -> Safely{ hostName + "_runs_" + (item ~> h("process_path")).asString },
            "_type" -> "vertex",
            "source" -> "Hone",
            "edgeType" -> "runs",
            "outVType" -> "host",
            "inVType" -> "software"
          ),
          ^(
            "_id" -> Safely{ hostName + "_usesAddress_" + (item ~> h("process_path")).asString },
            "_type" -> "vertex",
            "source" -> "Hone",
            "edgeType" -> "usesAddress",
            "outVType" -> "host",
            "inVType" -> "address"
          ),
          ^(
            "_id" -> Safely{ 
              (item ~> h("source_ip")).asString + ":" + (item ~> h("source_port")).asString + 
              "_hasIP_" + (item ~> h("source_ip")).asString 
            },
            "_type" -> "vertex",
            "source" -> "Hone",
            "edgeType" -> "hasIP",
            "outVType" -> "address",
            "inVType" -> "IP"
          ),
          ^(
            "_id" -> Safely{ 
              (item ~> h("dest_ip")).asString + ":" + (item ~> h("dest_port")).asString + 
              "_hasIP_" + (item ~> h("dest_ip")).asString 
            },
            "_type" -> "vertex",
            "source" -> "Hone",
            "edgeType" -> "hasIP",
            "outVType" -> "address",
            "inVType" -> "IP"
          ),
          ^(
            "_id" -> Safely{ 
              (item ~> h("source_ip")).asString + ":" + (item ~> h("source_port")).asString + 
              "_hasPort_" + (item ~> h("source_port")).asString 
            },
            "_type" -> "vertex",
            "source" -> "Hone",
            "edgeType" -> "hasPort",
            "outVType" -> "address",
            "inVType" -> "port"
          ),
          ^(
            "_id" -> Safely{ 
              (item ~> h("dest_ip")).asString + ":" + (item ~> h("dest_port")).asString + 
              "_hasPort_" + (item ~> h("dest_port")).asString 
            },
            "_type" -> "vertex",
            "source" -> "Hone",
            "edgeType" -> "hasPort",
            "outVType" -> "address",
            "inVType" -> "port"
          ),
          ^(
            "_id" -> Safely{
              (item ~> h("source_ip")).asString + ":" + (item ~> h("source_port")).asString + "::" + 
              (item ~> h("dest_ip")).asString + ":" + (item ~> h("dest_port")).asString + "_dstAddress_" + 
              (item ~> h("dest_ip")).asString + ":" + (item ~> h("dest_port")).asString 
            },
            "_type" -> "vertex",
            "source" -> "Hone",
            "edgeType" -> "dstAddress",
            "outVType" -> "flow",
            "inVType" -> "address"
          ),
          ^(
            "_id" -> Safely{
              (item ~> h("source_ip")).asString + ":" + (item ~> h("source_port")).asString + "::" + 
              (item ~> h("dest_ip")).asString + ":" + (item ~> h("dest_port")).asString + "_srcAddress_" + 
              (item ~> h("source_ip")).asString + ":" + (item ~> h("source_port")).asString 
            },
            "_type" -> "vertex",
            "source" -> "Hone",
            "edgeType" -> "srcAddress",
            "outVType" -> "flow",
            "inVType" -> "address"
          ),
          ^(
            "_id" -> Safely{
              (item ~> h("process_path")).asString + "_hasFlow_" + 
              (item ~> h("source_ip")).asString + ":" + (item ~> h("source_port")).asString + "::" + 
              (item ~> h("dest_ip")).asString + ":" + (item ~> h("dest_port")).asString
            },
            "_type" -> "vertex",
            "source" -> "Hone",
            "edgeType" -> "hasFlow",
            "outVType" -> "software",
            "inVType" -> "flow"
          ),
          ^(
            "_id" -> Safely{ 
              (item ~> h("process_path")).asString + "_runsAs_" + 
              hostName + ":" + (item ~> h("uid")).asString 
            },
            "_type" -> "vertex",
            "source" -> "Hone",
            "edgeType" -> "runsAs",
            "outVType" -> "software",
            "inVType" -> "account"
          )
        )
      }).autoFlatten
    )
  }

}


