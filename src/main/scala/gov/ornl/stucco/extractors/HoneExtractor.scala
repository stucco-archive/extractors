import morph.ast._
import morph.extractor.Extractor

object HoneExtractor extends Extractor {

  // to make testing easier
  val O = ObjectNode
  val A = ArrayNode
  val S = StringNode
  val N = NumberNode

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
          {
            val n = ^(
              "_id" -> item ~> h("process_path"),
              "_type" -> "vertex",
              "source" -> "Hone",
              "vertexType" -> "software",
              "processPath" -> item ~> h("process_path"),
              "processPid" -> item ~> h("process_pid")
            )
            if( (n ~> "_id") != None && (n ~> "_id") != Some(S("")) ) n
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
            if( (n ~> "_id") != None && (n ~> "_id") != Some(S("")) ) n
            else None
          },
          {
            val n = ^(
              "_id" -> Safely{ (item ~> h("source_ip")).asString + ":" + (item ~> h("source_port")).asString },
              "_type" -> "vertex",
              "source" -> "Hone",
              "vertexType" -> "address"
            )
            if( (item ~> h("source_ip")) != None && (item ~> h("source_ip")) != Some(S("")) && 
              (item ~> h("source_port")) != None && (item ~> h("source_port")) != Some(S("")) ) n
            else None
          },
          {
            val n = ^(
              "_id" -> Safely{ (item ~> h("dest_ip")).asString + ":" + (item ~> h("dest_port")).asString },
              "_type" -> "vertex",
              "source" -> "Hone",
              "vertexType" -> "address"
            )
            if( (item ~> h("dest_ip")) != None && (item ~> h("dest_ip")) != Some(S("")) && 
              (item ~> h("dest_port")) != None && (item ~> h("dest_port")) != Some(S("")) ) n
            else None
          },
          {
            val n = ^(
              "_id" -> item ~> h("source_ip"),
              "_type" -> "vertex",
              "source" -> "Hone",
              "vertexType" -> "IP"
            )
            if( (n ~> "_id") != None && (n ~> "_id") != Some(S("")) ) n
            else None
          },
          {
            val n = ^(
              "_id" -> item ~> h("dest_ip"),
              "_type" -> "vertex",
              "source" -> "Hone",
              "vertexType" -> "IP"
            )
            if( (n ~> "_id") != None && (n ~> "_id") != Some(S("")) ) n
            else None
          },
          {
            val n = ^(
              "_id" -> item ~> h("source_port"),
              "_type" -> "vertex",
              "source" -> "Hone",
              "vertexType" -> "port"
            )
            if( (n ~> "_id") != None && (n ~> "_id") != Some(S("")) ) n
            else None
          },
          {
            val n = ^(
              "_id" -> item ~> h("dest_port"),
              "_type" -> "vertex",
              "source" -> "Hone",
              "vertexType" -> "port"
            )
            if( (n ~> "_id") != None && (n ~> "_id") != Some(S("")) ) n
            else None
          },
          {
            val n = ^(
              "_id" -> Safely{
                (item ~> h("source_ip")).asString + ":" + (item ~> h("source_port")).asString + "::" + 
                (item ~> h("dest_ip")).asString + ":" + (item ~> h("dest_port")).asString
              },
              "_type" -> "vertex",
              "source" -> "Hone",
              "vertexType" -> "flow",
              "startTime" -> item ~> h("timestamp_epoch_ms")
            )
            if( (item ~> h("source_ip")) != None && (item ~> h("source_ip")) != Some(S("")) && 
              (item ~> h("source_port")) != None && (item ~> h("source_port")) != Some(S("")) && 
              (item ~> h("dest_ip")) != None && (item ~> h("dest_ip")) != Some(S("")) && 
              (item ~> h("dest_port")) != None && (item ~> h("dest_port")) != Some(S("")) ) n
            else None
          },
          {
            val n = ^(
              "_id" -> Safely{ hostName + ":" + (item ~> h("uid")).asString },
              "_type" -> "vertex",
              "source" -> "Hone",
              "vertexType" -> "account",
              "uid" -> item ~> h("uid"),
              "userName" -> item ~> h("user")
            )
            if( hostName != "" && (item ~> h("uid")) != None && (item ~> h("uid")) != Some(S("")) ) n
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
              "_id" -> Safely{ hostName + "_runs_" + (item ~> h("process_path")).asString },
              "_outV" -> hostName,
              "_inV" -> item ~> h("process_path"),
              "_type" -> "edge",
              "_label" -> "runs",
              "source" -> "Hone",
              "outVType" -> "host",
              "inVType" -> "software"
            )
            if(hostName != "" && (item ~> h("process_path")) != None && (item ~> h("process_path")) != Some(S("")) ) n
            else None
          },
          {
            val n = ^(
              "_id" -> Safely{ 
                hostName + "_usesAddress_" + 
                (item ~> h("source_ip")).asString + ":" + (item ~> h("source_port")).asString 
              },
              "_outV" -> hostName,
              "_inV" -> Safely{ (item ~> h("source_ip")).asString + ":" + (item ~> h("source_port")).asString },
              "_type" -> "edge",
              "_label" -> "usesAddress",
              "source" -> "Hone",
              "outVType" -> "host",
              "inVType" -> "address"
            )
            if(hostName != "" && (item ~> h("source_ip")) != None && (item ~> h("source_ip")) != Some(S("")) && 
              (item ~> h("source_port")) != None && (item ~> h("source_port")) != Some(S("")) ) n
            else None
          },
          {
            val n = ^(
              "_id" -> Safely{ 
                (item ~> h("source_ip")).asString + ":" + (item ~> h("source_port")).asString + 
                "_hasIP_" + (item ~> h("source_ip")).asString 
              },
              "_outV" -> Safely{ (item ~> h("source_ip")).asString + ":" + (item ~> h("source_port")).asString },
              "_inV" -> item ~> h("source_ip"),
              "_type" -> "edge",
              "_label" -> "hasIP",
              "source" -> "Hone",
              "outVType" -> "address",
              "inVType" -> "IP"
            )
            if((item ~> h("source_ip")) != None && (item ~> h("source_ip")) != Some(S("")) && 
              (item ~> h("source_port")) != None && (item ~> h("source_port")) != Some(S("")) ) n
            else None
          },
          {
            val n = ^(
              "_id" -> Safely{ 
                (item ~> h("dest_ip")).asString + ":" + (item ~> h("dest_port")).asString + 
                "_hasIP_" + (item ~> h("dest_ip")).asString 
              },
              "_outV" -> Safely{ (item ~> h("dest_ip")).asString + ":" + (item ~> h("dest_port")).asString },
              "_inV" -> item ~> h("dest_ip"),
              "_type" -> "edge",
              "_label" -> "hasIP",
              "source" -> "Hone",
              "outVType" -> "address",
              "inVType" -> "IP"
            )
            if((item ~> h("dest_ip")) != None && (item ~> h("dest_ip")) != Some(S("")) && 
              (item ~> h("dest_port")) != None && (item ~> h("dest_port")) != Some(S("")) ) n
            else None
          },
          {
            val n = ^(
              "_id" -> Safely{ 
                (item ~> h("source_ip")).asString + ":" + (item ~> h("source_port")).asString + 
                "_hasPort_" + (item ~> h("source_port")).asString 
              },
              "_outV" -> Safely{ (item ~> h("source_ip")).asString + ":" + (item ~> h("source_port")).asString },
              "_inV" -> item ~> h("source_port"),
              "_type" -> "edge",
              "_label" -> "hasPort",
              "source" -> "Hone",
              "outVType" -> "address",
              "inVType" -> "port"
            )
            if((item ~> h("source_ip")) != None && (item ~> h("source_ip")) != Some(S("")) && 
              (item ~> h("source_port")) != None && (item ~> h("source_port")) != Some(S("")) ) n
            else None
          },
          {
            val n = ^(
              "_id" -> Safely{ 
                (item ~> h("dest_ip")).asString + ":" + (item ~> h("dest_port")).asString + 
                "_hasPort_" + (item ~> h("dest_port")).asString 
              },
              "_outV" -> Safely{ (item ~> h("dest_ip")).asString + ":" + (item ~> h("dest_port")).asString },
              "_inV" -> item ~> h("dest_port"),
              "_type" -> "edge",
              "_label" -> "hasPort",
              "source" -> "Hone",
              "outVType" -> "address",
              "inVType" -> "port"
            )
            if((item ~> h("dest_ip")) != None && (item ~> h("dest_ip")) != Some(S("")) && 
              (item ~> h("dest_port")) != None && (item ~> h("dest_port")) != Some(S("")) ) n
            else None
          },
          {
            val n = ^(
              "_id" -> Safely{
                (item ~> h("source_ip")).asString + ":" + (item ~> h("source_port")).asString + "::" + 
                (item ~> h("dest_ip")).asString + ":" + (item ~> h("dest_port")).asString + "_dstAddress_" + 
                (item ~> h("dest_ip")).asString + ":" + (item ~> h("dest_port")).asString 
              },
              "_outV" -> Safely{
                (item ~> h("source_ip")).asString + ":" + (item ~> h("source_port")).asString + "::" + 
                (item ~> h("dest_ip")).asString + ":" + (item ~> h("dest_port")).asString
              },
              "_inV" -> Safely{ (item ~> h("dest_ip")).asString + ":" + (item ~> h("dest_port")).asString },
              "_type" -> "edge",
              "_label" -> "dstAddress",
              "source" -> "Hone",
              "outVType" -> "flow",
              "inVType" -> "address"
            )
            if((item ~> h("source_ip")) != None && (item ~> h("source_ip")) != Some(S("")) && 
              (item ~> h("source_port")) != None && (item ~> h("source_port")) != Some(S("")) && 
              (item ~> h("dest_ip")) != None && (item ~> h("dest_ip")) != Some(S("")) && 
              (item ~> h("dest_port")) != None && (item ~> h("dest_port")) != Some(S("")) ) n
            else None
          },
          {
            val n = ^(
              "_id" -> Safely{
                (item ~> h("source_ip")).asString + ":" + (item ~> h("source_port")).asString + "::" + 
                (item ~> h("dest_ip")).asString + ":" + (item ~> h("dest_port")).asString + "_srcAddress_" + 
                (item ~> h("source_ip")).asString + ":" + (item ~> h("source_port")).asString 
              },
              "_outV" -> Safely{
                (item ~> h("source_ip")).asString + ":" + (item ~> h("source_port")).asString + "::" + 
                (item ~> h("dest_ip")).asString + ":" + (item ~> h("dest_port")).asString
              },
              "_inV" -> Safely{ (item ~> h("source_ip")).asString + ":" + (item ~> h("source_port")).asString },
              "_type" -> "edge",
              "_label" -> "srcAddress",
              "source" -> "Hone",
              "outVType" -> "flow",
              "inVType" -> "address"
            )
            if((item ~> h("source_ip")) != None && (item ~> h("source_ip")) != Some(S("")) && 
              (item ~> h("source_port")) != None && (item ~> h("source_port")) != Some(S("")) && 
              (item ~> h("dest_ip")) != None && (item ~> h("dest_ip")) != Some(S("")) && 
              (item ~> h("dest_port")) != None && (item ~> h("dest_port")) != Some(S("")) ) n
            else None
          },
          {
            val n = ^(
              "_id" -> Safely{
                (item ~> h("process_path")).asString + "_hasFlow_" + 
                (item ~> h("source_ip")).asString + ":" + (item ~> h("source_port")).asString + "::" + 
                (item ~> h("dest_ip")).asString + ":" + (item ~> h("dest_port")).asString
              },
              "_outV" -> item ~> h("process_path"),
              "_inV" -> Safely{ 
                (item ~> h("source_ip")).asString + ":" + (item ~> h("source_port")).asString + "::" + 
                (item ~> h("dest_ip")).asString + ":" + (item ~> h("dest_port")).asString
              },
              "_type" -> "edge",
              "_label" -> "hasFlow",
              "source" -> "Hone",
              "outVType" -> "software",
              "inVType" -> "flow"
            )
            if((item ~> h("source_ip")) != None && (item ~> h("source_ip")) != Some(S("")) && 
              (item ~> h("source_port")) != None && (item ~> h("source_port")) != Some(S("")) && 
              (item ~> h("dest_ip")) != None && (item ~> h("dest_ip")) != Some(S("")) && 
              (item ~> h("dest_port")) != None && (item ~> h("dest_port")) != Some(S("")) &&
              (item ~> h("process_path")) != None && (item ~> h("process_path")) != Some(S(""))) n
            else None
          },
          {
            val n = ^(
              "_id" -> Safely{ 
                (item ~> h("process_path")).asString + "_runsAs_" + 
                hostName + ":" + (item ~> h("uid")).asString 
              },
              "_outV" -> item ~> h("process_path"),
              "_inV" -> Safely{
                hostName + ":" + (item ~> h("uid")).asString 
              },
              "_type" -> "edge",
              "_label" -> "runsAs",
              "source" -> "Hone",
              "outVType" -> "software",
              "inVType" -> "account"
            )
            if((item ~> h("process_path")) != None && (item ~> h("process_path")) != Some(S("")) &&
              (item ~> h("uid")) != None && (item ~> h("uid")) != Some(S("")) && hostName != "") n
            else None
          }
        )
      }).autoFlatten
    )
  }

}


