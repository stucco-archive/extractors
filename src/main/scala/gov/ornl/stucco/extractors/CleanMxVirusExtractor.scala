package gov.ornl.stucco.extractors

import gov.ornl.stucco.morph.ast._
import gov.ornl.stucco.morph.extractor.Extractor

/**
 * CleanMX Virus data extractor.
 *
 * @author Mike Iannacone
 */
object CleanMxVirusExtractor extends Extractor {

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
    "vertices" -> (node ~> "output" ~> "entries" ~> "entry" %%-> { item =>
      *(
        {
          ^(
            "_id" -> Safely{ "CleanMx_" + (item ~> "id").asNumber},
            "name" -> Safely{ "CleanMx_" + (item ~> "id").asNumber},
            "description" -> Safely{ "CleanMx entry " + (item ~> "id").asNumber},
            "_type" -> "vertex",
            "vertexType" -> "malware",
            "source" -> "CleanMx(virus)",
            "aliases" -> item ~> "virusname", //TODO remove ![CDATA[]]
            "md5hashes" -> item ~> "md5"
          )
        },
        {
          ^(
            "_id" -> Safely{ (item ~> "ip").asString + ":80"}, //TODO extract port from URL string, if present.  a few are non-default.
            "name" -> Safely{ (item ~> "ip").asString + ":80"}, 
            "description" -> Safely{ (item ~> "ip").asString + ", port 80"}, 
            "_type" -> "vertex",
            "vertexType" -> "address",
            "source" -> "CleanMx(virus)"
          )
        },
        {
          ^(
            "_id" -> "80", //TODO extract port from URL string, if present.  a few are non-default.
            "name" -> "80", 
            "description" -> "80", 
            "_type" -> "vertex",
            "vertexType" -> "port",
            "source" -> "CleanMx(virus)"
          )
        },
        {
          val n = ^(
            "_id" -> item ~> "domain", //TODO keep subdomain?  (This field does not have subdomain, URL field does)
            "name" -> item ~> "domain",
            "description" -> item ~> "domain",
            "_type" -> "vertex",
            "vertexType" -> "DNSName",
            "source" -> "CleanMx(virus)",
            "ns1" -> item ~> "ns1",
            "ns2" -> item ~> "ns2",
            "ns3" -> item ~> "ns3",
            "ns4" -> item ~> "ns4", 
            "ns5" -> item ~> "ns5"  //TODO null vs None
          )
          n
        },
        {
          ^(
            "_id" -> item ~> "ip",
            "name" -> item ~> "ip",
            "description" -> item ~> "ip",
            "_type" -> "vertex",
            "vertexType" -> "IP",
            "source" -> "CleanMx(virus)"
          )
        },
        {
          val inetnum = (item ~> "inetnum").asString
          val ips = if(inetnum.contains(" - ")) inetnum.split(" - ") else inetnum.split("-")
          val n = ^(
            "_id" -> Safely { ips(0) + "_through_" + ips(1) },
            "name" -> Safely { ips(0) + "_through_" + ips(1) },
            "_type" -> "vertex",
            "vertexType" -> "addressRange",
            "source" -> "CleanMx(virus)",
            "startIP" -> ips(0),
            "endIP" -> ips(1),
            //"startIPInt" //TODO could also populate these other fields
            //"endIPInt"
            "countryCode" -> item ~> "country",
            //"countryName"
            "netname" -> item ~> "netname",
            "description" -> item ~> "descr",
            "asNum" -> item ~> "as",
            "assignedBy" -> item ~> "source"
          )
          if (notEmpty(n ~> "_id")) n
          else None
        }
      )
    }).encapsulate.autoFlatten,
    "edges" -> (node ~> "output" ~> "entries" ~> "entry" %%-> { item =>
      *(
        {
          ^(
            "_id" -> Safely{ ("CleanMx_" + (item ~> "id").asNumber + "_communicatesWith_" + (item ~> "ip").asString + ":80")}, //TODO port num, see above.
            "description" -> Safely{ ("CleanMx entry " + (item ~> "id").asNumber + " communicates with " + (item ~> "ip").asString + ", port 80")},
            "_type" -> "edge",
            "inVType" -> "address",
            "outVType" -> "malware",
            "source" -> "CleanMx(virus)",
            "_inV" -> Safely{ ((item ~> "ip").asString + ":80")},
            "_outV" -> Safely{ ("CleanMx_" + (item ~> "id").asNumber)},
            "_label" -> "communicatesWith"
          )
        },
        {
          ^(
            "_id" -> Safely{ ((item ~> "ip").asString + ":80" + "_hasPort_" + "80")}, //TODO port num, see above.
            "description" -> Safely{ ((item ~> "ip").asString + ", port 80" + " has port " + "80")},
            "_type" -> "edge",
            "inVType" -> "port",
            "outVType" -> "address",
            "source" -> "CleanMx(virus)",
            "_inV" -> "80",
            "_outV" -> Safely{ ((item ~> "ip").asString + ":80")},
            "_label" -> "hasPort"
          )
        },
        {
          ^(
            "_id" -> Safely{ ((item ~> "ip").asString + ":80" + "_hasDNSName_" + (item ~> "domain").asString)}, //TODO keep subdomain? see above.  port num, see above.
            "description" -> Safely{ ((item ~> "ip").asString + ", port 80" + " has DNS name " + (item ~> "domain").asString)},
            "_type" -> "edge",
            "inVType" -> "DNSName",
            "outVType" -> "address",
            "source" -> "CleanMx(virus)",
            "_inV" -> item ~> "domain",
            "_outV" -> Safely{ ((item ~> "ip").asString + ":80")},
            "_label" -> "hasDNSName"
          )
        },
        {
          ^(
            "_id" -> Safely{ ((item ~> "ip").asString + ":80" + "_hasIP_" + (item ~> "ip").asString)}, //TODO port num, see above.
            "description" -> Safely{ ((item ~> "ip").asString + ", port 80" + " has IP " + (item ~> "ip").asString)},
            "_type" -> "edge",
            "inVType" -> "IP",
            "outVType" -> "address",
            "source" -> "CleanMx(virus)",
            "_inV" -> item ~> "ip",
            "_outV" -> Safely{ ((item ~> "ip").asString + ":80")},
            "_label" -> "hasIP"
          )
        },
        {
          val inetnum = (item ~> "inetnum").asString
          val ips = if(inetnum.contains(" - ")) inetnum.split(" - ") else inetnum.split("-")
          val n = ^(
            "_id" -> Safely { (item ~> "ip").asString + "_inAddressRange_" + ips(0) + "_through_" + ips(1) },
            "description" -> Safely { (item ~> "ip").asString + " is in address range " + ips(0) + " through " + ips(1) },
            "_type" -> "edge",
            "inVType" -> "addressRange",
            "outVType" -> "IP",
            "source" -> "CleanMx(virus)",
            "_inV" -> Safely{ (ips(0) + "_through_" + ips(1))},
            "_outV" -> item ~> "ip",
            "_label" -> "inAddressRange"
          )
          if (notEmpty(n ~> "_id")) n
          else None
        }
      )
    }).autoFlatten
  )
}
