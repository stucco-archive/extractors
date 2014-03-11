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
          val n = ^(
            "_id" -> Safely{ "CleanMx_" + (item ~> "id").asNumber.toString },
            "_type" -> "vertex",
            "vertexType" -> "attackerAsset",
            "source" -> "CleanMx(virus)",
            "firstSeen" -> item ~> "first",
            "lastSeen" -> item ~> "last"
          )
          n
        },
        {
          ^(
            "_id" -> Safely{ "CleanMx_" + (item ~> "md5").asString},
            "_type" -> "vertex",
            "vertexType" -> "malware",
            "source" -> "CleanMx(virus)",
            "avName" -> item ~> "virusname", //TODO remove ![CDATA[]]
            "md5" -> item ~> "md5"
          )
        },
        {
          ^(
            "_id" -> Safely{ (item ~> "ip").asString + ":80"}, //TODO extract port from URL string, if present.  a few are non-default.
            "_type" -> "vertex",
            "vertexType" -> "address",
            "source" -> "CleanMx(virus)"
          )
        },
        {
          ^(
            "_id" -> "80", //TODO extract port from URL string, if present.  a few are non-default.
            "_type" -> "vertex",
            "vertexType" -> "port",
            "source" -> "CleanMx(virus)"
          )
        },
        {
          val n = ^(
            "_id" -> item ~> "domain", //TODO keep subdomain?  (This field does not have subdomain, URL field does)
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
            "_type" -> "vertex",
            "vertexType" -> "IP",
            "source" -> "CleanMx(virus)"
          )
        },
        {
          val ips = (item ~> "inetnum").asString.split(" - ")
          val n = ^(
            "_id" -> Safely { ips(0) + "_through_" + ips(1) },
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
    }).encapsulate,
    "edges" -> (node ~> "output" ~> "entries" ~> "entry" %%-> { item =>
      *(
        {
          ^(
            "_id" -> Safely{ ("CleanMx_" + (item ~> "md5").asString + "_to_" + "CleanMx_" + (item ~> "id").asNumber.toString)},
            "_type" -> "edge",
            "inVType" -> "attackerAsset",
            "outVType" -> "malware",
            "source" -> "CleanMx(virus)",
            "_inV" -> Safely{ ("CleanMx_" + (item ~> "id").asNumber.toString)},
            "_outV" -> Safely{ ("CleanMx_" + (item ~> "md5").asString)},
            "_label" -> "associatedWith"
          )
        },
        {
          ^(
            "_id" -> Safely{ ("CleanMx_" + (item ~> "id").asNumber.toString + "_to_" + (item ~> "ip").asString + ":80")}, //TODO port num, see above.
            "_type" -> "edge",
            "inVType" -> "address",
            "outVType" -> "attackerAsset",
            "source" -> "CleanMx(virus)",
            "_inV" -> Safely{ ((item ~> "ip").asString + ":80")},
            "_outV" -> Safely{ ("CleanMx_" + (item ~> "id").asNumber.toString)},
            "_label" -> "usesAddress"
          )
        },
        {
          ^(
            "_id" -> Safely{ ((item ~> "ip").asString + ":80" + "_to_" + "80")}, //TODO port num, see above.
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
            "_id" -> Safely{ ((item ~> "ip").asString + ":80" + "_to_" + (item ~> "domain").asString)}, //TODO keep subdomain? see above.  port num, see above.
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
            "_id" -> Safely{ ((item ~> "ip").asString + ":80" + "_to_" + (item ~> "ip").asString)}, //TODO port num, see above.
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
          val ips = (item ~> "inetnum").asString.split(" - ")
          val n = ^(
            "_id" -> Safely { (item ~> "ip").asString + "_to_" + ips(0) + "_through_" + ips(1) },
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
