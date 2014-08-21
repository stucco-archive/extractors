package gov.ornl.stucco.extractors

import gov.ornl.stucco.morph.ast._
import gov.ornl.stucco.morph.extractor.Extractor

object MetasploitExtractor extends Extractor {

  // to make testing easier
  val O = ObjectNode
  val A = ArrayNode
  val S = StringNode
  val N = NumberNode

  //TODO: it would be useful to also check non-strings here.
  def notEmpty(node: Option[ValueNode]): Boolean = {
    node != None && node != Some(S(""))
  }

  def getRefList(node: Option[ValueNode]): List[String] = { List("asdf","asdf2") }

  def extract(node: ValueNode): ValueNode = {
    //"id","mtime","file","mtype","refname","fullname","name","rank","description","license","privileged","disclosure_date","default_target","default_action","stance","ready","ref_names","author_names"
    val headers = node.get(0)
    val h = headers.asList.zipWithIndex.map { a => a }.toMap
    ^(
      "vertices" -> (node mapPartial {
        //this will ignore header row and will ignore last row if it is just an empty string.
        case item if (item ~> 0 != headers ~> 0) && (item ~> 1 != None) =>
          *(
            {
              val n = ^(
                "_id" -> item ~> h("fullname"),
                "_type" -> "vertex",
                "source" -> "Metasploit",
                "vertexType" -> "malware",
                "malwareType" -> item ~> h("mtype"),
                "discoveryDate" -> item ~> h("disclosure_date"),
                "overview" -> item ~> h("name"),
                "details" -> item ~> h("description")
              )
              if (notEmpty(n ~> "_id")) n
              else None
            },
            {
              val cves = gov.ornl.stucco.morph.parser.CsvParser((item ~> h("ref_names")).asString) ~> 0 
              val m = cves mapPartial {
                case cve if (cve.isString && cve.asString.contains("CVE-") ) =>
                *(
                  {
                    val n = ^(
                      "_id" -> cve.asString.trim(),
                      "_type" -> "vertex",
                      "source" -> "Metasploit",
                      "vertexType" -> "vulnerability"
                    )
                    if (notEmpty(n ~> "_id") ) n
                    else None
                  }
                )
              }
              if (m.asList.length > 0) m.autoFlatten
              else None
            }
          )
      }).autoFlatten.autoFlatten,
      "edges" -> (node mapPartial {
        //this will ignore header row and will ignore last row if it is just an empty string.
        case item if (item ~> 0 != headers ~> 0) && (item ~> 1 != None) =>
          *(
            {
              val cves = gov.ornl.stucco.morph.parser.CsvParser((item ~> h("ref_names")).asString) ~> 0 //*((item ~> h("ref_names")).asString.split(","))
              val m = cves mapPartial {
                case cve if (cve.isString && cve.asString.contains("CVE-") ) =>
                *(
                  {
                    val n = ^(
                      "_id" -> Safely { (item ~> h("fullname")).asString + "_exploits_" + cve.asString.trim() },
                      "_outV" -> item ~> h("fullname"),
                      "_inV" -> cve.asString.trim(),
                      "_type" -> "edge",
                      "_label" -> "exploits",
                      "source" -> "Metasploit",
                      "outVType" -> "malware",
                      "inVType" -> "vulnerability"
                    )
                    if (notEmpty(n ~> "_id") ) n
                    else None
                  }
                )
              }
              if (m.asList.length > 0) m.autoFlatten//ArrayNode(m.asInstanceOf[List[morph.ast.ValueNode]])//A(m.asInstanceOf[List[ObjectNode]])//(notEmpty(m)) A(m)
              else None
            }
          )
      }).autoFlatten.autoFlatten        
    )
  }

}

