import org.scalatest.FunSuite

import gov.ornl.stucco.morph.ast._
import gov.ornl.stucco.morph.ast.Implicits._
import gov.ornl.stucco.morph.ast.DSL._
import gov.ornl.stucco.morph.parser._
import gov.ornl.stucco.morph.parser.Interface._
import gov.ornl.stucco.morph.utils.Utils._

import gov.ornl.stucco.extractors._

class ArgusExtractorSuite extends FunSuite {

  // to make testing easier
  val O = ObjectNode
  val A = ArrayNode
  val S = StringNode
  val N = NumberNode

  test("parse an empty element (no header)") {
    var text = """,,,,,,,,,,,,,,,,,,,,,
"""
    val node = CsvParser(text)
    val argus = ArgusExtractor(node)

    assert(argus ~> "vertices" ~> 0 === None)
    assert(argus ~> "edges" ~> 0 === None)
  }

  test("parse an empty element (header included)") {
    var text = """StartTime,Flgs,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,TotPkts,TotBytes,State
,,,,,,,,,,,,,,,,,,,,,
"""
    val node = CsvParser(text)
    val argus = ArgusExtractor(node)

    assert(argus ~> "vertices" ~> 0 === None)
    assert(argus ~> "edges" ~> 0 === None)
  }

  test("parse one argus entries") {
    val node = CsvParser("15:52:32.860730, e s      ,6,10.10.10.1,56867,   ->,10.10.10.100,22,8,585,REQ")
    val argus = ArgusExtractor(node)
   
    assert(argus ~> "vertices" ~> 0 ~> "_id" === Some(S("10.10.10.1:56867::10.10.10.100:22")))
    assert(argus ~> "vertices" ~> 0 ~> "_type" === Some(S("vertex")))
    assert(argus ~> "vertices" ~> 0 ~> "vertexType" === Some(S("flow")))
    assert(argus ~> "vertices" ~> 0 ~> "source" === Some(S("Argus")))
    assert(argus ~> "vertices" ~> 0 ~> "proto" === Some(S("6")))
    assert(argus ~> "vertices" ~> 0 ~> "appBytes" === Some(S("585")))
    assert(argus ~> "vertices" ~> 0 ~> "startTime" === Some(S("15:52:32.860730")))
    assert(argus ~> "vertices" ~> 0 ~> "dir" === Some(S("   ->")))
    assert(argus ~> "vertices" ~> 0 ~> "flags" === Some(S(" e s      ")))
    assert(argus ~> "vertices" ~> 0 ~> "state" === Some(S("REQ")))

    assert(argus ~> "vertices" ~> 1 ~> "_id" === Some(S("10.10.10.1:56867")))
    assert(argus ~> "vertices" ~> 1 ~> "_type" === Some(S("vertex")))
    assert(argus ~> "vertices" ~> 1 ~> "vertexType" === Some(S("address")))
    assert(argus ~> "vertices" ~> 1 ~> "source" === Some(S("Argus")))

    assert(argus ~> "vertices" ~> 2 ~> "_id" === Some(S("10.10.10.100:22")))
    assert(argus ~> "vertices" ~> 2 ~> "_type" === Some(S("vertex")))
    assert(argus ~> "vertices" ~> 2 ~> "vertexType" === Some(S("address")))
    assert(argus ~> "vertices" ~> 2 ~> "source" === Some(S("Argus")))

    assert(argus ~> "vertices" ~> 3 ~> "_id" === Some(S("10.10.10.1")))
    assert(argus ~> "vertices" ~> 3 ~> "_type" === Some(S("vertex")))
    assert(argus ~> "vertices" ~> 3 ~> "vertexType" === Some(S("IP")))
    assert(argus ~> "vertices" ~> 3 ~> "source" === Some(S("Argus")))

    assert(argus ~> "vertices" ~> 4 ~> "_id" === Some(S("10.10.10.100")))
    assert(argus ~> "vertices" ~> 4 ~> "_type" === Some(S("vertex")))
    assert(argus ~> "vertices" ~> 4 ~> "vertexType" === Some(S("IP")))
    assert(argus ~> "vertices" ~> 4 ~> "source" === Some(S("Argus")))

    assert(argus ~> "vertices" ~> 5 ~> "_id" === Some(S("56867")))
    assert(argus ~> "vertices" ~> 5 ~> "_type" === Some(S("vertex")))
    assert(argus ~> "vertices" ~> 5 ~> "vertexType" === Some(S("port")))
    assert(argus ~> "vertices" ~> 5 ~> "source" === Some(S("Argus")))

    assert(argus ~> "vertices" ~> 6 ~> "_id" === Some(S("22")))
    assert(argus ~> "vertices" ~> 6 ~> "_type" === Some(S("vertex")))
    assert(argus ~> "vertices" ~> 6 ~> "vertexType" === Some(S("port")))
    assert(argus ~> "vertices" ~> 6 ~> "source" === Some(S("Argus")))

    assert(argus ~> "edges" ~> 0 ~> "_id" === Some(S("10.10.10.1:56867::10.10.10.100:22_srcAddress_10.10.10.1:56867")))
    assert(argus ~> "edges" ~> 0 ~> "_outV" === Some(S("10.10.10.1:56867::10.10.10.100:22")))
    assert(argus ~> "edges" ~> 0 ~> "_inV" === Some(S("10.10.10.1:56867")))
    assert(argus ~> "edges" ~> 0 ~> "_type" === Some(S("edge")))
    assert(argus ~> "edges" ~> 0 ~> "_label" === Some(S("srcAddress")))
    assert(argus ~> "edges" ~> 0 ~> "source" === Some(S("Argus")))
    assert(argus ~> "edges" ~> 0 ~> "outVType" === Some(S("flow")))
    assert(argus ~> "edges" ~> 0 ~> "inVType" === Some(S("address")))
    
    assert(argus ~> "edges" ~> 1 ~> "_id" === Some(S("10.10.10.1:56867::10.10.10.100:22_dstAddress_10.10.10.100:22")))
    assert(argus ~> "edges" ~> 1 ~> "_outV" === Some(S("10.10.10.1:56867::10.10.10.100:22")))
    assert(argus ~> "edges" ~> 1 ~> "_inV" === Some(S("10.10.10.100:22")))
    assert(argus ~> "edges" ~> 1 ~> "_type" === Some(S("edge")))
    assert(argus ~> "edges" ~> 1 ~> "_label" === Some(S("dstAddress")))
    assert(argus ~> "edges" ~> 1 ~> "source" === Some(S("Argus")))
    assert(argus ~> "edges" ~> 1 ~> "outVType" === Some(S("flow")))
    assert(argus ~> "edges" ~> 1 ~> "inVType" === Some(S("address")))

    assert(argus ~> "edges" ~> 2 ~> "_id" === Some(S("10.10.10.1:56867_hasIP_10.10.10.1")))
    assert(argus ~> "edges" ~> 2 ~> "_outV" === Some(S("10.10.10.1:56867")))
    assert(argus ~> "edges" ~> 2 ~> "_inV" === Some(S("10.10.10.1")))
    assert(argus ~> "edges" ~> 2 ~> "_type" === Some(S("edge")))
    assert(argus ~> "edges" ~> 2 ~> "_label" === Some(S("hasIP")))
    assert(argus ~> "edges" ~> 2 ~> "source" === Some(S("Argus")))
    assert(argus ~> "edges" ~> 2 ~> "outVType" === Some(S("address")))
    assert(argus ~> "edges" ~> 2 ~> "inVType" === Some(S("IP")))

    assert(argus ~> "edges" ~> 3 ~> "_id" === Some(S("10.10.10.100:22_hasIP_10.10.10.100")))
    assert(argus ~> "edges" ~> 3 ~> "_outV" === Some(S("10.10.10.100:22")))
    assert(argus ~> "edges" ~> 3 ~> "_inV" === Some(S("10.10.10.100")))
    assert(argus ~> "edges" ~> 3 ~> "_type" === Some(S("edge")))
    assert(argus ~> "edges" ~> 3 ~> "_label" === Some(S("hasIP")))
    assert(argus ~> "edges" ~> 3 ~> "source" === Some(S("Argus")))
    assert(argus ~> "edges" ~> 3 ~> "outVType" === Some(S("address")))
    assert(argus ~> "edges" ~> 3 ~> "inVType" === Some(S("IP")))
    
    assert(argus ~> "edges" ~> 4 ~> "_id" === Some(S("10.10.10.1:56867_hasPort_56867")))
    assert(argus ~> "edges" ~> 4 ~> "_outV" === Some(S("10.10.10.1:56867")))
    assert(argus ~> "edges" ~> 4 ~> "_inV" === Some(S("56867")))
    assert(argus ~> "edges" ~> 4 ~> "_type" === Some(S("edge")))
    assert(argus ~> "edges" ~> 4 ~> "_label" === Some(S("hasPort")))
    assert(argus ~> "edges" ~> 4 ~> "source" === Some(S("Argus")))
    assert(argus ~> "edges" ~> 4 ~> "outVType" === Some(S("address")))
    assert(argus ~> "edges" ~> 4 ~> "inVType" === Some(S("port")))

    assert(argus ~> "edges" ~> 5 ~> "_id" === Some(S("10.10.10.100:22_hasPort_22")))
    assert(argus ~> "edges" ~> 5 ~> "_outV" === Some(S("10.10.10.100:22")))
    assert(argus ~> "edges" ~> 5 ~> "_inV" === Some(S("22")))
    assert(argus ~> "edges" ~> 5 ~> "_type" === Some(S("edge")))
    assert(argus ~> "edges" ~> 5 ~> "_label" === Some(S("hasPort")))
    assert(argus ~> "edges" ~> 5 ~> "source" === Some(S("Argus")))
    assert(argus ~> "edges" ~> 5 ~> "outVType" === Some(S("address")))
    assert(argus ~> "edges" ~> 5 ~> "inVType" === Some(S("port")))
  }
}
