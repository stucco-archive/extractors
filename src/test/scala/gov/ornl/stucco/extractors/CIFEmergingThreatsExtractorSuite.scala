import org.scalatest.FunSuite

import gov.ornl.stucco.morph.ast._
import gov.ornl.stucco.morph.ast.Implicits._
import gov.ornl.stucco.morph.ast.DSL._
import gov.ornl.stucco.morph.parser._
import gov.ornl.stucco.morph.parser.Interface._
import gov.ornl.stucco.morph.utils.Utils._

import gov.ornl.stucco.extractors._

class CIFEmergingThreatsExtractorSuite extends FunSuite {

  // to make testing easier
  val O = ObjectNode
  val A = ArrayNode
  val S = StringNode
  val N = NumberNode

  test("parse one entry") {
    var text = """100.42.62.172
"""
    val node = CsvParser(text)
    val ips = CIFEmergingThreatsExtractor(node)
    //print(ips)
    assert(ips ~> "vertices" ~> 0 ~> "_id" === Some(S("100.42.62.172")))
    assert(ips ~> "vertices" ~> 0 ~> "name" === Some(S("100.42.62.172")))
    assert(ips ~> "vertices" ~> 0 ~> "description" === Some(S("100.42.62.172")))
    assert(ips ~> "vertices" ~> 0 ~> "_type" === Some(S("vertex")))
    assert(ips ~> "vertices" ~> 0 ~> "source" === Some(S("rules.emergingthreats.net")))
    assert(ips ~> "vertices" ~> 0 ~> "vertexType" === Some(S("IP")))
    assert(ips ~> "vertices" ~> 0 ~> "ipInt" === Some(N(1680490156)))
    assert(ips ~> "vertices" ~> 0 ~> "tags" === Some(S("malware")))

    assert(ips ~> "vertices" ~> 1 === None)
  }

  test("parse several entries") {
    var text = """1.186.245.244
1.209.170.39
1.212.121.122
"""
    val node = CsvParser(text)
    val ips = CIFEmergingThreatsExtractor(node)
    //print(ips)
    assert(ips ~> "vertices" ~> 0 ~> "_id" === Some(S("1.186.245.244")))
    assert(ips ~> "vertices" ~> 0 ~> "name" === Some(S("1.186.245.244")))
    assert(ips ~> "vertices" ~> 0 ~> "description" === Some(S("1.186.245.244")))
    assert(ips ~> "vertices" ~> 0 ~> "_type" === Some(S("vertex")))
    assert(ips ~> "vertices" ~> 0 ~> "source" === Some(S("rules.emergingthreats.net")))
    assert(ips ~> "vertices" ~> 0 ~> "vertexType" === Some(S("IP")))
    assert(ips ~> "vertices" ~> 0 ~> "ipInt" === Some(N(29029876)))
    assert(ips ~> "vertices" ~> 0 ~> "tags" === Some(S("malware")))

    assert(ips ~> "vertices" ~> 1 ~> "_id" === Some(S("1.209.170.39")))
    assert(ips ~> "vertices" ~> 1 ~> "name" === Some(S("1.209.170.39")))
    assert(ips ~> "vertices" ~> 1 ~> "description" === Some(S("1.209.170.39")))
    assert(ips ~> "vertices" ~> 1 ~> "_type" === Some(S("vertex")))
    assert(ips ~> "vertices" ~> 1 ~> "source" === Some(S("rules.emergingthreats.net")))
    assert(ips ~> "vertices" ~> 1 ~> "vertexType" === Some(S("IP")))
    assert(ips ~> "vertices" ~> 1 ~> "ipInt" === Some(N(30517799)))
    assert(ips ~> "vertices" ~> 1 ~> "tags" === Some(S("malware")))

    assert(ips ~> "vertices" ~> 2 ~> "_id" === Some(S("1.212.121.122")))
    assert(ips ~> "vertices" ~> 2 ~> "name" === Some(S("1.212.121.122")))
    assert(ips ~> "vertices" ~> 2 ~> "description" === Some(S("1.212.121.122")))
    assert(ips ~> "vertices" ~> 2 ~> "_type" === Some(S("vertex")))
    assert(ips ~> "vertices" ~> 2 ~> "source" === Some(S("rules.emergingthreats.net")))
    assert(ips ~> "vertices" ~> 2 ~> "vertexType" === Some(S("IP")))
    assert(ips ~> "vertices" ~> 2 ~> "ipInt" === Some(N(30701946)))
    assert(ips ~> "vertices" ~> 2 ~> "tags" === Some(S("malware")))

    assert(ips ~> "vertices" ~> 3 === None)
  }

}

