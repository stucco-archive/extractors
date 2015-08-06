import org.scalatest.FunSuite

import gov.ornl.stucco.morph.ast._
import gov.ornl.stucco.morph.ast.Implicits._
import gov.ornl.stucco.morph.ast.DSL._
import gov.ornl.stucco.morph.parser._
import gov.ornl.stucco.morph.parser.Interface._
import gov.ornl.stucco.morph.utils.Utils._

import gov.ornl.stucco.extractors._

class CIF1d4ExtractorSuite extends FunSuite {

  // to make testing easier
  val O = ObjectNode
  val A = ArrayNode
  val S = StringNode
  val N = NumberNode

  test("parse one entry") {
    var text = """103.36.125.189
"""
    val node = CsvParser(text)
    val ips = CIF1d4Extractor(node)
    //print(ips)
    assert(ips ~> "vertices" ~> 0 ~> "_id" === Some(S("103.36.125.189")))
    assert(ips ~> "vertices" ~> 0 ~> "name" === Some(S("103.36.125.189")))
    assert(ips ~> "vertices" ~> 0 ~> "description" === Some(S("103.36.125.189")))
    assert(ips ~> "vertices" ~> 0 ~> "_type" === Some(S("vertex")))
    assert(ips ~> "vertices" ~> 0 ~> "source" === Some(S("1d4.us")))
    assert(ips ~> "vertices" ~> 0 ~> "vertexType" === Some(S("IP")))
    assert(ips ~> "vertices" ~> 0 ~> "ipInt" === Some(N(1730444733)))
    assert(ips ~> "vertices" ~> 0 ~> "tags" === Some(S("scanner")))

    assert(ips ~> "vertices" ~> 1 === None)
  }

  test("parse several entries") {
    var text = """112.120.48.179
113.195.145.12
113.195.145.70
113.195.145.80
"""
    val node = CsvParser(text)
    val ips = CIF1d4Extractor(node)
    //print(ips)
    assert(ips ~> "vertices" ~> 0 ~> "_id" === Some(S("112.120.48.179")))
    assert(ips ~> "vertices" ~> 0 ~> "name" === Some(S("112.120.48.179")))
    assert(ips ~> "vertices" ~> 0 ~> "description" === Some(S("112.120.48.179")))
    assert(ips ~> "vertices" ~> 0 ~> "_type" === Some(S("vertex")))
    assert(ips ~> "vertices" ~> 0 ~> "source" === Some(S("1d4.us")))
    assert(ips ~> "vertices" ~> 0 ~> "vertexType" === Some(S("IP")))
    assert(ips ~> "vertices" ~> 0 ~> "ipInt" === Some(N(1886924979)))
    assert(ips ~> "vertices" ~> 0 ~> "tags" === Some(S("scanner")))

    assert(ips ~> "vertices" ~> 1 ~> "_id" === Some(S("113.195.145.12")))
    assert(ips ~> "vertices" ~> 1 ~> "name" === Some(S("113.195.145.12")))
    assert(ips ~> "vertices" ~> 1 ~> "description" === Some(S("113.195.145.12")))
    assert(ips ~> "vertices" ~> 1 ~> "_type" === Some(S("vertex")))
    assert(ips ~> "vertices" ~> 1 ~> "source" === Some(S("1d4.us")))
    assert(ips ~> "vertices" ~> 1 ~> "vertexType" === Some(S("IP")))
    assert(ips ~> "vertices" ~> 1 ~> "ipInt" === Some(N(1908642060)))
    assert(ips ~> "vertices" ~> 1 ~> "tags" === Some(S("scanner")))

    assert(ips ~> "vertices" ~> 2 ~> "_id" === Some(S("113.195.145.70")))
    assert(ips ~> "vertices" ~> 2 ~> "name" === Some(S("113.195.145.70")))
    assert(ips ~> "vertices" ~> 2 ~> "description" === Some(S("113.195.145.70")))
    assert(ips ~> "vertices" ~> 2 ~> "_type" === Some(S("vertex")))
    assert(ips ~> "vertices" ~> 2 ~> "source" === Some(S("1d4.us")))
    assert(ips ~> "vertices" ~> 2 ~> "vertexType" === Some(S("IP")))
    assert(ips ~> "vertices" ~> 2 ~> "ipInt" === Some(N(1908642118)))
    assert(ips ~> "vertices" ~> 2 ~> "tags" === Some(S("scanner")))

    assert(ips ~> "vertices" ~> 3 ~> "_id" === Some(S("113.195.145.80")))
    assert(ips ~> "vertices" ~> 3 ~> "name" === Some(S("113.195.145.80")))
    assert(ips ~> "vertices" ~> 3 ~> "description" === Some(S("113.195.145.80")))
    assert(ips ~> "vertices" ~> 3 ~> "_type" === Some(S("vertex")))
    assert(ips ~> "vertices" ~> 3 ~> "source" === Some(S("1d4.us")))
    assert(ips ~> "vertices" ~> 3 ~> "vertexType" === Some(S("IP")))
    assert(ips ~> "vertices" ~> 3 ~> "ipInt" === Some(N(1908642128)))
    assert(ips ~> "vertices" ~> 3 ~> "tags" === Some(S("scanner")))

    assert(ips ~> "vertices" ~> 4 === None)
  }

}

