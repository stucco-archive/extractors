import org.scalatest.FunSuite

import gov.ornl.stucco.morph.ast._
import gov.ornl.stucco.morph.ast.Implicits._
import gov.ornl.stucco.morph.ast.DSL._
import gov.ornl.stucco.morph.parser._
import gov.ornl.stucco.morph.parser.Interface._
import gov.ornl.stucco.morph.utils.Utils._

import gov.ornl.stucco.extractors._

import org.apache.commons.io._

class PackageListExtractorSuite extends FunSuite {

  // to make testing easier
  val O = ObjectNode
  val A = ArrayNode
  val S = StringNode
  val N = NumberNode

  test("parse an empty line (no header)") {
    var text = """,,,,,,,,,,,,,,,,,,,,,
"""
    val node = CsvParser(text)
    val packageList = PackageListExtractor.extract(node)

    assert(packageList ~> "vertices" ~> 0 === None)
    assert(packageList ~> "edges" ~> 0 === None)
  }

  test("parse an empty PackageList element (header included)") {
    var text = """hostname,package,version
,,,,,,,,,,,,,,,,,,,,,
"""
    val node = CsvParser(text)
    val packageList = PackageListExtractor.extract(node)

    assert(packageList ~> "vertices" ~> 0 === None)
    assert(packageList ~> "edges" ~> 0 === None)
  }

  test("parse 1 PackageList element") {
    var text = """stucco1,ftp,0.17-25
"""
    val node = CsvParser(text)
    val packageList = PackageListExtractor.extract(node)
    //print(packageList)

    assert(packageList ~> "vertices" ~> 0 ~> "_id" === Some(S("stucco1")))
    assert(packageList ~> "vertices" ~> 0 ~> "name" === Some(S("stucco1")))
    assert(packageList ~> "vertices" ~> 0 ~> "description" === Some(S("stucco1")))
    assert(packageList ~> "vertices" ~> 0 ~> "_type" === Some(S("vertex")))
    assert(packageList ~> "vertices" ~> 0 ~> "source" === Some(S("PackageList")))
    assert(packageList ~> "vertices" ~> 0 ~> "vertexType" === Some(S("host")))

    assert(packageList ~> "vertices" ~> 1 ~> "_id" === Some(S("ftp_0.17-25")))
    assert(packageList ~> "vertices" ~> 1 ~> "name" === Some(S("ftp_0.17-25")))
    assert(packageList ~> "vertices" ~> 1 ~> "description" === Some(S("ftp version 0.17-25")))
    assert(packageList ~> "vertices" ~> 1 ~> "_type" === Some(S("vertex")))
    assert(packageList ~> "vertices" ~> 1 ~> "source" === Some(S("PackageList")))
    assert(packageList ~> "vertices" ~> 1 ~> "vertexType" === Some(S("software")))
    assert(packageList ~> "vertices" ~> 1 ~> "product" === Some(S("ftp")))
    assert(packageList ~> "vertices" ~> 1 ~> "version" === Some(S("0.17-25")))

    assert(packageList ~> "edges" ~> 0 ~> "_id" === Some(S("stucco1_runs_ftp_0.17-25")))
    assert(packageList ~> "edges" ~> 0 ~> "description" === Some(S("stucco1 runs ftp_0.17-25")))
    assert(packageList ~> "edges" ~> 0 ~> "_outV" === Some(S("stucco1")))
    assert(packageList ~> "edges" ~> 0 ~> "_inV" === Some(S("ftp_0.17-25")))
    assert(packageList ~> "edges" ~> 0 ~> "_type" === Some(S("edge")))
    assert(packageList ~> "edges" ~> 0 ~> "_label" === Some(S("runs")))
    assert(packageList ~> "edges" ~> 0 ~> "source" === Some(S("PackageList")))
    assert(packageList ~> "edges" ~> 0 ~> "outVType" === Some(S("host")))
    assert(packageList ~> "edges" ~> 0 ~> "inVType" === Some(S("software")))
  }
}

