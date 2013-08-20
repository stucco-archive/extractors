import org.scalatest.FunSuite

import morph.ast._
import morph.ast.Implicits._
import morph.ast.DSL._
import morph.parser._
import morph.parser.Interface._
import morph.utils.Utils._

import gov.ornl.stucco.extractors._

class GeoIPExtractorSuite extends FunSuite {

  // to make testing easier
  val O = ObjectNode
  val A = ArrayNode
  val S = StringNode
  val N = NumberNode

  test("parse 5 geoIP elements") {
    var text = """"StartIP","EndIP","Start IP (int)","End IP (int)","Country code","Country name"
"1.0.0.0","1.0.0.255","16777216","16777471","AU","Australia"
"1.0.1.0","1.0.3.255","16777472","16778239","CN","China"
"1.0.4.0","1.0.7.255","16778240","16779263","AU","Australia"
"1.0.8.0","1.0.15.255","16779264","16781311","CN","China"
"1.0.16.0","1.0.31.255","16781312","16785407","JP","Japan"
"""
    val node = morph.parser.CsvParser(text)
    val geoIP = GeoIPExtractor(node)
    //print(geoIP)
    assert(geoIP ~> "vertices" ~> 0 ~> "_id" === Some(S("1.0.0.0_through_1.0.0.255")))
    assert(geoIP ~> "vertices" ~> 0 ~> "_type" === Some(S("vertex")))
    assert(geoIP ~> "vertices" ~> 0 ~> "source" === Some(S("maxmind")))
    assert(geoIP ~> "vertices" ~> 0 ~> "vertexType" === Some(S("addressRange")))

    assert(geoIP ~> "vertices" ~> 0 ~> "startIP" === Some(S("1.0.0.0")))
    assert(geoIP ~> "vertices" ~> 0 ~> "endIP" === Some(S("1.0.0.255")))
    assert(geoIP ~> "vertices" ~> 0 ~> "startIPInt" === Some(N(16777216)))
    assert(geoIP ~> "vertices" ~> 0 ~> "endIPInt" === Some(N(16777471)))
    assert(geoIP ~> "vertices" ~> 0 ~> "countryCode" === Some(S("AU")))
    assert(geoIP ~> "vertices" ~> 0 ~> "countryName" === Some(S("Australia")))

    assert(geoIP ~> "vertices" ~> 1 ~> "_id" === Some(S("1.0.1.0_through_1.0.3.255")))
    assert(geoIP ~> "vertices" ~> 1 ~> "_type" === Some(S("vertex")))
    assert(geoIP ~> "vertices" ~> 1 ~> "source" === Some(S("maxmind")))
    assert(geoIP ~> "vertices" ~> 1 ~> "vertexType" === Some(S("addressRange")))

    assert(geoIP ~> "vertices" ~> 1 ~> "startIP" === Some(S("1.0.1.0")))
    assert(geoIP ~> "vertices" ~> 1 ~> "endIP" === Some(S("1.0.3.255")))
    assert(geoIP ~> "vertices" ~> 1 ~> "startIPInt" === Some(N(16777472)))
    assert(geoIP ~> "vertices" ~> 1 ~> "endIPInt" === Some(N(16778239)))
    assert(geoIP ~> "vertices" ~> 1 ~> "countryCode" === Some(S("CN")))
    assert(geoIP ~> "vertices" ~> 1 ~> "countryName" === Some(S("China")))

    assert(geoIP ~> "vertices" ~> 2 ~> "_id" === Some(S("1.0.4.0_through_1.0.7.255")))
    assert(geoIP ~> "vertices" ~> 2 ~> "_type" === Some(S("vertex")))
    assert(geoIP ~> "vertices" ~> 2 ~> "source" === Some(S("maxmind")))
    assert(geoIP ~> "vertices" ~> 2 ~> "vertexType" === Some(S("addressRange")))

    assert(geoIP ~> "vertices" ~> 2 ~> "startIP" === Some(S("1.0.4.0")))
    assert(geoIP ~> "vertices" ~> 2 ~> "endIP" === Some(S("1.0.7.255")))
    assert(geoIP ~> "vertices" ~> 2 ~> "startIPInt" === Some(N(16778240)))
    assert(geoIP ~> "vertices" ~> 2 ~> "endIPInt" === Some(N(16779263)))
    assert(geoIP ~> "vertices" ~> 2 ~> "countryCode" === Some(S("AU")))
    assert(geoIP ~> "vertices" ~> 2 ~> "countryName" === Some(S("Australia")))

    assert(geoIP ~> "vertices" ~> 3 ~> "_id" === Some(S("1.0.8.0_through_1.0.15.255")))
    assert(geoIP ~> "vertices" ~> 3 ~> "_type" === Some(S("vertex")))
    assert(geoIP ~> "vertices" ~> 3 ~> "source" === Some(S("maxmind")))
    assert(geoIP ~> "vertices" ~> 3 ~> "vertexType" === Some(S("addressRange")))

    assert(geoIP ~> "vertices" ~> 3 ~> "startIP" === Some(S("1.0.8.0")))
    assert(geoIP ~> "vertices" ~> 3 ~> "endIP" === Some(S("1.0.15.255")))
    assert(geoIP ~> "vertices" ~> 3 ~> "startIPInt" === Some(N(16779264)))
    assert(geoIP ~> "vertices" ~> 3 ~> "endIPInt" === Some(N(16781311)))
    assert(geoIP ~> "vertices" ~> 3 ~> "countryCode" === Some(S("CN")))
    assert(geoIP ~> "vertices" ~> 3 ~> "countryName" === Some(S("China")))

    assert(geoIP ~> "vertices" ~> 4 ~> "_id" === Some(S("1.0.16.0_through_1.0.31.255")))
    assert(geoIP ~> "vertices" ~> 4 ~> "_type" === Some(S("vertex")))
    assert(geoIP ~> "vertices" ~> 4 ~> "source" === Some(S("maxmind")))
    assert(geoIP ~> "vertices" ~> 4 ~> "vertexType" === Some(S("addressRange")))

    assert(geoIP ~> "vertices" ~> 4 ~> "startIP" === Some(S("1.0.16.0")))
    assert(geoIP ~> "vertices" ~> 4 ~> "endIP" === Some(S("1.0.31.255")))
    assert(geoIP ~> "vertices" ~> 4 ~> "startIPInt" === Some(N(16781312)))
    assert(geoIP ~> "vertices" ~> 4 ~> "endIPInt" === Some(N(16785407)))
    assert(geoIP ~> "vertices" ~> 4 ~> "countryCode" === Some(S("JP")))
    assert(geoIP ~> "vertices" ~> 4 ~> "countryName" === Some(S("Japan")))
  }

}

