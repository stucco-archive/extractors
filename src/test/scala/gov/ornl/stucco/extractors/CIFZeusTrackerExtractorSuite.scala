import org.scalatest.FunSuite

import gov.ornl.stucco.morph.ast._
import gov.ornl.stucco.morph.ast.Implicits._
import gov.ornl.stucco.morph.ast.DSL._
import gov.ornl.stucco.morph.parser._
import gov.ornl.stucco.morph.parser.Interface._
import gov.ornl.stucco.morph.utils.Utils._

import gov.ornl.stucco.extractors._

class CIFZeusTrackerExtractorSuite extends FunSuite {

  // to make testing easier
  val O = ObjectNode
  val A = ArrayNode
  val S = StringNode
  val N = NumberNode

  test("parse one comment") {
    var text = """# abuse.ch ZeuS IP blocklist
"""
    val node = CsvParser(text)
    val ips = CIFZeusTrackerExtractor(node)
    //print(ips)
    assert(ips ~> "vertices" ~> 0 === None)
  }

  test("parse one entry, with comment") {
    var text = """##############################################################################
# abuse.ch ZeuS IP blocklist                                                 #
#                                                                            #
# For questions please refer to https://zeustracker.abuse.ch/blocklist.php   #
##############################################################################

101.0.89.3
"""
    val node = CsvParser(text)
    val ips = CIFZeusTrackerExtractor(node)
    //print(ips)
    assert(ips ~> "vertices" ~> 0 ~> "_id" === Some(S("101.0.89.3")))
    assert(ips ~> "vertices" ~> 0 ~> "name" === Some(S("101.0.89.3")))
    assert(ips ~> "vertices" ~> 0 ~> "description" === Some(S("101.0.89.3")))
    assert(ips ~> "vertices" ~> 0 ~> "_type" === Some(S("vertex")))
    assert(ips ~> "vertices" ~> 0 ~> "source" === Some(S("zeustracker.abuse.ch")))
    assert(ips ~> "vertices" ~> 0 ~> "vertexType" === Some(S("IP")))
    assert(ips ~> "vertices" ~> 0 ~> "ipInt" === Some(N(1694521603)))
    assert(ips ~> "vertices" ~> 0 ~> "tags" === Some(S("botnet")))

    assert(ips ~> "vertices" ~> 1 === None)
  }

  test("parse several entries, with comment") {
    var text = """##############################################################################
# abuse.ch ZeuS IP blocklist                                                 #
#                                                                            #
# For questions please refer to https://zeustracker.abuse.ch/blocklist.php   #
##############################################################################

101.0.89.3
103.19.89.118
103.230.84.239
"""
    val node = CsvParser(text)
    val ips = CIFZeusTrackerExtractor(node)
    //print(ips)
    assert(ips ~> "vertices" ~> 0 ~> "_id" === Some(S("101.0.89.3")))
    assert(ips ~> "vertices" ~> 0 ~> "name" === Some(S("101.0.89.3")))
    assert(ips ~> "vertices" ~> 0 ~> "description" === Some(S("101.0.89.3")))
    assert(ips ~> "vertices" ~> 0 ~> "_type" === Some(S("vertex")))
    assert(ips ~> "vertices" ~> 0 ~> "source" === Some(S("zeustracker.abuse.ch")))
    assert(ips ~> "vertices" ~> 0 ~> "vertexType" === Some(S("IP")))
    assert(ips ~> "vertices" ~> 0 ~> "ipInt" === Some(N(1694521603)))
    assert(ips ~> "vertices" ~> 0 ~> "tags" === Some(S("botnet")))

    assert(ips ~> "vertices" ~> 1 ~> "_id" === Some(S("103.19.89.118")))
    assert(ips ~> "vertices" ~> 1 ~> "name" === Some(S("103.19.89.118")))
    assert(ips ~> "vertices" ~> 1 ~> "description" === Some(S("103.19.89.118")))
    assert(ips ~> "vertices" ~> 1 ~> "_type" === Some(S("vertex")))
    assert(ips ~> "vertices" ~> 1 ~> "source" === Some(S("zeustracker.abuse.ch")))
    assert(ips ~> "vertices" ~> 1 ~> "vertexType" === Some(S("IP")))
    assert(ips ~> "vertices" ~> 1 ~> "ipInt" === Some(N(1729321334)))
    assert(ips ~> "vertices" ~> 1 ~> "tags" === Some(S("botnet")))

    assert(ips ~> "vertices" ~> 2 ~> "_id" === Some(S("103.230.84.239")))
    assert(ips ~> "vertices" ~> 2 ~> "name" === Some(S("103.230.84.239")))
    assert(ips ~> "vertices" ~> 2 ~> "description" === Some(S("103.230.84.239")))
    assert(ips ~> "vertices" ~> 2 ~> "_type" === Some(S("vertex")))
    assert(ips ~> "vertices" ~> 2 ~> "source" === Some(S("zeustracker.abuse.ch")))
    assert(ips ~> "vertices" ~> 2 ~> "vertexType" === Some(S("IP")))
    assert(ips ~> "vertices" ~> 2 ~> "ipInt" === Some(N(1743148271)))
    assert(ips ~> "vertices" ~> 2 ~> "tags" === Some(S("botnet")))

    assert(ips ~> "vertices" ~> 3 === None)
  }

}

