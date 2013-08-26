import org.scalatest.FunSuite

import morph.ast._
import morph.ast.Implicits._
import morph.ast.DSL._
import morph.parser._
import morph.parser.Interface._
import morph.utils.Utils._

import gov.ornl.stucco.extractors._

class HoneExtractorSuite extends FunSuite {

  // to make testing easier
  val O = ObjectNode
  val A = ArrayNode
  val S = StringNode
  val N = NumberNode

  test("parse 3 Hone elements") {
    var text = """user,uid,process_pid,process_path,timestamp_epoch_ms,source_port,dest_port,ip_version,source_ip,dest_ip
,0,3476,/sbin/ttymon,1371770584002,63112,37632,0,,,
,0,3476,/sbin/ttymon,1371770584005,0,0,4,127.0.0.1,127.0.0.1,
,1000,3144,/usr/lib/gvfs/gvfsd-smb,1371797596390,49870,6667,4,10.32.92.230,69.42.215.170,
"""
    val node = morph.parser.CsvParser(text)
    val hone = HoneExtractor.extract(node, Map("hostName" -> "Mary"))
    //print(hone)
    //assert(geoIP ~> "vertices" ~> 0 ~> "_id" === Some(S("1.0.0.0_through_1.0.0.255")))
    //assert(geoIP ~> "vertices" ~> 0 ~> "_type" === Some(S("vertex")))
    //assert(geoIP ~> "vertices" ~> 0 ~> "source" === Some(S("Hone")))
    //assert(geoIP ~> "vertices" ~> 0 ~> "vertexType" === Some(S("addressRange")))


  }

}

