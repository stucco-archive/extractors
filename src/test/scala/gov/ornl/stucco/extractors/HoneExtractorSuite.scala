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

  test("parse an empty Hone element") {
    var text = """user,uid,process_pid,process_path,timestamp_epoch_ms,source_port,dest_port,ip_version,source_ip,dest_ip
,,,,,,,,,,
"""
    val node = morph.parser.CsvParser(text)
    val hone = HoneExtractor.extract(node, Map("hostName" -> "Mary"))

    assert(hone ~> "vertices" ~> 0 === None)
    assert(hone ~> "edges" ~> 0 === None)
  }

  test("parse 1 Hone element - missing: user, source_ip, dest_ip") {
    var text = """user,uid,process_pid,process_path,timestamp_epoch_ms,source_port,dest_port,ip_version,source_ip,dest_ip
,0,3476,/sbin/ttymon,1371770584002,63112,37632,0,,,
"""
//,0,3476,/sbin/ttymon,1371770584005,0,0,4,127.0.0.1,127.0.0.1,
//,1000,3144,/usr/lib/gvfs/gvfsd-smb,1371797596390,49870,6667,4,10.32.92.230,69.42.215.170,
//"""
    val node = morph.parser.CsvParser(text)
    val hone = HoneExtractor.extract(node, Map("hostName" -> "Mary"))

    assert(hone ~> "vertices" ~> 0 ~> "_id" === Some(S("/sbin/ttymon")))
    assert(hone ~> "vertices" ~> 0 ~> "_type" === Some(S("vertex")))
    assert(hone ~> "vertices" ~> 0 ~> "source" === Some(S("Hone")))
    assert(hone ~> "vertices" ~> 0 ~> "vertexType" === Some(S("software")))
    assert(hone ~> "vertices" ~> 0 ~> "processPath" === Some(S("/sbin/ttymon")))
    assert(hone ~> "vertices" ~> 0 ~> "processPid" === Some(S("3476")))

    assert(hone ~> "vertices" ~> 1 ~> "_id" === Some(S("63112")))
    assert(hone ~> "vertices" ~> 1 ~> "_type" === Some(S("vertex")))
    assert(hone ~> "vertices" ~> 1 ~> "source" === Some(S("Hone")))
    assert(hone ~> "vertices" ~> 1 ~> "vertexType" === Some(S("port")))

    assert(hone ~> "vertices" ~> 2 ~> "_id" === Some(S("37632")))
    assert(hone ~> "vertices" ~> 2 ~> "_type" === Some(S("vertex")))
    assert(hone ~> "vertices" ~> 2 ~> "source" === Some(S("Hone")))
    assert(hone ~> "vertices" ~> 2 ~> "vertexType" === Some(S("port")))

    assert(hone ~> "vertices" ~> 3 ~> "_id" === Some(S("Mary:0")))
    assert(hone ~> "vertices" ~> 3 ~> "_type" === Some(S("vertex")))
    assert(hone ~> "vertices" ~> 3 ~> "source" === Some(S("Hone")))
    assert(hone ~> "vertices" ~> 3 ~> "vertexType" === Some(S("account")))
    assert(hone ~> "vertices" ~> 3 ~> "uid" === Some(S("0")))
    assert(hone ~> "vertices" ~> 3 ~> "userName" === Some(S("")))

    assert(hone ~> "edges" ~> 0 ~> "_id" === Some(S("Mary_runs_/sbin/ttymon")))
    assert(hone ~> "edges" ~> 0 ~> "_outV" === Some(S("Mary")))
    assert(hone ~> "edges" ~> 0 ~> "_inV" === Some(S("/sbin/ttymon")))
    assert(hone ~> "edges" ~> 0 ~> "_type" === Some(S("edge")))
    assert(hone ~> "edges" ~> 0 ~> "_label" === Some(S("runs")))
    assert(hone ~> "edges" ~> 0 ~> "source" === Some(S("Hone")))
    assert(hone ~> "edges" ~> 0 ~> "outVType" === Some(S("host")))
    assert(hone ~> "edges" ~> 0 ~> "inVType" === Some(S("software")))

    assert(hone ~> "edges" ~> 1 ~> "_id" === Some(S("/sbin/ttymon_runsAs_Mary:0")))
    assert(hone ~> "edges" ~> 1 ~> "_outV" === Some(S("/sbin/ttymon")))
    assert(hone ~> "edges" ~> 1 ~> "_inV" === Some(S("Mary:0")))
    assert(hone ~> "edges" ~> 1 ~> "_type" === Some(S("edge")))
    assert(hone ~> "edges" ~> 1 ~> "_label" === Some(S("runsAs")))
    assert(hone ~> "edges" ~> 1 ~> "source" === Some(S("Hone")))
    assert(hone ~> "edges" ~> 1 ~> "outVType" === Some(S("software")))
    assert(hone ~> "edges" ~> 1 ~> "inVType" === Some(S("account")))

  }

}

