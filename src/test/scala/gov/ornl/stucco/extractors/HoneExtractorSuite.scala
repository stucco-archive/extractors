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

    assert(hone ~> "vertices" ~> 0 ~> "_id" === Some(S("Mary")))
    assert(hone ~> "vertices" ~> 0 ~> "_type" === Some(S("vertex")))
    assert(hone ~> "vertices" ~> 0 ~> "source" === Some(S("Hone")))
    assert(hone ~> "vertices" ~> 0 ~> "vertexType" === Some(S("host")))

    assert(hone ~> "vertices" ~> 1 === None)
    assert(hone ~> "edges" ~> 0 === None)
  }

  test("parse 1 Hone element - missing: user, source_ip, dest_ip") {
    var text = """user,uid,process_pid,process_path,timestamp_epoch_ms,source_port,dest_port,ip_version,source_ip,dest_ip
,0,3476,/sbin/ttymon,1371770584002,63112,37632,0,,,
"""
    val node = morph.parser.CsvParser(text)
    val hone = HoneExtractor.extract(node, Map("hostName" -> "Mary"))

    assert(hone ~> "vertices" ~> 0 ~> "_id" === Some(S("Mary")))
    assert(hone ~> "vertices" ~> 0 ~> "_type" === Some(S("vertex")))
    assert(hone ~> "vertices" ~> 0 ~> "source" === Some(S("Hone")))
    assert(hone ~> "vertices" ~> 0 ~> "vertexType" === Some(S("host")))

    assert(hone ~> "vertices" ~> 1 ~> "_id" === Some(S("/sbin/ttymon")))
    assert(hone ~> "vertices" ~> 1 ~> "_type" === Some(S("vertex")))
    assert(hone ~> "vertices" ~> 1 ~> "source" === Some(S("Hone")))
    assert(hone ~> "vertices" ~> 1 ~> "vertexType" === Some(S("software")))
    assert(hone ~> "vertices" ~> 1 ~> "processPath" === Some(S("/sbin/ttymon")))
    assert(hone ~> "vertices" ~> 1 ~> "processPid" === Some(S("3476")))

    assert(hone ~> "vertices" ~> 2 ~> "_id" === Some(S("63112")))
    assert(hone ~> "vertices" ~> 2 ~> "_type" === Some(S("vertex")))
    assert(hone ~> "vertices" ~> 2 ~> "source" === Some(S("Hone")))
    assert(hone ~> "vertices" ~> 2 ~> "vertexType" === Some(S("port")))

    assert(hone ~> "vertices" ~> 3 ~> "_id" === Some(S("37632")))
    assert(hone ~> "vertices" ~> 3 ~> "_type" === Some(S("vertex")))
    assert(hone ~> "vertices" ~> 3 ~> "source" === Some(S("Hone")))
    assert(hone ~> "vertices" ~> 3 ~> "vertexType" === Some(S("port")))

    assert(hone ~> "vertices" ~> 4 ~> "_id" === Some(S("Mary:0")))
    assert(hone ~> "vertices" ~> 4 ~> "_type" === Some(S("vertex")))
    assert(hone ~> "vertices" ~> 4 ~> "source" === Some(S("Hone")))
    assert(hone ~> "vertices" ~> 4 ~> "vertexType" === Some(S("account")))
    assert(hone ~> "vertices" ~> 4 ~> "uid" === Some(S("0")))
    assert(hone ~> "vertices" ~> 4 ~> "userName" === Some(S("")))

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

  test("parse 1 Hone element - missing user") {
    var text = """user,uid,process_pid,process_path,timestamp_epoch_ms,source_port,dest_port,ip_version,source_ip,dest_ip
,1000,3144,/usr/lib/gvfs/gvfsd-smb,1371797596390,49870,6667,4,10.32.92.230,69.42.215.170,
"""
    val node = morph.parser.CsvParser(text)
    val hone = HoneExtractor.extract(node, Map("hostName" -> "Mary"))

    assert(hone ~> "vertices" ~> 0 ~> "_id" === Some(S("Mary")))
    assert(hone ~> "vertices" ~> 0 ~> "_type" === Some(S("vertex")))
    assert(hone ~> "vertices" ~> 0 ~> "source" === Some(S("Hone")))
    assert(hone ~> "vertices" ~> 0 ~> "vertexType" === Some(S("host")))

    assert(hone ~> "vertices" ~> 1 ~> "_id" === Some(S("/usr/lib/gvfs/gvfsd-smb")))
    assert(hone ~> "vertices" ~> 1 ~> "_type" === Some(S("vertex")))
    assert(hone ~> "vertices" ~> 1 ~> "source" === Some(S("Hone")))
    assert(hone ~> "vertices" ~> 1 ~> "vertexType" === Some(S("software")))
    assert(hone ~> "vertices" ~> 1 ~> "processPath" === Some(S("/usr/lib/gvfs/gvfsd-smb")))
    assert(hone ~> "vertices" ~> 1 ~> "processPid" === Some(S("3144")))

    assert(hone ~> "vertices" ~> 2 ~> "_id" === Some(S("10.32.92.230:49870")))
    assert(hone ~> "vertices" ~> 2 ~> "_type" === Some(S("vertex")))
    assert(hone ~> "vertices" ~> 2 ~> "source" === Some(S("Hone")))
    assert(hone ~> "vertices" ~> 2 ~> "vertexType" === Some(S("address")))

    assert(hone ~> "vertices" ~> 3 ~> "_id" === Some(S("69.42.215.170:6667")))
    assert(hone ~> "vertices" ~> 3 ~> "_type" === Some(S("vertex")))
    assert(hone ~> "vertices" ~> 3 ~> "source" === Some(S("Hone")))
    assert(hone ~> "vertices" ~> 3 ~> "vertexType" === Some(S("address")))

    assert(hone ~> "vertices" ~> 4 ~> "_id" === Some(S("10.32.92.230")))
    assert(hone ~> "vertices" ~> 4 ~> "_type" === Some(S("vertex")))
    assert(hone ~> "vertices" ~> 4 ~> "source" === Some(S("Hone")))
    assert(hone ~> "vertices" ~> 4 ~> "vertexType" === Some(S("IP")))

    assert(hone ~> "vertices" ~> 5 ~> "_id" === Some(S("69.42.215.170")))
    assert(hone ~> "vertices" ~> 5 ~> "_type" === Some(S("vertex")))
    assert(hone ~> "vertices" ~> 5 ~> "source" === Some(S("Hone")))
    assert(hone ~> "vertices" ~> 5 ~> "vertexType" === Some(S("IP")))

    assert(hone ~> "vertices" ~> 6 ~> "_id" === Some(S("49870")))
    assert(hone ~> "vertices" ~> 6 ~> "_type" === Some(S("vertex")))
    assert(hone ~> "vertices" ~> 6 ~> "source" === Some(S("Hone")))
    assert(hone ~> "vertices" ~> 6 ~> "vertexType" === Some(S("port")))

    assert(hone ~> "vertices" ~> 7 ~> "_id" === Some(S("6667")))
    assert(hone ~> "vertices" ~> 7 ~> "_type" === Some(S("vertex")))
    assert(hone ~> "vertices" ~> 7 ~> "source" === Some(S("Hone")))
    assert(hone ~> "vertices" ~> 7 ~> "vertexType" === Some(S("port")))

    assert(hone ~> "vertices" ~> 8 ~> "_id" === Some(S("10.32.92.230:49870::69.42.215.170:6667")))
    assert(hone ~> "vertices" ~> 8 ~> "_type" === Some(S("vertex")))
    assert(hone ~> "vertices" ~> 8 ~> "source" === Some(S("Hone")))
    assert(hone ~> "vertices" ~> 8 ~> "vertexType" === Some(S("flow")))
    assert(hone ~> "vertices" ~> 8 ~> "startTime" === Some(S("1371797596390")))

    assert(hone ~> "vertices" ~> 9 ~> "_id" === Some(S("Mary:1000")))
    assert(hone ~> "vertices" ~> 9 ~> "_type" === Some(S("vertex")))
    assert(hone ~> "vertices" ~> 9 ~> "source" === Some(S("Hone")))
    assert(hone ~> "vertices" ~> 9 ~> "vertexType" === Some(S("account")))
    assert(hone ~> "vertices" ~> 9 ~> "uid" === Some(S("1000")))
    assert(hone ~> "vertices" ~> 9 ~> "userName" === Some(S("")))

    assert(hone ~> "edges" ~> 0 ~> "_id" === Some(S("Mary_runs_/usr/lib/gvfs/gvfsd-smb")))
    assert(hone ~> "edges" ~> 0 ~> "_outV" === Some(S("Mary")))
    assert(hone ~> "edges" ~> 0 ~> "_inV" === Some(S("/usr/lib/gvfs/gvfsd-smb")))
    assert(hone ~> "edges" ~> 0 ~> "_type" === Some(S("edge")))
    assert(hone ~> "edges" ~> 0 ~> "_label" === Some(S("runs")))
    assert(hone ~> "edges" ~> 0 ~> "source" === Some(S("Hone")))
    assert(hone ~> "edges" ~> 0 ~> "outVType" === Some(S("host")))
    assert(hone ~> "edges" ~> 0 ~> "inVType" === Some(S("software")))

    assert(hone ~> "edges" ~> 1 ~> "_id" === Some(S("Mary_usesAddress_10.32.92.230:49870")))
    assert(hone ~> "edges" ~> 1 ~> "_outV" === Some(S("Mary")))
    assert(hone ~> "edges" ~> 1 ~> "_inV" === Some(S("10.32.92.230:49870")))
    assert(hone ~> "edges" ~> 1 ~> "_type" === Some(S("edge")))
    assert(hone ~> "edges" ~> 1 ~> "_label" === Some(S("usesAddress")))
    assert(hone ~> "edges" ~> 1 ~> "source" === Some(S("Hone")))
    assert(hone ~> "edges" ~> 1 ~> "outVType" === Some(S("host")))
    assert(hone ~> "edges" ~> 1 ~> "inVType" === Some(S("address")))

    assert(hone ~> "edges" ~> 2 ~> "_id" === Some(S("10.32.92.230:49870_hasIP_10.32.92.230")))
    assert(hone ~> "edges" ~> 2 ~> "_outV" === Some(S("10.32.92.230:49870")))
    assert(hone ~> "edges" ~> 2 ~> "_inV" === Some(S("10.32.92.230")))
    assert(hone ~> "edges" ~> 2 ~> "_type" === Some(S("edge")))
    assert(hone ~> "edges" ~> 2 ~> "_label" === Some(S("hasIP")))
    assert(hone ~> "edges" ~> 2 ~> "source" === Some(S("Hone")))
    assert(hone ~> "edges" ~> 2 ~> "outVType" === Some(S("address")))
    assert(hone ~> "edges" ~> 2 ~> "inVType" === Some(S("IP")))

    assert(hone ~> "edges" ~> 3 ~> "_id" === Some(S("69.42.215.170:6667_hasIP_69.42.215.170")))
    assert(hone ~> "edges" ~> 3 ~> "_outV" === Some(S("69.42.215.170:6667")))
    assert(hone ~> "edges" ~> 3 ~> "_inV" === Some(S("69.42.215.170")))
    assert(hone ~> "edges" ~> 3 ~> "_type" === Some(S("edge")))
    assert(hone ~> "edges" ~> 3 ~> "_label" === Some(S("hasIP")))
    assert(hone ~> "edges" ~> 3 ~> "source" === Some(S("Hone")))
    assert(hone ~> "edges" ~> 3 ~> "outVType" === Some(S("address")))
    assert(hone ~> "edges" ~> 3 ~> "inVType" === Some(S("IP")))

    assert(hone ~> "edges" ~> 4 ~> "_id" === Some(S("10.32.92.230:49870_hasPort_49870")))
    assert(hone ~> "edges" ~> 4 ~> "_outV" === Some(S("10.32.92.230:49870")))
    assert(hone ~> "edges" ~> 4 ~> "_inV" === Some(S("49870")))
    assert(hone ~> "edges" ~> 4 ~> "_type" === Some(S("edge")))
    assert(hone ~> "edges" ~> 4 ~> "_label" === Some(S("hasPort")))
    assert(hone ~> "edges" ~> 4 ~> "source" === Some(S("Hone")))
    assert(hone ~> "edges" ~> 4 ~> "outVType" === Some(S("address")))
    assert(hone ~> "edges" ~> 4 ~> "inVType" === Some(S("port")))

    assert(hone ~> "edges" ~> 5 ~> "_id" === Some(S("69.42.215.170:6667_hasPort_6667")))
    assert(hone ~> "edges" ~> 5 ~> "_outV" === Some(S("69.42.215.170:6667")))
    assert(hone ~> "edges" ~> 5 ~> "_inV" === Some(S("6667")))
    assert(hone ~> "edges" ~> 5 ~> "_type" === Some(S("edge")))
    assert(hone ~> "edges" ~> 5 ~> "_label" === Some(S("hasPort")))
    assert(hone ~> "edges" ~> 5 ~> "source" === Some(S("Hone")))
    assert(hone ~> "edges" ~> 5 ~> "outVType" === Some(S("address")))
    assert(hone ~> "edges" ~> 5 ~> "inVType" === Some(S("port")))

    assert(hone ~> "edges" ~> 6 ~> "_id" === Some(S("10.32.92.230:49870::69.42.215.170:6667_dstAddress_69.42.215.170:6667")))
    assert(hone ~> "edges" ~> 6 ~> "_outV" === Some(S("10.32.92.230:49870::69.42.215.170:6667")))
    assert(hone ~> "edges" ~> 6 ~> "_inV" === Some(S("69.42.215.170:6667")))
    assert(hone ~> "edges" ~> 6 ~> "_type" === Some(S("edge")))
    assert(hone ~> "edges" ~> 6 ~> "_label" === Some(S("dstAddress")))
    assert(hone ~> "edges" ~> 6 ~> "source" === Some(S("Hone")))
    assert(hone ~> "edges" ~> 6 ~> "outVType" === Some(S("flow")))
    assert(hone ~> "edges" ~> 6 ~> "inVType" === Some(S("address")))

    assert(hone ~> "edges" ~> 7 ~> "_id" === Some(S("10.32.92.230:49870::69.42.215.170:6667_srcAddress_10.32.92.230:49870")))
    assert(hone ~> "edges" ~> 7 ~> "_outV" === Some(S("10.32.92.230:49870::69.42.215.170:6667")))
    assert(hone ~> "edges" ~> 7 ~> "_inV" === Some(S("10.32.92.230:49870")))
    assert(hone ~> "edges" ~> 7 ~> "_type" === Some(S("edge")))
    assert(hone ~> "edges" ~> 7 ~> "_label" === Some(S("srcAddress")))
    assert(hone ~> "edges" ~> 7 ~> "source" === Some(S("Hone")))
    assert(hone ~> "edges" ~> 7 ~> "outVType" === Some(S("flow")))
    assert(hone ~> "edges" ~> 7 ~> "inVType" === Some(S("address")))

    assert(hone ~> "edges" ~> 8 ~> "_id" === Some(S("/usr/lib/gvfs/gvfsd-smb_hasFlow_10.32.92.230:49870::69.42.215.170:6667")))
    assert(hone ~> "edges" ~> 8 ~> "_outV" === Some(S("/usr/lib/gvfs/gvfsd-smb")))
    assert(hone ~> "edges" ~> 8 ~> "_inV" === Some(S("10.32.92.230:49870::69.42.215.170:6667")))
    assert(hone ~> "edges" ~> 8 ~> "_type" === Some(S("edge")))
    assert(hone ~> "edges" ~> 8 ~> "_label" === Some(S("hasFlow")))
    assert(hone ~> "edges" ~> 8 ~> "source" === Some(S("Hone")))
    assert(hone ~> "edges" ~> 8 ~> "outVType" === Some(S("software")))
    assert(hone ~> "edges" ~> 8 ~> "inVType" === Some(S("flow")))

    assert(hone ~> "edges" ~> 9 ~> "_id" === Some(S("/usr/lib/gvfs/gvfsd-smb_runsAs_Mary:1000")))
    assert(hone ~> "edges" ~> 9 ~> "_outV" === Some(S("/usr/lib/gvfs/gvfsd-smb")))
    assert(hone ~> "edges" ~> 9 ~> "_inV" === Some(S("Mary:1000")))
    assert(hone ~> "edges" ~> 9 ~> "_type" === Some(S("edge")))
    assert(hone ~> "edges" ~> 9 ~> "_label" === Some(S("runsAs")))
    assert(hone ~> "edges" ~> 9 ~> "source" === Some(S("Hone")))
    assert(hone ~> "edges" ~> 9 ~> "outVType" === Some(S("software")))
    assert(hone ~> "edges" ~> 9 ~> "inVType" === Some(S("account")))

  }

}

