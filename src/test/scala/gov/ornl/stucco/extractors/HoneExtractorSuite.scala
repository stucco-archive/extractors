import org.scalatest.FunSuite

import gov.ornl.stucco.morph.ast._
import gov.ornl.stucco.morph.ast.Implicits._
import gov.ornl.stucco.morph.ast.DSL._
import gov.ornl.stucco.morph.parser._
import gov.ornl.stucco.morph.parser.Interface._
import gov.ornl.stucco.morph.utils.Utils._

import gov.ornl.stucco.extractors._

import org.apache.commons.io._

class HoneExtractorSuite extends FunSuite {

  // to make testing easier
  val O = ObjectNode
  val A = ArrayNode
  val S = StringNode
  val N = NumberNode

  test("parse an empty Hone element (no header)") {
    var text = """,,,,,,,,,,,,,,,,,,,,,
"""
    val node = CsvParser(text)
    val hone = HoneExtractor.extract(node, Map("hostName" -> "Mary"))

    assert(hone ~> "vertices" ~> 0 ~> "_id" === Some(S("Mary")))
    assert(hone ~> "vertices" ~> 0 ~> "_type" === Some(S("vertex")))
    assert(hone ~> "vertices" ~> 0 ~> "source" === Some(S("Hone")))
    assert(hone ~> "vertices" ~> 0 ~> "vertexType" === Some(S("host")))

    assert(hone ~> "vertices" ~> 1 === None)
    assert(hone ~> "edges" ~> 0 === None)
  }

  test("parse an empty Hone element (header included)") {
    var text = """user,uid,proc_pid,proc_ppid,path,argv,conn_id,timestamp_epoch_ms,source_port,dest_port,ip_version,source_ip,dest_ip,byte_cnt,packet_cnt
,,,,,,,,,,,,,,,,,,,,,
"""
    val node = CsvParser(text)
    val hone = HoneExtractor.extract(node, Map("hostName" -> "Mary"))

    assert(hone ~> "vertices" ~> 0 ~> "_id" === Some(S("Mary")))
    assert(hone ~> "vertices" ~> 0 ~> "name" === Some(S("Mary")))
    assert(hone ~> "vertices" ~> 0 ~> "description" === Some(S("Mary")))
    assert(hone ~> "vertices" ~> 0 ~> "_type" === Some(S("vertex")))
    assert(hone ~> "vertices" ~> 0 ~> "source" === Some(S("Hone")))
    assert(hone ~> "vertices" ~> 0 ~> "vertexType" === Some(S("host")))

    assert(hone ~> "vertices" ~> 1 === None)
    assert(hone ~> "edges" ~> 0 === None)
  }

    test("parse an empty Hone element (using java map)") {
    var text = """user,uid,proc_pid,proc_ppid,path,argv,conn_id,timestamp_epoch_ms,source_port,dest_port,ip_version,source_ip,dest_ip,byte_cnt,packet_cnt
,,,,,,,,,,,,,,,,,,,,,
"""
    var map = new java.util.HashMap[java.lang.String, java.lang.String]
    //map += "hostName" -> "Mary"
    map.put("hostName", "Mary")
    val node = CsvParser(text)
    val hone = HoneExtractor.extract(node, map.asInstanceOf[java.util.Map[java.lang.String, java.lang.String]])

    assert(hone ~> "vertices" ~> 0 ~> "_id" === Some(S("Mary")))
    assert(hone ~> "vertices" ~> 0 ~> "name" === Some(S("Mary")))
    assert(hone ~> "vertices" ~> 0 ~> "description" === Some(S("Mary")))
    assert(hone ~> "vertices" ~> 0 ~> "_type" === Some(S("vertex")))
    assert(hone ~> "vertices" ~> 0 ~> "source" === Some(S("Hone")))
    assert(hone ~> "vertices" ~> 0 ~> "vertexType" === Some(S("host")))

    assert(hone ~> "vertices" ~> 1 === None)
    assert(hone ~> "edges" ~> 0 === None)
  }

  test("parse 1 Hone element - missing: user, argv, source_ip, dest_ip") {
    var text = """,0,3476,3470,/sbin/ttymon,,10000,1371770584002,63112,37632,0,,,,
"""
    val node = CsvParser(text)
    val hone = HoneExtractor.extract(node, Map("hostName" -> "Mary"))

    assert(hone ~> "vertices" ~> 0 ~> "_id" === Some(S("Mary")))
    assert(hone ~> "vertices" ~> 0 ~> "name" === Some(S("Mary")))
    assert(hone ~> "vertices" ~> 0 ~> "description" === Some(S("Mary")))
    assert(hone ~> "vertices" ~> 0 ~> "_type" === Some(S("vertex")))
    assert(hone ~> "vertices" ~> 0 ~> "source" === Some(S("Hone")))
    assert(hone ~> "vertices" ~> 0 ~> "vertexType" === Some(S("host")))

    assert(hone ~> "vertices" ~> 1 ~> "_id" === Some(S("/sbin/ttymon")))
    assert(hone ~> "vertices" ~> 1 ~> "name" === Some(S("/sbin/ttymon")))
    assert(hone ~> "vertices" ~> 1 ~> "description" === Some(S("/sbin/ttymon")))
    assert(hone ~> "vertices" ~> 1 ~> "_type" === Some(S("vertex")))
    assert(hone ~> "vertices" ~> 1 ~> "source" === Some(S("Hone")))
    assert(hone ~> "vertices" ~> 1 ~> "vertexType" === Some(S("software")))
    assert(hone ~> "vertices" ~> 1 ~> "processPath" === Some(S("/sbin/ttymon")))
    assert(hone ~> "vertices" ~> 1 ~> "processPid" === Some(S("3476")))
    assert(hone ~> "vertices" ~> 1 ~> "processPpid" === Some(S("3470")))
    assert(hone ~> "vertices" ~> 1 ~> "processArgs" === Some(S("")))

    assert(hone ~> "vertices" ~> 2 ~> "_id" === Some(S("63112")))
    assert(hone ~> "vertices" ~> 2 ~> "name" === Some(S("63112")))
    assert(hone ~> "vertices" ~> 2 ~> "description" === Some(S("63112")))
    assert(hone ~> "vertices" ~> 2 ~> "_type" === Some(S("vertex")))
    assert(hone ~> "vertices" ~> 2 ~> "source" === Some(S("Hone")))
    assert(hone ~> "vertices" ~> 2 ~> "vertexType" === Some(S("port")))

    assert(hone ~> "vertices" ~> 3 ~> "_id" === Some(S("37632")))
    assert(hone ~> "vertices" ~> 3 ~> "name" === Some(S("37632")))
    assert(hone ~> "vertices" ~> 3 ~> "description" === Some(S("37632")))
    assert(hone ~> "vertices" ~> 3 ~> "_type" === Some(S("vertex")))
    assert(hone ~> "vertices" ~> 3 ~> "source" === Some(S("Hone")))
    assert(hone ~> "vertices" ~> 3 ~> "vertexType" === Some(S("port")))

    assert(hone ~> "vertices" ~> 4 ~> "_id" === Some(S("Mary:0")))
    assert(hone ~> "vertices" ~> 4 ~> "name" === Some(S("Mary:0")))
    assert(hone ~> "vertices" ~> 4 ~> "description" === Some(S("uid 0 on host Mary")))
    assert(hone ~> "vertices" ~> 4 ~> "_type" === Some(S("vertex")))
    assert(hone ~> "vertices" ~> 4 ~> "source" === Some(S("Hone")))
    assert(hone ~> "vertices" ~> 4 ~> "vertexType" === Some(S("account")))
    assert(hone ~> "vertices" ~> 4 ~> "uid" === Some(S("0")))
    assert(hone ~> "vertices" ~> 4 ~> "userName" === Some(S("")))

    assert(hone ~> "edges" ~> 0 ~> "_id" === Some(S("Mary_runs_/sbin/ttymon")))
    assert(hone ~> "edges" ~> 0 ~> "description" === Some(S("Mary runs /sbin/ttymon")))
    assert(hone ~> "edges" ~> 0 ~> "_outV" === Some(S("Mary")))
    assert(hone ~> "edges" ~> 0 ~> "_inV" === Some(S("/sbin/ttymon")))
    assert(hone ~> "edges" ~> 0 ~> "_type" === Some(S("edge")))
    assert(hone ~> "edges" ~> 0 ~> "_label" === Some(S("runs")))
    assert(hone ~> "edges" ~> 0 ~> "source" === Some(S("Hone")))
    assert(hone ~> "edges" ~> 0 ~> "outVType" === Some(S("host")))
    assert(hone ~> "edges" ~> 0 ~> "inVType" === Some(S("software")))

    assert(hone ~> "edges" ~> 1 ~> "_id" === Some(S("/sbin/ttymon_runsAs_Mary:0")))
    assert(hone ~> "edges" ~> 1 ~> "description" === Some(S("/sbin/ttymon runs as uid 0 on host Mary")))
    assert(hone ~> "edges" ~> 1 ~> "_outV" === Some(S("/sbin/ttymon")))
    assert(hone ~> "edges" ~> 1 ~> "_inV" === Some(S("Mary:0")))
    assert(hone ~> "edges" ~> 1 ~> "_type" === Some(S("edge")))
    assert(hone ~> "edges" ~> 1 ~> "_label" === Some(S("runsAs")))
    assert(hone ~> "edges" ~> 1 ~> "source" === Some(S("Hone")))
    assert(hone ~> "edges" ~> 1 ~> "outVType" === Some(S("software")))
    assert(hone ~> "edges" ~> 1 ~> "inVType" === Some(S("account")))
  }

  test("parse 1 Hone element - missing user") {
    var text = """user,uid,proc_pid,proc_ppid,path,argv,conn_id,timestamp_epoch_ms,source_port,dest_port,ip_version,source_ip,dest_ip,byte_cnt,packet_cnt
,1000,3144,3140,/usr/lib/gvfs/gvfsd-smb,test,10000,1371797596390,49870,6667,4,10.32.92.230,69.42.215.170,2068,2
"""
    val node = CsvParser(text)
    val hone = HoneExtractor.extract(node, Map("hostName" -> "Mary"))

    assert(hone ~> "vertices" ~> 0 ~> "_id" === Some(S("Mary")))
    assert(hone ~> "vertices" ~> 0 ~> "name" === Some(S("Mary")))
    assert(hone ~> "vertices" ~> 0 ~> "description" === Some(S("Mary")))
    assert(hone ~> "vertices" ~> 0 ~> "_type" === Some(S("vertex")))
    assert(hone ~> "vertices" ~> 0 ~> "source" === Some(S("Hone")))
    assert(hone ~> "vertices" ~> 0 ~> "vertexType" === Some(S("host")))

    assert(hone ~> "vertices" ~> 1 ~> "_id" === Some(S("/usr/lib/gvfs/gvfsd-smb")))
    assert(hone ~> "vertices" ~> 1 ~> "name" === Some(S("/usr/lib/gvfs/gvfsd-smb")))
    assert(hone ~> "vertices" ~> 1 ~> "description" === Some(S("/usr/lib/gvfs/gvfsd-smb")))
    assert(hone ~> "vertices" ~> 1 ~> "_type" === Some(S("vertex")))
    assert(hone ~> "vertices" ~> 1 ~> "source" === Some(S("Hone")))
    assert(hone ~> "vertices" ~> 1 ~> "vertexType" === Some(S("software")))
    assert(hone ~> "vertices" ~> 1 ~> "processPath" === Some(S("/usr/lib/gvfs/gvfsd-smb")))
    assert(hone ~> "vertices" ~> 1 ~> "processPid" === Some(S("3144")))
    assert(hone ~> "vertices" ~> 1 ~> "processPpid" === Some(S("3140")))
    assert(hone ~> "vertices" ~> 1 ~> "processArgs" === Some(S("test")))

    assert(hone ~> "vertices" ~> 2 ~> "_id" === Some(S("10.32.92.230:49870")))
    assert(hone ~> "vertices" ~> 2 ~> "name" === Some(S("10.32.92.230:49870")))
    assert(hone ~> "vertices" ~> 2 ~> "description" === Some(S("10.32.92.230, port 49870")))
    assert(hone ~> "vertices" ~> 2 ~> "_type" === Some(S("vertex")))
    assert(hone ~> "vertices" ~> 2 ~> "source" === Some(S("Hone")))
    assert(hone ~> "vertices" ~> 2 ~> "vertexType" === Some(S("address")))

    assert(hone ~> "vertices" ~> 3 ~> "_id" === Some(S("69.42.215.170:6667")))
    assert(hone ~> "vertices" ~> 3 ~> "name" === Some(S("69.42.215.170:6667")))
    assert(hone ~> "vertices" ~> 3 ~> "description" === Some(S("69.42.215.170, port 6667")))
    assert(hone ~> "vertices" ~> 3 ~> "_type" === Some(S("vertex")))
    assert(hone ~> "vertices" ~> 3 ~> "source" === Some(S("Hone")))
    assert(hone ~> "vertices" ~> 3 ~> "vertexType" === Some(S("address")))

    assert(hone ~> "vertices" ~> 4 ~> "_id" === Some(S("10.32.92.230")))
    assert(hone ~> "vertices" ~> 4 ~> "name" === Some(S("10.32.92.230")))
    assert(hone ~> "vertices" ~> 4 ~> "description" === Some(S("10.32.92.230")))
    assert(hone ~> "vertices" ~> 4 ~> "_type" === Some(S("vertex")))
    assert(hone ~> "vertices" ~> 4 ~> "source" === Some(S("Hone")))
    assert(hone ~> "vertices" ~> 4 ~> "vertexType" === Some(S("IP")))

    assert(hone ~> "vertices" ~> 5 ~> "_id" === Some(S("69.42.215.170")))
    assert(hone ~> "vertices" ~> 5 ~> "name" === Some(S("69.42.215.170")))
    assert(hone ~> "vertices" ~> 5 ~> "description" === Some(S("69.42.215.170")))
    assert(hone ~> "vertices" ~> 5 ~> "_type" === Some(S("vertex")))
    assert(hone ~> "vertices" ~> 5 ~> "source" === Some(S("Hone")))
    assert(hone ~> "vertices" ~> 5 ~> "vertexType" === Some(S("IP")))

    assert(hone ~> "vertices" ~> 6 ~> "_id" === Some(S("49870")))
    assert(hone ~> "vertices" ~> 6 ~> "name" === Some(S("49870")))
    assert(hone ~> "vertices" ~> 6 ~> "description" === Some(S("49870")))
    assert(hone ~> "vertices" ~> 6 ~> "_type" === Some(S("vertex")))
    assert(hone ~> "vertices" ~> 6 ~> "source" === Some(S("Hone")))
    assert(hone ~> "vertices" ~> 6 ~> "vertexType" === Some(S("port")))

    assert(hone ~> "vertices" ~> 7 ~> "_id" === Some(S("6667")))
    assert(hone ~> "vertices" ~> 7 ~> "name" === Some(S("6667")))
    assert(hone ~> "vertices" ~> 7 ~> "description" === Some(S("6667")))
    assert(hone ~> "vertices" ~> 7 ~> "_type" === Some(S("vertex")))
    assert(hone ~> "vertices" ~> 7 ~> "source" === Some(S("Hone")))
    assert(hone ~> "vertices" ~> 7 ~> "vertexType" === Some(S("port")))

    assert(hone ~> "vertices" ~> 8 ~> "_id" === Some(S("10.32.92.230:49870::69.42.215.170:6667")))
    assert(hone ~> "vertices" ~> 8 ~> "name" === Some(S("10.32.92.230:49870::69.42.215.170:6667")))
    assert(hone ~> "vertices" ~> 8 ~> "description" === Some(S("10.32.92.230, port 49870 to 69.42.215.170, port 6667")))
    assert(hone ~> "vertices" ~> 8 ~> "_type" === Some(S("vertex")))
    assert(hone ~> "vertices" ~> 8 ~> "source" === Some(S("Hone")))
    assert(hone ~> "vertices" ~> 8 ~> "vertexType" === Some(S("flow")))
    assert(hone ~> "vertices" ~> 8 ~> "startTime" === Some(N(1371797596390L)))
    assert(hone ~> "vertices" ~> 8 ~> "totalPkts" === Some(S("2")))
    assert(hone ~> "vertices" ~> 8 ~> "totalBytes" === Some(S("2068")))

    assert(hone ~> "vertices" ~> 9 ~> "_id" === Some(S("Mary:1000")))
    assert(hone ~> "vertices" ~> 9 ~> "name" === Some(S("Mary:1000")))
    assert(hone ~> "vertices" ~> 9 ~> "description" === Some(S("uid 1000 on host Mary")))
    assert(hone ~> "vertices" ~> 9 ~> "_type" === Some(S("vertex")))
    assert(hone ~> "vertices" ~> 9 ~> "source" === Some(S("Hone")))
    assert(hone ~> "vertices" ~> 9 ~> "vertexType" === Some(S("account")))
    assert(hone ~> "vertices" ~> 9 ~> "uid" === Some(S("1000")))
    assert(hone ~> "vertices" ~> 9 ~> "userName" === Some(S("")))

    assert(hone ~> "edges" ~> 0 ~> "_id" === Some(S("Mary_runs_/usr/lib/gvfs/gvfsd-smb")))
    assert(hone ~> "edges" ~> 0 ~> "description" === Some(S("Mary runs /usr/lib/gvfs/gvfsd-smb")))
    assert(hone ~> "edges" ~> 0 ~> "_outV" === Some(S("Mary")))
    assert(hone ~> "edges" ~> 0 ~> "_inV" === Some(S("/usr/lib/gvfs/gvfsd-smb")))
    assert(hone ~> "edges" ~> 0 ~> "_type" === Some(S("edge")))
    assert(hone ~> "edges" ~> 0 ~> "_label" === Some(S("runs")))
    assert(hone ~> "edges" ~> 0 ~> "source" === Some(S("Hone")))
    assert(hone ~> "edges" ~> 0 ~> "outVType" === Some(S("host")))
    assert(hone ~> "edges" ~> 0 ~> "inVType" === Some(S("software")))

    assert(hone ~> "edges" ~> 1 ~> "_id" === Some(S("Mary_usesAddress_10.32.92.230:49870")))
    assert(hone ~> "edges" ~> 1 ~> "description" === Some(S("Mary uses address 10.32.92.230, port 49870")))
    assert(hone ~> "edges" ~> 1 ~> "_outV" === Some(S("Mary")))
    assert(hone ~> "edges" ~> 1 ~> "_inV" === Some(S("10.32.92.230:49870")))
    assert(hone ~> "edges" ~> 1 ~> "_type" === Some(S("edge")))
    assert(hone ~> "edges" ~> 1 ~> "_label" === Some(S("usesAddress")))
    assert(hone ~> "edges" ~> 1 ~> "source" === Some(S("Hone")))
    assert(hone ~> "edges" ~> 1 ~> "outVType" === Some(S("host")))
    assert(hone ~> "edges" ~> 1 ~> "inVType" === Some(S("address")))

    assert(hone ~> "edges" ~> 2 ~> "_id" === Some(S("10.32.92.230:49870_hasIP_10.32.92.230")))
    assert(hone ~> "edges" ~> 2 ~> "description" === Some(S("10.32.92.230, port 49870 has IP 10.32.92.230")))
    assert(hone ~> "edges" ~> 2 ~> "_outV" === Some(S("10.32.92.230:49870")))
    assert(hone ~> "edges" ~> 2 ~> "_inV" === Some(S("10.32.92.230")))
    assert(hone ~> "edges" ~> 2 ~> "_type" === Some(S("edge")))
    assert(hone ~> "edges" ~> 2 ~> "_label" === Some(S("hasIP")))
    assert(hone ~> "edges" ~> 2 ~> "source" === Some(S("Hone")))
    assert(hone ~> "edges" ~> 2 ~> "outVType" === Some(S("address")))
    assert(hone ~> "edges" ~> 2 ~> "inVType" === Some(S("IP")))

    assert(hone ~> "edges" ~> 3 ~> "_id" === Some(S("69.42.215.170:6667_hasIP_69.42.215.170")))
    assert(hone ~> "edges" ~> 3 ~> "description" === Some(S("69.42.215.170, port 6667 has IP 69.42.215.170")))
    assert(hone ~> "edges" ~> 3 ~> "_outV" === Some(S("69.42.215.170:6667")))
    assert(hone ~> "edges" ~> 3 ~> "_inV" === Some(S("69.42.215.170")))
    assert(hone ~> "edges" ~> 3 ~> "_type" === Some(S("edge")))
    assert(hone ~> "edges" ~> 3 ~> "_label" === Some(S("hasIP")))
    assert(hone ~> "edges" ~> 3 ~> "source" === Some(S("Hone")))
    assert(hone ~> "edges" ~> 3 ~> "outVType" === Some(S("address")))
    assert(hone ~> "edges" ~> 3 ~> "inVType" === Some(S("IP")))

    assert(hone ~> "edges" ~> 4 ~> "_id" === Some(S("10.32.92.230:49870_hasPort_49870")))
    assert(hone ~> "edges" ~> 4 ~> "description" === Some(S("10.32.92.230, port 49870 has port 49870")))
    assert(hone ~> "edges" ~> 4 ~> "_outV" === Some(S("10.32.92.230:49870")))
    assert(hone ~> "edges" ~> 4 ~> "_inV" === Some(S("49870")))
    assert(hone ~> "edges" ~> 4 ~> "_type" === Some(S("edge")))
    assert(hone ~> "edges" ~> 4 ~> "_label" === Some(S("hasPort")))
    assert(hone ~> "edges" ~> 4 ~> "source" === Some(S("Hone")))
    assert(hone ~> "edges" ~> 4 ~> "outVType" === Some(S("address")))
    assert(hone ~> "edges" ~> 4 ~> "inVType" === Some(S("port")))

    assert(hone ~> "edges" ~> 5 ~> "_id" === Some(S("69.42.215.170:6667_hasPort_6667")))
    assert(hone ~> "edges" ~> 5 ~> "description" === Some(S("69.42.215.170, port 6667 has port 6667")))
    assert(hone ~> "edges" ~> 5 ~> "_outV" === Some(S("69.42.215.170:6667")))
    assert(hone ~> "edges" ~> 5 ~> "_inV" === Some(S("6667")))
    assert(hone ~> "edges" ~> 5 ~> "_type" === Some(S("edge")))
    assert(hone ~> "edges" ~> 5 ~> "_label" === Some(S("hasPort")))
    assert(hone ~> "edges" ~> 5 ~> "source" === Some(S("Hone")))
    assert(hone ~> "edges" ~> 5 ~> "outVType" === Some(S("address")))
    assert(hone ~> "edges" ~> 5 ~> "inVType" === Some(S("port")))

    assert(hone ~> "edges" ~> 6 ~> "_id" === Some(S("10.32.92.230:49870::69.42.215.170:6667_dstAddress_69.42.215.170:6667")))
    assert(hone ~> "edges" ~> 6 ~> "description" === Some(S("10.32.92.230, port 49870 to 69.42.215.170, port 6667 has destination address 69.42.215.170, port 6667")))
    assert(hone ~> "edges" ~> 6 ~> "_outV" === Some(S("10.32.92.230:49870::69.42.215.170:6667")))
    assert(hone ~> "edges" ~> 6 ~> "_inV" === Some(S("69.42.215.170:6667")))
    assert(hone ~> "edges" ~> 6 ~> "_type" === Some(S("edge")))
    assert(hone ~> "edges" ~> 6 ~> "_label" === Some(S("dstAddress")))
    assert(hone ~> "edges" ~> 6 ~> "source" === Some(S("Hone")))
    assert(hone ~> "edges" ~> 6 ~> "outVType" === Some(S("flow")))
    assert(hone ~> "edges" ~> 6 ~> "inVType" === Some(S("address")))

    assert(hone ~> "edges" ~> 7 ~> "_id" === Some(S("10.32.92.230:49870::69.42.215.170:6667_srcAddress_10.32.92.230:49870")))
    assert(hone ~> "edges" ~> 7 ~> "description" === Some(S("10.32.92.230, port 49870 to 69.42.215.170, port 6667 has source address 10.32.92.230, port 49870")))
    assert(hone ~> "edges" ~> 7 ~> "_outV" === Some(S("10.32.92.230:49870::69.42.215.170:6667")))
    assert(hone ~> "edges" ~> 7 ~> "_inV" === Some(S("10.32.92.230:49870")))
    assert(hone ~> "edges" ~> 7 ~> "_type" === Some(S("edge")))
    assert(hone ~> "edges" ~> 7 ~> "_label" === Some(S("srcAddress")))
    assert(hone ~> "edges" ~> 7 ~> "source" === Some(S("Hone")))
    assert(hone ~> "edges" ~> 7 ~> "outVType" === Some(S("flow")))
    assert(hone ~> "edges" ~> 7 ~> "inVType" === Some(S("address")))

    assert(hone ~> "edges" ~> 8 ~> "_id" === Some(S("/usr/lib/gvfs/gvfsd-smb_hasFlow_10.32.92.230:49870::69.42.215.170:6667")))
    assert(hone ~> "edges" ~> 8 ~> "description" === Some(S("/usr/lib/gvfs/gvfsd-smb has flow 10.32.92.230, port 49870 to 69.42.215.170, port 6667")))
    assert(hone ~> "edges" ~> 8 ~> "_outV" === Some(S("/usr/lib/gvfs/gvfsd-smb")))
    assert(hone ~> "edges" ~> 8 ~> "_inV" === Some(S("10.32.92.230:49870::69.42.215.170:6667")))
    assert(hone ~> "edges" ~> 8 ~> "_type" === Some(S("edge")))
    assert(hone ~> "edges" ~> 8 ~> "_label" === Some(S("hasFlow")))
    assert(hone ~> "edges" ~> 8 ~> "source" === Some(S("Hone")))
    assert(hone ~> "edges" ~> 8 ~> "outVType" === Some(S("software")))
    assert(hone ~> "edges" ~> 8 ~> "inVType" === Some(S("flow")))

    assert(hone ~> "edges" ~> 9 ~> "_id" === Some(S("/usr/lib/gvfs/gvfsd-smb_runsAs_Mary:1000")))
    assert(hone ~> "edges" ~> 9 ~> "description" === Some(S("/usr/lib/gvfs/gvfsd-smb runs as uid 1000 on host Mary")))
    assert(hone ~> "edges" ~> 9 ~> "_outV" === Some(S("/usr/lib/gvfs/gvfsd-smb")))
    assert(hone ~> "edges" ~> 9 ~> "_inV" === Some(S("Mary:1000")))
    assert(hone ~> "edges" ~> 9 ~> "_type" === Some(S("edge")))
    assert(hone ~> "edges" ~> 9 ~> "_label" === Some(S("runsAs")))
    assert(hone ~> "edges" ~> 9 ~> "source" === Some(S("Hone")))
    assert(hone ~> "edges" ~> 9 ~> "outVType" === Some(S("software")))
    assert(hone ~> "edges" ~> 9 ~> "inVType" === Some(S("account")))

  }
/*
  test("parse a >15M csv from file") {
    val copyCount = 15
    val text = scala.io.Source.fromFile("testData/hone.csv").getLines mkString "\n"
    var longerText = ""
    for (i <- 1 to copyCount) { longerText = longerText + text + '\n' }
    val hone = HoneExtractor.extract(CsvParser(longerText), Map("hostName" -> "Mary"))
    assert(hone.get("vertices").asList.length === 1722345 )
  }
*/
  /*
  //gives error: java.lang.OutOfMemoryError: GC overhead limit exceeded
  test("parse a >50M csv from file") {
    val text = scala.io.Source.fromFile("testData/hone.csv").getLines mkString "\n"
    val moreText = text + '\n' + text + '\n' + text + '\n' + text + '\n' + text + '\n' + text + '\n' + text + '\n' + text + '\n' + text + '\n' + text
    val evenMoreText = moreText + '\n' + moreText + '\n' + moreText + '\n' + moreText + '\n' + moreText// + '\n' + moreText + '\n' + moreText + '\n' + moreText + '\n' + moreText + '\n' + moreText
    val hone = HoneExtractor.extract(CsvParser(evenMoreText), Map("hostName" -> "Mary"))
    //print(hone)
    assert(hone != null ) //TODO ?
  }*/

}

