import org.scalatest.FunSuite

import gov.ornl.stucco.morph.ast._
import gov.ornl.stucco.morph.ast.Implicits._
import gov.ornl.stucco.morph.ast.DSL._
import gov.ornl.stucco.morph.parser._
import gov.ornl.stucco.morph.parser.Interface._
import gov.ornl.stucco.morph.utils.Utils._

import gov.ornl.stucco.extractors._

import org.apache.commons.io._

class LoginEventExtractorSuite extends FunSuite {

  // to make testing easier
  val O = ObjectNode
  val A = ArrayNode
  val S = StringNode
  val N = NumberNode

  test("parse an empty line (no header)") {
    var text = """,,,,,,,,,,,,,,,,,,,,,
"""
    val node = CsvParser(text)
    val loginEvent = LoginEventExtractor.extract(node)

    assert(loginEvent ~> "vertices" ~> 0 === None)
    assert(loginEvent ~> "edges" ~> 0 === None)
  }

  test("parse an empty LoginEvent element (header included)") {
    var text = """date_time,hostname,login_software,status,user,from_ip
,,,,,,,,,,,,,,,,,,,,,
"""
    val node = CsvParser(text)
    val loginEvent = LoginEventExtractor.extract(node)

    assert(loginEvent ~> "vertices" ~> 0 === None)
    assert(loginEvent ~> "edges" ~> 0 === None)
  }

  test("parse 1 LoginEvent element") {
    var text = """Sep 24 15:11:03,StuccoHost,sshd,Accepted,StuccoUser,192.168.10.11
"""
//    Sep 24 15:12:03,OtherStuccoHost,sshd,Failed,OtherStuccoUser,192.168.10.12

    val node = CsvParser(text)
    val loginEvent = LoginEventExtractor.extract(node)

    //print(loginEvent)

    assert(loginEvent ~> "vertices" ~> 0 ~> "_id" === Some(S("StuccoHost")))
    assert(loginEvent ~> "vertices" ~> 0 ~> "name" === Some(S("StuccoHost")))
    assert(loginEvent ~> "vertices" ~> 0 ~> "description" === Some(S("StuccoHost")))
    assert(loginEvent ~> "vertices" ~> 0 ~> "_type" === Some(S("vertex")))
    assert(loginEvent ~> "vertices" ~> 0 ~> "source" === Some(S("LoginEvent")))
    assert(loginEvent ~> "vertices" ~> 0 ~> "vertexType" === Some(S("host")))

    assert(loginEvent ~> "vertices" ~> 1 ~> "_id" === Some(S("StuccoUser")))
    assert(loginEvent ~> "vertices" ~> 1 ~> "name" === Some(S("StuccoUser")))
    assert(loginEvent ~> "vertices" ~> 1 ~> "description" === Some(S("StuccoUser")))
    assert(loginEvent ~> "vertices" ~> 1 ~> "_type" === Some(S("vertex")))
    assert(loginEvent ~> "vertices" ~> 1 ~> "source" === Some(S("LoginEvent")))
    assert(loginEvent ~> "vertices" ~> 1 ~> "vertexType" === Some(S("account")))

    assert(loginEvent ~> "vertices" ~> 2 ~> "_id" === Some(S("sshd")))
    assert(loginEvent ~> "vertices" ~> 2 ~> "name" === Some(S("sshd")))
    assert(loginEvent ~> "vertices" ~> 2 ~> "description" === Some(S("sshd")))
    assert(loginEvent ~> "vertices" ~> 2 ~> "_type" === Some(S("vertex")))
    assert(loginEvent ~> "vertices" ~> 2 ~> "source" === Some(S("LoginEvent")))
    assert(loginEvent ~> "vertices" ~> 2 ~> "vertexType" === Some(S("software")))
    
    assert(loginEvent ~> "vertices" ~> 3 ~> "_id" === Some(S("192.168.10.11")))
    assert(loginEvent ~> "vertices" ~> 3 ~> "name" === Some(S("192.168.10.11")))
    assert(loginEvent ~> "vertices" ~> 3 ~> "description" === Some(S("192.168.10.11")))
    assert(loginEvent ~> "vertices" ~> 3 ~> "_type" === Some(S("vertex")))
    assert(loginEvent ~> "vertices" ~> 3 ~> "source" === Some(S("LoginEvent")))
    assert(loginEvent ~> "vertices" ~> 3 ~> "vertexType" === Some(S("ip")))

    assert(loginEvent ~> "vertices" ~> 4 ~> "_id" === Some(S("host_at_192.168.10.11")))
    assert(loginEvent ~> "vertices" ~> 4 ~> "name" === Some(S("host_at_192.168.10.11")))
    assert(loginEvent ~> "vertices" ~> 4 ~> "description" === Some(S("host at 192.168.10.11")))
    assert(loginEvent ~> "vertices" ~> 4 ~> "_type" === Some(S("vertex")))
    assert(loginEvent ~> "vertices" ~> 4 ~> "source" === Some(S("LoginEvent")))
    assert(loginEvent ~> "vertices" ~> 4 ~> "vertexType" === Some(S("host")))

    assert(loginEvent ~> "vertices" ~> 5 === None)

    assert(loginEvent ~> "edges" ~> 0 ~> "_id" === Some(S("StuccoUser_logsInTo_StuccoHost")))
    assert(loginEvent ~> "edges" ~> 0 ~> "_outV" === Some(S("StuccoUser")))
    assert(loginEvent ~> "edges" ~> 0 ~> "_inV" === Some(S("StuccoHost")))
    assert(loginEvent ~> "edges" ~> 0 ~> "_type" === Some(S("edge")))
    assert(loginEvent ~> "edges" ~> 0 ~> "_label" === Some(S("logsInTo")))
    assert(loginEvent ~> "edges" ~> 0 ~> "source" === Some(S("LoginEvent")))
    assert(loginEvent ~> "edges" ~> 0 ~> "outVType" === Some(S("account")))
    assert(loginEvent ~> "edges" ~> 0 ~> "inVType" === Some(S("host")))
    assert(loginEvent ~> "edges" ~> 0 ~> "timeStamp" === Some(N(1411571463000L)))
    assert(loginEvent ~> "edges" ~> 0 ~> "status" === Some(S("Accepted")))

    assert(loginEvent ~> "edges" ~> 1 ~> "_id" === Some(S("StuccoUser_logsInFrom_host_at_192.168.10.11")))
    assert(loginEvent ~> "edges" ~> 1 ~> "_outV" === Some(S("StuccoUser")))
    assert(loginEvent ~> "edges" ~> 1 ~> "_inV" === Some(S("host_at_192.168.10.11")))
    assert(loginEvent ~> "edges" ~> 1 ~> "_type" === Some(S("edge")))
    assert(loginEvent ~> "edges" ~> 1 ~> "_label" === Some(S("logsInFrom")))
    assert(loginEvent ~> "edges" ~> 1 ~> "source" === Some(S("LoginEvent")))
    assert(loginEvent ~> "edges" ~> 1 ~> "outVType" === Some(S("account")))
    assert(loginEvent ~> "edges" ~> 1 ~> "inVType" === Some(S("host")))
    assert(loginEvent ~> "edges" ~> 1 ~> "timeStamp" === Some(N(1411571463000L)))
    assert(loginEvent ~> "edges" ~> 1 ~> "status" === Some(S("Accepted")))

    assert(loginEvent ~> "edges" ~> 2 ~> "_id" === Some(S("host_at_192.168.10.11_hasIP_192.168.10.11")))
    assert(loginEvent ~> "edges" ~> 2 ~> "_outV" === Some(S("host_at_192.168.10.11")))
    assert(loginEvent ~> "edges" ~> 2 ~> "_inV" === Some(S("192.168.10.11")))
    assert(loginEvent ~> "edges" ~> 2 ~> "_type" === Some(S("edge")))
    assert(loginEvent ~> "edges" ~> 2 ~> "_label" === Some(S("hasIP")))
    assert(loginEvent ~> "edges" ~> 2 ~> "source" === Some(S("LoginEvent")))
    assert(loginEvent ~> "edges" ~> 2 ~> "outVType" === Some(S("host")))
    assert(loginEvent ~> "edges" ~> 2 ~> "inVType" === Some(S("ip")))

    assert(loginEvent ~> "edges" ~> 3 ~> "_id" === Some(S("StuccoHost_runs_sshd")))
    assert(loginEvent ~> "edges" ~> 3 ~> "_outV" === Some(S("StuccoHost")))
    assert(loginEvent ~> "edges" ~> 3 ~> "_inV" === Some(S("sshd")))
    assert(loginEvent ~> "edges" ~> 3 ~> "_type" === Some(S("edge")))
    assert(loginEvent ~> "edges" ~> 3 ~> "_label" === Some(S("runs")))
    assert(loginEvent ~> "edges" ~> 3 ~> "source" === Some(S("LoginEvent")))
    assert(loginEvent ~> "edges" ~> 3 ~> "outVType" === Some(S("host")))
    assert(loginEvent ~> "edges" ~> 3 ~> "inVType" === Some(S("software")))

    assert(loginEvent ~> "edges" ~> 4 === None)
  }
}

