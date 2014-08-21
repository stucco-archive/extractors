import org.scalatest.FunSuite

import gov.ornl.stucco.morph.ast._
import gov.ornl.stucco.morph.ast.Implicits._
import gov.ornl.stucco.morph.ast.DSL._
import gov.ornl.stucco.morph.parser._
import gov.ornl.stucco.morph.parser.Interface._
import gov.ornl.stucco.morph.utils.Utils._

import gov.ornl.stucco.extractors._

class MetasploitExtractorSuite extends FunSuite {

  // to make testing easier
  val O = ObjectNode
  val A = ArrayNode
  val S = StringNode
  val N = NumberNode

  test("parse an empty Metasploit element") {
    var text = """"id","mtime","file","mtype","refname","fullname","name","rank","description","license","privileged","disclosure_date","default_target","default_action","stance","ready","ref_names","author_names"
-1,,,,,-1,,,,,,,,,,,,
"""
    val node = gov.ornl.stucco.morph.parser.CsvParser(text)
    val msf = MetasploitExtractor.extract(node)

    assert(msf ~> "vertices" ~> 0 ~> "_id" === Some(S("-1")))
    assert(msf ~> "vertices" ~> 0 ~> "_type" === Some(S("vertex")))
    assert(msf ~> "vertices" ~> 0 ~> "source" === Some(S("Metasploit")))
    assert(msf ~> "vertices" ~> 0 ~> "vertexType" === Some(S("malware")))

    assert(msf ~> "vertices" ~> 1 === None)
    assert(msf ~> "edges" ~> 0 === None)
  }

  test("parse 1 Metasploit element - No CVE given") {
    var text = """"id","mtime","file","mtype","refname","fullname","name","rank","description","license","privileged","disclosure_date","default_target","default_action","stance","ready","ref_names","author_names"
1,"2013-05-07 00:25:41","/opt/metasploit/apps/pro/msf3/modules/exploits/aix/rpc_cmsd_opcode21.rb","exploit","aix/rpc_cmsd_opcode21","exploit/aix/rpc_cmsd_opcode21","AIX Calendar Manager Service Daemon (rpc.cmsd) Opcode 21 Buffer Overflow",500,"This module exploits a buffer overflow vulnerability in opcode 21 handled by rpc.cmsd on AIX. By making a request with a long string passed to the first argument of the ""rtable_create"" RPC, a stack based buffer overflow occurs. This leads to arbitrary code execution.  NOTE: Unsuccessful attempts may cause inetd/portmapper to enter a state where further attempts are not possible.","Metasploit Framework License (BSD)","f","2009-10-07 00:00:00",0,,"aggressive","t","BID-36615, OSVDB-58726, URL-http://aix.software.ibm.com/aix/efixes/security/cmsd_advisory.asc, URL-http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=825","Rodrigo Rubira Branco (BSDaemon), jduck <jduck@metasploit.com>"
"""
    val node = gov.ornl.stucco.morph.parser.CsvParser(text)
    val msf = MetasploitExtractor.extract(node)

    assert(msf ~> "vertices" ~> 0 ~> "_id" === Some(S("exploit/aix/rpc_cmsd_opcode21")))
    assert(msf ~> "vertices" ~> 0 ~> "_type" === Some(S("vertex")))
    assert(msf ~> "vertices" ~> 0 ~> "source" === Some(S("Metasploit")))
    assert(msf ~> "vertices" ~> 0 ~> "vertexType" === Some(S("malware")))
    assert(msf ~> "vertices" ~> 0 ~> "malwareType" === Some(S("exploit")))
    assert(msf ~> "vertices" ~> 0 ~> "discoveryDate" === Some(S("2009-10-07 00:00:00")))
    assert(msf ~> "vertices" ~> 0 ~> "overview" === Some(S("AIX Calendar Manager Service Daemon (rpc.cmsd) Opcode 21 Buffer Overflow")))
    assert(msf ~> "vertices" ~> 0 ~> "details" === Some(S("This module exploits a buffer overflow vulnerability in opcode 21 handled by rpc.cmsd on AIX. By making a request with a long string passed to the first argument of the \"rtable_create\" RPC, a stack based buffer overflow occurs. This leads to arbitrary code execution.  NOTE: Unsuccessful attempts may cause inetd/portmapper to enter a state where further attempts are not possible.")))

    assert(msf ~> "vertices" ~> 1 === None)
    assert(msf ~> "edges" ~> 0 === None)
  }

  test("parse 1 Metasploit element - with CVE") {
    var text = """"id","mtime","file","mtype","refname","fullname","name","rank","description","license","privileged","disclosure_date","default_target","default_action","stance","ready","ref_names","author_names"
1,"2013-05-07 00:25:41","/opt/metasploit/apps/pro/msf3/modules/exploits/aix/rpc_cmsd_opcode21.rb","exploit","aix/rpc_cmsd_opcode21","exploit/aix/rpc_cmsd_opcode21","AIX Calendar Manager Service Daemon (rpc.cmsd) Opcode 21 Buffer Overflow",500,"This module exploits a buffer overflow vulnerability in opcode 21 handled by rpc.cmsd on AIX. By making a request with a long string passed to the first argument of the ""rtable_create"" RPC, a stack based buffer overflow occurs. This leads to arbitrary code execution.  NOTE: Unsuccessful attempts may cause inetd/portmapper to enter a state where further attempts are not possible.","Metasploit Framework License (BSD)","f","2009-10-07 00:00:00",0,,"aggressive","t","BID-36615, CVE-2009-3699, OSVDB-58726, URL-http://aix.software.ibm.com/aix/efixes/security/cmsd_advisory.asc, URL-http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=825","Rodrigo Rubira Branco (BSDaemon), jduck <jduck@metasploit.com>"
"""
    val node = gov.ornl.stucco.morph.parser.CsvParser(text)
    val msf = MetasploitExtractor.extract(node)

    assert(msf ~> "vertices" ~> 0 ~> "_id" === Some(S("exploit/aix/rpc_cmsd_opcode21")))
    assert(msf ~> "vertices" ~> 0 ~> "_type" === Some(S("vertex")))
    assert(msf ~> "vertices" ~> 0 ~> "source" === Some(S("Metasploit")))
    assert(msf ~> "vertices" ~> 0 ~> "vertexType" === Some(S("malware")))
    assert(msf ~> "vertices" ~> 0 ~> "malwareType" === Some(S("exploit")))
    assert(msf ~> "vertices" ~> 0 ~> "discoveryDate" === Some(S("2009-10-07 00:00:00")))
    assert(msf ~> "vertices" ~> 0 ~> "overview" === Some(S("AIX Calendar Manager Service Daemon (rpc.cmsd) Opcode 21 Buffer Overflow")))
    assert(msf ~> "vertices" ~> 0 ~> "details" === Some(S("This module exploits a buffer overflow vulnerability in opcode 21 handled by rpc.cmsd on AIX. By making a request with a long string passed to the first argument of the \"rtable_create\" RPC, a stack based buffer overflow occurs. This leads to arbitrary code execution.  NOTE: Unsuccessful attempts may cause inetd/portmapper to enter a state where further attempts are not possible.")))

    assert(msf ~> "vertices" ~> 1 ~> "_id" === Some(S("CVE-2009-3699")))
    assert(msf ~> "vertices" ~> 1 ~> "_type" === Some(S("vertex")))
    assert(msf ~> "vertices" ~> 1 ~> "source" === Some(S("Metasploit")))
    assert(msf ~> "vertices" ~> 1 ~> "vertexType" === Some(S("vulnerability")))

    assert(msf ~> "vertices" ~> 2 === None)

    assert(msf ~> "edges" ~> 0 ~> "_id" === Some(S("exploit/aix/rpc_cmsd_opcode21_exploits_CVE-2009-3699")))
    assert(msf ~> "edges" ~> 0 ~> "_outV" === Some(S("exploit/aix/rpc_cmsd_opcode21")))
    assert(msf ~> "edges" ~> 0 ~> "_inV" === Some(S("CVE-2009-3699")))
    assert(msf ~> "edges" ~> 0 ~> "_type" === Some(S("edge")))
    assert(msf ~> "edges" ~> 0 ~> "_label" === Some(S("exploits")))
    assert(msf ~> "edges" ~> 0 ~> "source" === Some(S("Metasploit")))
    assert(msf ~> "edges" ~> 0 ~> "outVType" === Some(S("malware")))
    assert(msf ~> "edges" ~> 0 ~> "inVType" === Some(S("vulnerability")))

    assert(msf ~> "edges" ~> 1 === None)
  }

  test("parse 1 Metasploit element - with two CVEs") {
    var text = """"id","mtime","file","mtype","refname","fullname","name","rank","description","license","privileged","disclosure_date","default_target","default_action","stance","ready","ref_names","author_names"
1,"2013-05-07 00:25:41","/opt/metasploit/apps/pro/msf3/modules/exploits/aix/rpc_cmsd_opcode21.rb","exploit","aix/rpc_cmsd_opcode21","exploit/aix/rpc_cmsd_opcode21","AIX Calendar Manager Service Daemon (rpc.cmsd) Opcode 21 Buffer Overflow",500,"This module exploits a buffer overflow vulnerability in opcode 21 handled by rpc.cmsd on AIX. By making a request with a long string passed to the first argument of the ""rtable_create"" RPC, a stack based buffer overflow occurs. This leads to arbitrary code execution.  NOTE: Unsuccessful attempts may cause inetd/portmapper to enter a state where further attempts are not possible.","Metasploit Framework License (BSD)","f","2009-10-07 00:00:00",0,,"aggressive","t","BID-36615, CVE-2009-3699, CVE-2009-nnnn, OSVDB-58726, URL-http://aix.software.ibm.com/aix/efixes/security/cmsd_advisory.asc, URL-http://labs.idefense.com/intelligence/vulnerabilities/display.php?id=825","Rodrigo Rubira Branco (BSDaemon), jduck <jduck@metasploit.com>"
"""
    val node = gov.ornl.stucco.morph.parser.CsvParser(text)
    val msf = MetasploitExtractor.extract(node)

    assert(msf ~> "vertices" ~> 0 ~> "_id" === Some(S("exploit/aix/rpc_cmsd_opcode21")))
    assert(msf ~> "vertices" ~> 0 ~> "_type" === Some(S("vertex")))
    assert(msf ~> "vertices" ~> 0 ~> "source" === Some(S("Metasploit")))
    assert(msf ~> "vertices" ~> 0 ~> "vertexType" === Some(S("malware")))
    assert(msf ~> "vertices" ~> 0 ~> "malwareType" === Some(S("exploit")))
    assert(msf ~> "vertices" ~> 0 ~> "discoveryDate" === Some(S("2009-10-07 00:00:00")))
    assert(msf ~> "vertices" ~> 0 ~> "overview" === Some(S("AIX Calendar Manager Service Daemon (rpc.cmsd) Opcode 21 Buffer Overflow")))
    assert(msf ~> "vertices" ~> 0 ~> "details" === Some(S("This module exploits a buffer overflow vulnerability in opcode 21 handled by rpc.cmsd on AIX. By making a request with a long string passed to the first argument of the \"rtable_create\" RPC, a stack based buffer overflow occurs. This leads to arbitrary code execution.  NOTE: Unsuccessful attempts may cause inetd/portmapper to enter a state where further attempts are not possible.")))

    assert(msf ~> "vertices" ~> 1 ~> "_id" === Some(S("CVE-2009-3699")))
    assert(msf ~> "vertices" ~> 1 ~> "_type" === Some(S("vertex")))
    assert(msf ~> "vertices" ~> 1 ~> "source" === Some(S("Metasploit")))
    assert(msf ~> "vertices" ~> 1 ~> "vertexType" === Some(S("vulnerability")))

    assert(msf ~> "vertices" ~> 2 ~> "_id" === Some(S("CVE-2009-nnnn")))
    assert(msf ~> "vertices" ~> 2 ~> "_type" === Some(S("vertex")))
    assert(msf ~> "vertices" ~> 2 ~> "source" === Some(S("Metasploit")))
    assert(msf ~> "vertices" ~> 2 ~> "vertexType" === Some(S("vulnerability")))

    assert(msf ~> "vertices" ~> 3 === None)

    assert(msf ~> "edges" ~> 0 ~> "_id" === Some(S("exploit/aix/rpc_cmsd_opcode21_exploits_CVE-2009-3699")))
    assert(msf ~> "edges" ~> 0 ~> "_outV" === Some(S("exploit/aix/rpc_cmsd_opcode21")))
    assert(msf ~> "edges" ~> 0 ~> "_inV" === Some(S("CVE-2009-3699")))
    assert(msf ~> "edges" ~> 0 ~> "_type" === Some(S("edge")))
    assert(msf ~> "edges" ~> 0 ~> "_label" === Some(S("exploits")))
    assert(msf ~> "edges" ~> 0 ~> "source" === Some(S("Metasploit")))
    assert(msf ~> "edges" ~> 0 ~> "outVType" === Some(S("malware")))
    assert(msf ~> "edges" ~> 0 ~> "inVType" === Some(S("vulnerability")))

    assert(msf ~> "edges" ~> 1 ~> "_id" === Some(S("exploit/aix/rpc_cmsd_opcode21_exploits_CVE-2009-nnnn")))
    assert(msf ~> "edges" ~> 1 ~> "_outV" === Some(S("exploit/aix/rpc_cmsd_opcode21")))
    assert(msf ~> "edges" ~> 1 ~> "_inV" === Some(S("CVE-2009-nnnn")))
    assert(msf ~> "edges" ~> 1 ~> "_type" === Some(S("edge")))
    assert(msf ~> "edges" ~> 1 ~> "_label" === Some(S("exploits")))
    assert(msf ~> "edges" ~> 1 ~> "source" === Some(S("Metasploit")))
    assert(msf ~> "edges" ~> 1 ~> "outVType" === Some(S("malware")))
    assert(msf ~> "edges" ~> 1 ~> "inVType" === Some(S("vulnerability")))

    assert(msf ~> "edges" ~> 2 === None)
  }
/*
  test("parse the actual data") {
    val text = scala.io.Source.fromFile("testData/module_details_authors_refs_short.csv").mkString
    val node = CsvParser(text)
    val msf = MetasploitExtractor.extract(node)
    //print(msf)
    //assert(hone.get("vertices").asList.length === 1722345 )
  }
*/
}

