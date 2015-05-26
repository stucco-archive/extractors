import org.scalatest.FunSuite

import gov.ornl.stucco.morph.ast._
import gov.ornl.stucco.morph.ast.Implicits._
import gov.ornl.stucco.morph.ast.DSL._
import gov.ornl.stucco.morph.parser._
import gov.ornl.stucco.morph.parser.Interface._
import gov.ornl.stucco.morph.utils.Utils._

import gov.ornl.stucco.extractors._

class CleanMxVirusExtractorSuite extends FunSuite {

  // to make testing easier
  val O = ObjectNode
  val A = ArrayNode
  val S = StringNode
  val N = NumberNode

  test("parse one element with inetnum") {
    val node = XmlParser("""
        <?xml version="1.0" encoding="iso-8859-15"?>
        <output>
            <response>
                <error>0</error>
            </response>
        <entries>
        <entry>
            <line>1</line>
            <id>22447134</id>
            <first>1394445736</first>
            <last>0</last>
            <md5>b5bcb300eb41207d0d945b79c364a0b5</md5>
            <virustotal></virustotal>
            <vt_score>0/43 (0.0%)</vt_score>
            <scanner></scanner>
            <virusname><![CDATA[]]></virusname>
            <url><![CDATA[http://xz.idba.cc:88/jqsp.zip?qqdrsign=050c5]]></url>
            <recent>up</recent>
            <response>alive</response>
            <ip>115.47.55.160</ip>
            <as>AS9395</as>
            <review>115.47.55.160</review>
            <domain>idba.cc</domain>
            <country>CN</country>
            <source>APNIC</source>
            <email>donglin@xrnet.cn</email>
            <inetnum>115.47.0.0 - 115.47.255.255</inetnum>
            <netname>XRNET</netname>
            <descr><![CDATA[Beijing XiRang Media Cultural Co., Ltd.Build A6-1702,Fenghuahaojing,No.6 Guanganmennei RoadXuanwu, Beijing, China, 100053]]></descr>
            <ns1>f1g1ns2.dnspod.net</ns1>
            <ns2>f1g1ns1.dnspod.net</ns2>
            <ns3></ns3>
            <ns4></ns4>
            <ns5></ns5>
        </entry>
        </entries>
        </output>
      """)
    //println(node)
    val entries = CleanMxVirusExtractor(node)
    //println(entries)

    assert(entries ~> "vertices" ~> 0 ~> "_id" === Some(S("CleanMx_22447134")))
    assert(entries ~> "vertices" ~> 0 ~> "name" === Some(S("CleanMx_22447134")))
    assert(entries ~> "vertices" ~> 0 ~> "description" === Some(S("CleanMx entry 22447134")))
    assert(entries ~> "vertices" ~> 0 ~> "_type" === Some(S("vertex")))
    assert(entries ~> "vertices" ~> 0 ~> "source" === Some(S("CleanMx(virus)")))
    assert(entries ~> "vertices" ~> 0 ~> "vertexType" === Some(S("malware")))
    assert(entries ~> "vertices" ~> 0 ~> "md5hashes" === Some(S("b5bcb300eb41207d0d945b79c364a0b5")))

    assert(entries ~> "vertices" ~> 1 ~> "_id" === Some(S("115.47.55.160:80")))
    assert(entries ~> "vertices" ~> 1 ~> "name" === Some(S("115.47.55.160:80")))
    assert(entries ~> "vertices" ~> 1 ~> "description" === Some(S("115.47.55.160, port 80")))
    assert(entries ~> "vertices" ~> 1 ~> "_type" === Some(S("vertex")))
    assert(entries ~> "vertices" ~> 1 ~> "source" === Some(S("CleanMx(virus)")))
    assert(entries ~> "vertices" ~> 1 ~> "vertexType" === Some(S("address")))

    assert(entries ~> "vertices" ~> 2 ~> "_id" === Some(S("80")))
    assert(entries ~> "vertices" ~> 2 ~> "name" === Some(S("80")))
    assert(entries ~> "vertices" ~> 2 ~> "description" === Some(S("80")))
    assert(entries ~> "vertices" ~> 2 ~> "_type" === Some(S("vertex")))
    assert(entries ~> "vertices" ~> 2 ~> "source" === Some(S("CleanMx(virus)")))
    assert(entries ~> "vertices" ~> 2 ~> "vertexType" === Some(S("port")))

    assert(entries ~> "vertices" ~> 3 ~> "_id" === Some(S("idba.cc")))
    assert(entries ~> "vertices" ~> 3 ~> "name" === Some(S("idba.cc")))
    assert(entries ~> "vertices" ~> 3 ~> "description" === Some(S("idba.cc")))
    assert(entries ~> "vertices" ~> 3 ~> "_type" === Some(S("vertex")))
    assert(entries ~> "vertices" ~> 3 ~> "source" === Some(S("CleanMx(virus)")))
    assert(entries ~> "vertices" ~> 3 ~> "ns1" === Some(S("f1g1ns2.dnspod.net")))
    assert(entries ~> "vertices" ~> 3 ~> "ns2" === Some(S("f1g1ns1.dnspod.net")))
    //assert(entries ~> "vertices" ~> 3 ~> "ns3" === Some(null)) //TODO
    //assert(entries ~> "vertices" ~> 3 ~> "ns4" === Some(null))
    //assert(entries ~> "vertices" ~> 3 ~> "ns5" === None)

    assert(entries ~> "vertices" ~> 4 ~> "_id" === Some(S("115.47.55.160")))
    assert(entries ~> "vertices" ~> 4 ~> "name" === Some(S("115.47.55.160")))
    assert(entries ~> "vertices" ~> 4 ~> "description" === Some(S("115.47.55.160")))
    assert(entries ~> "vertices" ~> 4 ~> "_type" === Some(S("vertex")))
    assert(entries ~> "vertices" ~> 4 ~> "source" === Some(S("CleanMx(virus)")))
    assert(entries ~> "vertices" ~> 4 ~> "vertexType" === Some(S("IP")))

    assert(entries ~> "vertices" ~> 5 ~> "_id" === Some(S("115.47.0.0_through_115.47.255.255")))
    assert(entries ~> "vertices" ~> 5 ~> "name" === Some(S("115.47.0.0_through_115.47.255.255")))
    assert(entries ~> "vertices" ~> 5 ~> "_type" === Some(S("vertex")))
    assert(entries ~> "vertices" ~> 5 ~> "vertexType" === Some(S("addressRange")))
    assert(entries ~> "vertices" ~> 5 ~> "source" === Some(S("CleanMx(virus)")))
    assert(entries ~> "vertices" ~> 5 ~> "startIP" === Some(S("115.47.0.0")))
    assert(entries ~> "vertices" ~> 5 ~> "endIP" === Some(S("115.47.255.255")))
    assert(entries ~> "vertices" ~> 5 ~> "countryCode" === Some(S("CN")))
    assert(entries ~> "vertices" ~> 5 ~> "netname" === Some(S("XRNET")))
    assert(entries ~> "vertices" ~> 5 ~> "description" === Some(S("Beijing XiRang Media Cultural Co., Ltd.Build A6-1702,Fenghuahaojing,No.6 Guanganmennei RoadXuanwu, Beijing, China, 100053")))
    assert(entries ~> "vertices" ~> 5 ~> "asNum" === Some(N(9395)))
    assert(entries ~> "vertices" ~> 5 ~> "assignedBy" === Some(S("APNIC")))

    assert(entries ~> "vertices" ~> 6 === None)

    assert(entries ~> "edges" ~> 0 ~> "_id" === Some(S("CleanMx_22447134_communicatesWith_115.47.55.160:80")))
    assert(entries ~> "edges" ~> 0 ~> "description" === Some(S("CleanMx entry 22447134 communicates with 115.47.55.160, port 80")))
    assert(entries ~> "edges" ~> 0 ~> "_type" === Some(S("edge")))
    assert(entries ~> "edges" ~> 0 ~> "inVType" === Some(S("address")))
    assert(entries ~> "edges" ~> 0 ~> "outVType" === Some(S("malware")))
    assert(entries ~> "edges" ~> 0 ~> "source" === Some(S("CleanMx(virus)")))
    assert(entries ~> "edges" ~> 0 ~> "_inV" === Some(S("115.47.55.160:80")))
    assert(entries ~> "edges" ~> 0 ~> "_outV" === Some(S("CleanMx_22447134")))
    assert(entries ~> "edges" ~> 0 ~> "_label" === Some(S("communicatesWith")))

    assert(entries ~> "edges" ~> 1 ~> "_id" === Some(S("115.47.55.160:80_hasPort_80")))
    assert(entries ~> "edges" ~> 1 ~> "description" === Some(S("115.47.55.160, port 80 has port 80")))
    assert(entries ~> "edges" ~> 1 ~> "_type" === Some(S("edge")))
    assert(entries ~> "edges" ~> 1 ~> "inVType" === Some(S("port")))
    assert(entries ~> "edges" ~> 1 ~> "outVType" === Some(S("address")))
    assert(entries ~> "edges" ~> 1 ~> "source" === Some(S("CleanMx(virus)")))
    assert(entries ~> "edges" ~> 1 ~> "_inV" === Some(S("80")))
    assert(entries ~> "edges" ~> 1 ~> "_outV" === Some(S("115.47.55.160:80")))
    assert(entries ~> "edges" ~> 1 ~> "_label" === Some(S("hasPort")))

    assert(entries ~> "edges" ~> 2 ~> "_id" === Some(S("115.47.55.160:80_hasDNSName_idba.cc")))
    assert(entries ~> "edges" ~> 2 ~> "description" === Some(S("115.47.55.160, port 80 has DNS name idba.cc")))
    assert(entries ~> "edges" ~> 2 ~> "_type" === Some(S("edge")))
    assert(entries ~> "edges" ~> 2 ~> "inVType" === Some(S("DNSName")))
    assert(entries ~> "edges" ~> 2 ~> "outVType" === Some(S("address")))
    assert(entries ~> "edges" ~> 2 ~> "source" === Some(S("CleanMx(virus)")))
    assert(entries ~> "edges" ~> 2 ~> "_inV" === Some(S("idba.cc")))
    assert(entries ~> "edges" ~> 2 ~> "_outV" === Some(S("115.47.55.160:80")))
    assert(entries ~> "edges" ~> 2 ~> "_label" === Some(S("hasDNSName")))

    assert(entries ~> "edges" ~> 3 ~> "_id" === Some(S("115.47.55.160:80_hasIP_115.47.55.160")))
    assert(entries ~> "edges" ~> 3 ~> "description" === Some(S("115.47.55.160, port 80 has IP 115.47.55.160")))
    assert(entries ~> "edges" ~> 3 ~> "_type" === Some(S("edge")))
    assert(entries ~> "edges" ~> 3 ~> "inVType" === Some(S("IP")))
    assert(entries ~> "edges" ~> 3 ~> "outVType" === Some(S("address")))
    assert(entries ~> "edges" ~> 3 ~> "source" === Some(S("CleanMx(virus)")))
    assert(entries ~> "edges" ~> 3 ~> "_inV" === Some(S("115.47.55.160")))
    assert(entries ~> "edges" ~> 3 ~> "_outV" === Some(S("115.47.55.160:80")))
    assert(entries ~> "edges" ~> 3 ~> "_label" === Some(S("hasIP")))

    assert(entries ~> "edges" ~> 4 ~> "_id" === Some(S("115.47.55.160_inAddressRange_115.47.0.0_through_115.47.255.255")))
    assert(entries ~> "edges" ~> 4 ~> "description" === Some(S("115.47.55.160 is in address range 115.47.0.0 through 115.47.255.255")))
    assert(entries ~> "edges" ~> 4 ~> "_type" === Some(S("edge")))
    assert(entries ~> "edges" ~> 4 ~> "inVType" === Some(S("addressRange")))
    assert(entries ~> "edges" ~> 4 ~> "outVType" === Some(S("IP")))
    assert(entries ~> "edges" ~> 4 ~> "source" === Some(S("CleanMx(virus)")))
    assert(entries ~> "edges" ~> 4 ~> "_inV" === Some(S("115.47.0.0_through_115.47.255.255")))
    assert(entries ~> "edges" ~> 4 ~> "_outV" === Some(S("115.47.55.160")))
    assert(entries ~> "edges" ~> 4 ~> "_label" === Some(S("inAddressRange")))

    assert(entries ~> "edges" ~> 5 === None)

  }

  test("parse two elements") {
    val node = XmlParser("""
        <?xml version="1.0" encoding="iso-8859-15"?>
        <output>
            <response>
                <error>0</error>
            </response>
        <entries>
        <entry>
            <line>7</line>
            <id>22446016</id>
            <first>1394445710</first>
            <last>0</last>
            <md5>dad1324061f93af4eb0205a3b114ea6e</md5>
            <virustotal>http://www.virustotal.com/latest-report.html?resource=dad1324061f93af4eb0205a3b114ea6e</virustotal>
            <vt_score>28/46 (60.9%)</vt_score>
            <scanner>AhnLab_V3</scanner>
            <virusname><![CDATA[Trojan%2FWin32.generic]]></virusname>
            <url><![CDATA[http://www.filedataukmyscan.info/sp32_64_18199873683419572808.exe]]></url>
            <recent>up</recent>
            <response>alive</response>
            <ip>95.211.169.207</ip>
            <as>AS16265</as>
            <review>95.211.169.207</review>
            <domain>filedataukmyscan.info</domain>
            <country>NL</country>
            <source>RIPE</source>
            <email>abuse@leaseweb.com</email>
            <inetnum>95.211.0.0 - 95.211.255.255</inetnum>
            <netname>NL-LEASEWEB-20080724</netname>
            <descr><![CDATA[LeaseWeb B.V.]]></descr>
            <ns1>brad.ns.cloudflare.com</ns1>
            <ns2>pam.ns.cloudflare.com</ns2>
            <ns3></ns3>
            <ns4></ns4>
            <ns5></ns5>
        </entry>
        <entry>
            <line>8</line>
            <id>22446014</id>
            <first>1394445710</first>
            <last>0</last>
            <md5>6653a885aae75cc8bd45f2808d80202c</md5>
            <virustotal>http://www.virustotal.com/latest-report.html?resource=6653a885aae75cc8bd45f2808d80202c</virustotal>
            <vt_score>13/45 (28.9%)</vt_score>
            <scanner>AntiVir</scanner>
            <virusname><![CDATA[Adware%2FLinkular.C]]></virusname>
            <url><![CDATA[http://www.coolestmovie.info/ds-exe/vlc/9076/VLCPlus_Setup.exe]]></url>
            <recent>up</recent>
            <response>alive</response>
            <ip>54.208.13.153</ip>
            <as>AS16509</as>
            <review>54.208.13.153</review>
            <domain>coolestmovie.info</domain>
            <country>US</country>
            <source>ARIN</source>
            <email>ec2-abuse@amazon.com</email>
            <inetnum>54.208.0.0 - 54.209.255.255</inetnum>
            <netname>AMAZO-ZIAD4</netname>
            <descr><![CDATA[Amazon.com, Inc. AMAZO-4 Amazon Web Services, Elastic Compute Cloud, EC2 1200 12th Avenue South Seattle WA 98144]]></descr>
            <ns1>ns58.domaincontrol.com</ns1>
            <ns2>ns57.domaincontrol.com</ns2>
            <ns3></ns3>
            <ns4></ns4>
            <ns5></ns5>
        </entry>
        </entries>
        </output>
      """)
    //println(node)
    val entries = CleanMxVirusExtractor(node)
    //println(entries)

    assert(entries ~> "vertices" ~> 0 ~> "_id" === Some(S("CleanMx_22446016")))
    assert(entries ~> "vertices" ~> 0 ~> "name" === Some(S("CleanMx_22446016")))
    assert(entries ~> "vertices" ~> 0 ~> "description" === Some(S("CleanMx entry 22446016")))
    assert(entries ~> "vertices" ~> 0 ~> "_type" === Some(S("vertex")))
    assert(entries ~> "vertices" ~> 0 ~> "vertexType" === Some(S("malware")))
    assert(entries ~> "vertices" ~> 0 ~> "source" === Some(S("CleanMx(virus)")))
    assert(entries ~> "vertices" ~> 0 ~> "aliases" === Some(S("Trojan%2FWin32.generic")))
    assert(entries ~> "vertices" ~> 0 ~> "md5hashes" === Some(S("dad1324061f93af4eb0205a3b114ea6e")))

    assert(entries ~> "vertices" ~> 1 ~> "_id" === Some(S("95.211.169.207:80")))
    assert(entries ~> "vertices" ~> 1 ~> "name" === Some(S("95.211.169.207:80")))
    assert(entries ~> "vertices" ~> 1 ~> "description" === Some(S("95.211.169.207, port 80")))
    assert(entries ~> "vertices" ~> 1 ~> "_type" === Some(S("vertex")))
    assert(entries ~> "vertices" ~> 1 ~> "vertexType" === Some(S("address")))
    assert(entries ~> "vertices" ~> 1 ~> "source" === Some(S("CleanMx(virus)")))

    assert(entries ~> "vertices" ~> 2 ~> "_id" === Some(S("80")))
    assert(entries ~> "vertices" ~> 2 ~> "name" === Some(S("80")))
    assert(entries ~> "vertices" ~> 2 ~> "description" === Some(S("80")))
    assert(entries ~> "vertices" ~> 2 ~> "_type" === Some(S("vertex")))
    assert(entries ~> "vertices" ~> 2 ~> "vertexType" === Some(S("port")))
    assert(entries ~> "vertices" ~> 2 ~> "source" === Some(S("CleanMx(virus)")))

    assert(entries ~> "vertices" ~> 3 ~> "_id" === Some(S("filedataukmyscan.info")))
    assert(entries ~> "vertices" ~> 3 ~> "name" === Some(S("filedataukmyscan.info")))
    assert(entries ~> "vertices" ~> 3 ~> "description" === Some(S("filedataukmyscan.info")))
    assert(entries ~> "vertices" ~> 3 ~> "_type" === Some(S("vertex")))
    assert(entries ~> "vertices" ~> 3 ~> "vertexType" === Some(S("DNSName")))
    assert(entries ~> "vertices" ~> 3 ~> "source" === Some(S("CleanMx(virus)")))
    assert(entries ~> "vertices" ~> 3 ~> "ns1" === Some(S("brad.ns.cloudflare.com")))
    assert(entries ~> "vertices" ~> 3 ~> "ns2" === Some(S("pam.ns.cloudflare.com")))
    //assert(entries ~> "vertices" ~> 3 ~> "ns3" === Some(S(null)))
    //assert(entries ~> "vertices" ~> 3 ~> "ns4" === Some(S(null)))
    //assert(entries ~> "vertices" ~> 3 ~> "ns5" === Some(S(null)))

    assert(entries ~> "vertices" ~> 4 ~> "_id" === Some(S("95.211.169.207")))
    assert(entries ~> "vertices" ~> 4 ~> "name" === Some(S("95.211.169.207")))
    assert(entries ~> "vertices" ~> 4 ~> "description" === Some(S("95.211.169.207")))
    assert(entries ~> "vertices" ~> 4 ~> "_type" === Some(S("vertex")))
    assert(entries ~> "vertices" ~> 4 ~> "vertexType" === Some(S("IP")))
    assert(entries ~> "vertices" ~> 4 ~> "source" === Some(S("CleanMx(virus)")))

    assert(entries ~> "vertices" ~> 5 ~> "_id" === Some(S("95.211.0.0_through_95.211.255.255")))
    assert(entries ~> "vertices" ~> 5 ~> "name" === Some(S("95.211.0.0_through_95.211.255.255")))
    assert(entries ~> "vertices" ~> 5 ~> "_type" === Some(S("vertex")))
    assert(entries ~> "vertices" ~> 5 ~> "vertexType" === Some(S("addressRange")))
    assert(entries ~> "vertices" ~> 5 ~> "source" === Some(S("CleanMx(virus)")))
    assert(entries ~> "vertices" ~> 5 ~> "startIP" === Some(S("95.211.0.0")))
    assert(entries ~> "vertices" ~> 5 ~> "endIP" === Some(S("95.211.255.255")))
    assert(entries ~> "vertices" ~> 5 ~> "countryCode" === Some(S("NL")))
    assert(entries ~> "vertices" ~> 5 ~> "netname" === Some(S("NL-LEASEWEB-20080724")))
    assert(entries ~> "vertices" ~> 5 ~> "description" === Some(S("LeaseWeb B.V.")))
    assert(entries ~> "vertices" ~> 5 ~> "asNum" === Some(N(16265)))
    assert(entries ~> "vertices" ~> 5 ~> "assignedBy" === Some(S("RIPE")))

    assert(entries ~> "vertices" ~> 6 ~> "_id" === Some(S("CleanMx_22446014")))
    assert(entries ~> "vertices" ~> 6 ~> "name" === Some(S("CleanMx_22446014")))
    assert(entries ~> "vertices" ~> 6 ~> "description" === Some(S("CleanMx entry 22446014")))
    assert(entries ~> "vertices" ~> 6 ~> "_type" === Some(S("vertex")))
    assert(entries ~> "vertices" ~> 6 ~> "vertexType" === Some(S("malware")))
    assert(entries ~> "vertices" ~> 6 ~> "source" === Some(S("CleanMx(virus)")))
    assert(entries ~> "vertices" ~> 6 ~> "aliases" === Some(S("Adware%2FLinkular.C")))
    assert(entries ~> "vertices" ~> 6 ~> "md5hashes" === Some(S("6653a885aae75cc8bd45f2808d80202c")))

    assert(entries ~> "vertices" ~> 7 ~> "_id" === Some(S("54.208.13.153:80")))
    assert(entries ~> "vertices" ~> 7 ~> "name" === Some(S("54.208.13.153:80")))
    assert(entries ~> "vertices" ~> 7 ~> "description" === Some(S("54.208.13.153, port 80")))
    assert(entries ~> "vertices" ~> 7 ~> "_type" === Some(S("vertex")))
    assert(entries ~> "vertices" ~> 7 ~> "vertexType" === Some(S("address")))
    assert(entries ~> "vertices" ~> 7 ~> "source" === Some(S("CleanMx(virus)")))

    assert(entries ~> "vertices" ~> 8 ~> "_id" === Some(S("80")))
    assert(entries ~> "vertices" ~> 8 ~> "name" === Some(S("80")))
    assert(entries ~> "vertices" ~> 8 ~> "description" === Some(S("80")))
    assert(entries ~> "vertices" ~> 8 ~> "_type" === Some(S("vertex")))
    assert(entries ~> "vertices" ~> 8 ~> "vertexType" === Some(S("port")))
    assert(entries ~> "vertices" ~> 8 ~> "source" === Some(S("CleanMx(virus)")))

    assert(entries ~> "vertices" ~> 9 ~> "_id" === Some(S("coolestmovie.info")))
    assert(entries ~> "vertices" ~> 9 ~> "name" === Some(S("coolestmovie.info")))
    assert(entries ~> "vertices" ~> 9 ~> "description" === Some(S("coolestmovie.info")))
    assert(entries ~> "vertices" ~> 9 ~> "_type" === Some(S("vertex")))
    assert(entries ~> "vertices" ~> 9 ~> "vertexType" === Some(S("DNSName")))
    assert(entries ~> "vertices" ~> 9 ~> "source" === Some(S("CleanMx(virus)")))
    assert(entries ~> "vertices" ~> 9 ~> "ns1" === Some(S("ns58.domaincontrol.com")))
    assert(entries ~> "vertices" ~> 9 ~> "ns2" === Some(S("ns57.domaincontrol.com")))
    //assert(entries ~> "vertices" ~> 9 ~> "ns3" === Some(S(null)))
    //assert(entries ~> "vertices" ~> 9 ~> "ns4" === Some(S(null)))
    //assert(entries ~> "vertices" ~> 9 ~> "ns5" === None)

    assert(entries ~> "vertices" ~> 10 ~> "_id" === Some(S("54.208.13.153")))
    assert(entries ~> "vertices" ~> 10 ~> "name" === Some(S("54.208.13.153")))
    assert(entries ~> "vertices" ~> 10 ~> "description" === Some(S("54.208.13.153")))
    assert(entries ~> "vertices" ~> 10 ~> "_type" === Some(S("vertex")))
    assert(entries ~> "vertices" ~> 10 ~> "vertexType" === Some(S("IP")))
    assert(entries ~> "vertices" ~> 10 ~> "source" === Some(S("CleanMx(virus)")))

    assert(entries ~> "vertices" ~> 11 ~> "_id" === Some(S("54.208.0.0_through_54.209.255.255")))
    assert(entries ~> "vertices" ~> 11 ~> "name" === Some(S("54.208.0.0_through_54.209.255.255")))
    assert(entries ~> "vertices" ~> 11 ~> "_type" === Some(S("vertex")))
    assert(entries ~> "vertices" ~> 11 ~> "vertexType" === Some(S("addressRange")))
    assert(entries ~> "vertices" ~> 11 ~> "source" === Some(S("CleanMx(virus)")))
    assert(entries ~> "vertices" ~> 11 ~> "startIP" === Some(S("54.208.0.0")))
    assert(entries ~> "vertices" ~> 11 ~> "endIP" === Some(S("54.209.255.255")))
    assert(entries ~> "vertices" ~> 11 ~> "countryCode" === Some(S("US")))
    assert(entries ~> "vertices" ~> 11 ~> "netname" === Some(S("AMAZO-ZIAD4")))
    assert(entries ~> "vertices" ~> 11 ~> "description" === Some(S("Amazon.com, Inc. AMAZO-4 Amazon Web Services, Elastic Compute Cloud, EC2 1200 12th Avenue South Seattle WA 98144")))
    assert(entries ~> "vertices" ~> 11 ~> "asNum" === Some(N(16509)))
    assert(entries ~> "vertices" ~> 11 ~> "assignedBy" === Some(S("ARIN")))

    assert(entries ~> "vertices" ~> 12 === None)

    assert(entries ~> "edges" ~> 0 ~> "_id" === Some(S("CleanMx_22446016_communicatesWith_95.211.169.207:80")))
    assert(entries ~> "edges" ~> 0 ~> "description" === Some(S("CleanMx entry 22446016 communicates with 95.211.169.207, port 80")))
    assert(entries ~> "edges" ~> 0 ~> "_type" === Some(S("edge")))
    assert(entries ~> "edges" ~> 0 ~> "inVType" === Some(S("address")))
    assert(entries ~> "edges" ~> 0 ~> "outVType" === Some(S("malware")))
    assert(entries ~> "edges" ~> 0 ~> "source" === Some(S("CleanMx(virus)")))
    assert(entries ~> "edges" ~> 0 ~> "_inV" === Some(S("95.211.169.207:80")))
    assert(entries ~> "edges" ~> 0 ~> "_outV" === Some(S("CleanMx_22446016")))
    assert(entries ~> "edges" ~> 0 ~> "_label" === Some(S("communicatesWith")))
    
    assert(entries ~> "edges" ~> 1 ~> "_id" === Some(S("95.211.169.207:80_hasPort_80")))
    assert(entries ~> "edges" ~> 1 ~> "description" === Some(S("95.211.169.207, port 80 has port 80")))
    assert(entries ~> "edges" ~> 1 ~> "_type" === Some(S("edge")))
    assert(entries ~> "edges" ~> 1 ~> "inVType" === Some(S("port")))
    assert(entries ~> "edges" ~> 1 ~> "outVType" === Some(S("address")))
    assert(entries ~> "edges" ~> 1 ~> "source" === Some(S("CleanMx(virus)")))
    assert(entries ~> "edges" ~> 1 ~> "_inV" === Some(S("80")))
    assert(entries ~> "edges" ~> 1 ~> "_outV" === Some(S("95.211.169.207:80")))
    assert(entries ~> "edges" ~> 1 ~> "_label" === Some(S("hasPort")))
    
    assert(entries ~> "edges" ~> 2 ~> "_id" === Some(S("95.211.169.207:80_hasDNSName_filedataukmyscan.info")))
    assert(entries ~> "edges" ~> 2 ~> "description" === Some(S("95.211.169.207, port 80 has DNS name filedataukmyscan.info")))
    assert(entries ~> "edges" ~> 2 ~> "_type" === Some(S("edge")))
    assert(entries ~> "edges" ~> 2 ~> "inVType" === Some(S("DNSName")))
    assert(entries ~> "edges" ~> 2 ~> "outVType" === Some(S("address")))
    assert(entries ~> "edges" ~> 2 ~> "source" === Some(S("CleanMx(virus)")))
    assert(entries ~> "edges" ~> 2 ~> "_inV" === Some(S("filedataukmyscan.info")))
    assert(entries ~> "edges" ~> 2 ~> "_outV" === Some(S("95.211.169.207:80")))
    assert(entries ~> "edges" ~> 2 ~> "_label" === Some(S("hasDNSName")))
    
    assert(entries ~> "edges" ~> 3 ~> "_id" === Some(S("95.211.169.207:80_hasIP_95.211.169.207")))
    assert(entries ~> "edges" ~> 3 ~> "description" === Some(S("95.211.169.207, port 80 has IP 95.211.169.207")))
    assert(entries ~> "edges" ~> 3 ~> "_type" === Some(S("edge")))
    assert(entries ~> "edges" ~> 3 ~> "inVType" === Some(S("IP")))
    assert(entries ~> "edges" ~> 3 ~> "outVType" === Some(S("address")))
    assert(entries ~> "edges" ~> 3 ~> "source" === Some(S("CleanMx(virus)")))
    assert(entries ~> "edges" ~> 3 ~> "_inV" === Some(S("95.211.169.207")))
    assert(entries ~> "edges" ~> 3 ~> "_outV" === Some(S("95.211.169.207:80")))
    assert(entries ~> "edges" ~> 3 ~> "_label" === Some(S("hasIP")))
    
    assert(entries ~> "edges" ~> 4 ~> "_id" === Some(S("95.211.169.207_inAddressRange_95.211.0.0_through_95.211.255.255")))
    assert(entries ~> "edges" ~> 4 ~> "description" === Some(S("95.211.169.207 is in address range 95.211.0.0 through 95.211.255.255")))
    assert(entries ~> "edges" ~> 4 ~> "_type" === Some(S("edge")))
    assert(entries ~> "edges" ~> 4 ~> "inVType" === Some(S("addressRange")))
    assert(entries ~> "edges" ~> 4 ~> "outVType" === Some(S("IP")))
    assert(entries ~> "edges" ~> 4 ~> "source" === Some(S("CleanMx(virus)")))
    assert(entries ~> "edges" ~> 4 ~> "_inV" === Some(S("95.211.0.0_through_95.211.255.255")))
    assert(entries ~> "edges" ~> 4 ~> "_outV" === Some(S("95.211.169.207")))
    assert(entries ~> "edges" ~> 4 ~> "_label" === Some(S("inAddressRange")))
    
    assert(entries ~> "edges" ~> 5 ~> "_id" === Some(S("CleanMx_22446014_communicatesWith_54.208.13.153:80")))
    assert(entries ~> "edges" ~> 5 ~> "description" === Some(S("CleanMx entry 22446014 communicates with 54.208.13.153, port 80")))
    assert(entries ~> "edges" ~> 5 ~> "_type" === Some(S("edge")))
    assert(entries ~> "edges" ~> 5 ~> "inVType" === Some(S("address")))
    assert(entries ~> "edges" ~> 5 ~> "outVType" === Some(S("malware")))
    assert(entries ~> "edges" ~> 5 ~> "source" === Some(S("CleanMx(virus)")))
    assert(entries ~> "edges" ~> 5 ~> "_inV" === Some(S("54.208.13.153:80")))
    assert(entries ~> "edges" ~> 5 ~> "_outV" === Some(S("CleanMx_22446014")))
    assert(entries ~> "edges" ~> 5 ~> "_label" === Some(S("communicatesWith")))
    
    assert(entries ~> "edges" ~> 6 ~> "_id" === Some(S("54.208.13.153:80_hasPort_80")))
    assert(entries ~> "edges" ~> 6 ~> "description" === Some(S("54.208.13.153, port 80 has port 80")))
    assert(entries ~> "edges" ~> 6 ~> "_type" === Some(S("edge")))
    assert(entries ~> "edges" ~> 6 ~> "inVType" === Some(S("port")))
    assert(entries ~> "edges" ~> 6 ~> "outVType" === Some(S("address")))
    assert(entries ~> "edges" ~> 6 ~> "source" === Some(S("CleanMx(virus)")))
    assert(entries ~> "edges" ~> 6 ~> "_inV" === Some(S("80")))
    assert(entries ~> "edges" ~> 6 ~> "_outV" === Some(S("54.208.13.153:80")))
    assert(entries ~> "edges" ~> 6 ~> "_label" === Some(S("hasPort")))
    
    assert(entries ~> "edges" ~> 7 ~> "_id" === Some(S("54.208.13.153:80_hasDNSName_coolestmovie.info")))
    assert(entries ~> "edges" ~> 7 ~> "description" === Some(S("54.208.13.153, port 80 has DNS name coolestmovie.info")))
    assert(entries ~> "edges" ~> 7 ~> "_type" === Some(S("edge")))
    assert(entries ~> "edges" ~> 7 ~> "inVType" === Some(S("DNSName")))
    assert(entries ~> "edges" ~> 7 ~> "outVType" === Some(S("address")))
    assert(entries ~> "edges" ~> 7 ~> "source" === Some(S("CleanMx(virus)")))
    assert(entries ~> "edges" ~> 7 ~> "_inV" === Some(S("coolestmovie.info")))
    assert(entries ~> "edges" ~> 7 ~> "_outV" === Some(S("54.208.13.153:80")))
    assert(entries ~> "edges" ~> 7 ~> "_label" === Some(S("hasDNSName")))
    
    assert(entries ~> "edges" ~> 8 ~> "_id" === Some(S("54.208.13.153:80_hasIP_54.208.13.153")))
    assert(entries ~> "edges" ~> 8 ~> "description" === Some(S("54.208.13.153, port 80 has IP 54.208.13.153")))
    assert(entries ~> "edges" ~> 8 ~> "_type" === Some(S("edge")))
    assert(entries ~> "edges" ~> 8 ~> "inVType" === Some(S("IP")))
    assert(entries ~> "edges" ~> 8 ~> "outVType" === Some(S("address")))
    assert(entries ~> "edges" ~> 8 ~> "source" === Some(S("CleanMx(virus)")))
    assert(entries ~> "edges" ~> 8 ~> "_inV" === Some(S("54.208.13.153")))
    assert(entries ~> "edges" ~> 8 ~> "_outV" === Some(S("54.208.13.153:80")))
    assert(entries ~> "edges" ~> 8 ~> "_label" === Some(S("hasIP")))
    
    assert(entries ~> "edges" ~> 9 ~> "_id" === Some(S("54.208.13.153_inAddressRange_54.208.0.0_through_54.209.255.255")))
    assert(entries ~> "edges" ~> 9 ~> "description" === Some(S("54.208.13.153 is in address range 54.208.0.0 through 54.209.255.255")))
    assert(entries ~> "edges" ~> 9 ~> "_type" === Some(S("edge")))
    assert(entries ~> "edges" ~> 9 ~> "inVType" === Some(S("addressRange")))
    assert(entries ~> "edges" ~> 9 ~> "outVType" === Some(S("IP")))
    assert(entries ~> "edges" ~> 9 ~> "source" === Some(S("CleanMx(virus)")))
    assert(entries ~> "edges" ~> 9 ~> "_inV" === Some(S("54.208.0.0_through_54.209.255.255")))
    assert(entries ~> "edges" ~> 9 ~> "_outV" === Some(S("54.208.13.153")))
    assert(entries ~> "edges" ~> 9 ~> "_label" === Some(S("inAddressRange")))

    assert(entries ~> "edges" ~> 12 === None)
    
    assert(None === None) //TODO
  }
/*
  test("parse the actual data") {
    val source = scala.io.Source.fromFile("testData/b446b373-0491-42df-bfba-fcb619463a13")(io.Codec("iso-8859-15"))
    val text = source.getLines mkString "\n"
    source.close()
    print(text)
    val node = XmlParser(text)
    print("parsed OK!")
    val result = CleanMxVirusExtractor.extract(node)
    print("extracted OK!")
    //print(msf)
    //assert(hone.get("vertices").asList.length === 1722345 )
  }
*/
}

