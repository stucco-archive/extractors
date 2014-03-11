import org.scalatest.FunSuite

import morph.ast._
import morph.ast.Implicits._
import morph.ast.DSL._
import morph.parser._
import morph.parser.Interface._
import morph.utils.Utils._

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
    println(node)
    val entries = CleanMxVirusExtractor(node)
    println(entries)
    assert(entries ~> "vertices" ~> 0 ~> "_id" === Some(S("CleanMx_22447134")))
    assert(entries ~> "vertices" ~> 0 ~> "_type" === Some(S("vertex")))
    assert(entries ~> "vertices" ~> 0 ~> "source" === Some(S("CleanMx(virus)")))
    assert(entries ~> "vertices" ~> 0 ~> "vertexType" === Some(S("attackerAsset")))
    assert(entries ~> "vertices" ~> 0 ~> "firstSeen" === Some(N(1394445736)))
    assert(entries ~> "vertices" ~> 0 ~> "lastSeen" === Some(N(0)))

    assert(entries ~> "vertices" ~> 1 ~> "_id" === Some(S("CleanMx_b5bcb300eb41207d0d945b79c364a0b5")))
    assert(entries ~> "vertices" ~> 1 ~> "_type" === Some(S("vertex")))
    assert(entries ~> "vertices" ~> 1 ~> "source" === Some(S("CleanMx(virus)")))
    assert(entries ~> "vertices" ~> 1 ~> "vertexType" === Some(S("malware")))
    assert(entries ~> "vertices" ~> 1 ~> "md5" === Some(S("b5bcb300eb41207d0d945b79c364a0b5")))

    assert(entries ~> "vertices" ~> 2 ~> "_id" === Some(S("115.47.55.160:80")))
    assert(entries ~> "vertices" ~> 2 ~> "_type" === Some(S("vertex")))
    assert(entries ~> "vertices" ~> 2 ~> "source" === Some(S("CleanMx(virus)")))
    assert(entries ~> "vertices" ~> 2 ~> "vertexType" === Some(S("address")))

    assert(entries ~> "vertices" ~> 3 ~> "_id" === Some(S("80")))
    assert(entries ~> "vertices" ~> 3 ~> "_type" === Some(S("vertex")))
    assert(entries ~> "vertices" ~> 3 ~> "source" === Some(S("CleanMx(virus)")))
    assert(entries ~> "vertices" ~> 3 ~> "vertexType" === Some(S("port")))

    assert(entries ~> "vertices" ~> 4 ~> "_id" === Some(S("idba.cc")))
    assert(entries ~> "vertices" ~> 4 ~> "_type" === Some(S("vertex")))
    assert(entries ~> "vertices" ~> 4 ~> "source" === Some(S("CleanMx(virus)")))
    assert(entries ~> "vertices" ~> 4 ~> "ns1" === Some(S("f1g1ns2.dnspod.net")))
    assert(entries ~> "vertices" ~> 4 ~> "ns2" === Some(S("f1g1ns1.dnspod.net")))
    //assert(entries ~> "vertices" ~> 4 ~> "ns3" === Some(null)) //TODO
    //assert(entries ~> "vertices" ~> 4 ~> "ns4" === Some(null))
    //assert(entries ~> "vertices" ~> 4 ~> "ns5" === None)

    assert(entries ~> "vertices" ~> 5 ~> "_id" === Some(S("115.47.55.160")))
    assert(entries ~> "vertices" ~> 5 ~> "_type" === Some(S("vertex")))
    assert(entries ~> "vertices" ~> 5 ~> "source" === Some(S("CleanMx(virus)")))
    assert(entries ~> "vertices" ~> 5 ~> "vertexType" === Some(S("IP")))

    assert(entries ~> "vertices" ~> 6 ~> "_id" === Some(S("115.47.0.0_through_115.47.255.255")))
    assert(entries ~> "vertices" ~> 6 ~> "_type" === Some(S("vertex")))
    assert(entries ~> "vertices" ~> 6 ~> "vertexType" === Some(S("addressRange")))
    assert(entries ~> "vertices" ~> 6 ~> "source" === Some(S("CleanMx(virus)")))
    assert(entries ~> "vertices" ~> 6 ~> "startIP" === Some(S("115.47.0.0")))
    assert(entries ~> "vertices" ~> 6 ~> "endIP" === Some(S("115.47.255.255")))
    assert(entries ~> "vertices" ~> 6 ~> "countryCode" === Some(S("CN")))
    assert(entries ~> "vertices" ~> 6 ~> "netname" === Some(S("XRNET")))
    assert(entries ~> "vertices" ~> 6 ~> "description" === Some(S("Beijing XiRang Media Cultural Co., Ltd.Build A6-1702,Fenghuahaojing,No.6 Guanganmennei RoadXuanwu, Beijing, China, 100053")))
    assert(entries ~> "vertices" ~> 6 ~> "asNum" === Some(S("AS9395")))
    assert(entries ~> "vertices" ~> 6 ~> "assignedBy" === Some(S("APNIC")))

    assert(entries ~> "vertices" ~> 7 === None)

    assert(entries ~> "edges" ~> 0 ~> "_id" === Some(S("CleanMx_b5bcb300eb41207d0d945b79c364a0b5_to_CleanMx_22447134")))
    assert(entries ~> "edges" ~> 0 ~> "_type" === Some(S("edge")))
    assert(entries ~> "edges" ~> 0 ~> "inVType" === Some(S("attackerAsset")))
    assert(entries ~> "edges" ~> 0 ~> "outVType" === Some(S("malware")))
    assert(entries ~> "edges" ~> 0 ~> "source" === Some(S("CleanMx(virus)")))
    assert(entries ~> "edges" ~> 0 ~> "_inV" === Some(S("CleanMx_22447134")))
    assert(entries ~> "edges" ~> 0 ~> "_outV" === Some(S("CleanMx_b5bcb300eb41207d0d945b79c364a0b5")))
    assert(entries ~> "edges" ~> 0 ~> "_label" === Some(S("associatedWith")))

    assert(entries ~> "edges" ~> 1 ~> "_id" === Some(S("CleanMx_22447134_to_115.47.55.160:80")))
    assert(entries ~> "edges" ~> 1 ~> "_type" === Some(S("edge")))
    assert(entries ~> "edges" ~> 1 ~> "inVType" === Some(S("address")))
    assert(entries ~> "edges" ~> 1 ~> "outVType" === Some(S("attackerAsset")))
    assert(entries ~> "edges" ~> 1 ~> "source" === Some(S("CleanMx(virus)")))
    assert(entries ~> "edges" ~> 1 ~> "_inV" === Some(S("115.47.55.160:80")))
    assert(entries ~> "edges" ~> 1 ~> "_outV" === Some(S("CleanMx_22447134")))
    assert(entries ~> "edges" ~> 1 ~> "_label" === Some(S("usesAddress")))

    assert(entries ~> "edges" ~> 2 ~> "_id" === Some(S("115.47.55.160:80_to_80")))
    assert(entries ~> "edges" ~> 2 ~> "_type" === Some(S("edge")))
    assert(entries ~> "edges" ~> 2 ~> "inVType" === Some(S("port")))
    assert(entries ~> "edges" ~> 2 ~> "outVType" === Some(S("address")))
    assert(entries ~> "edges" ~> 2 ~> "source" === Some(S("CleanMx(virus)")))
    assert(entries ~> "edges" ~> 2 ~> "_inV" === Some(S("80")))
    assert(entries ~> "edges" ~> 2 ~> "_outV" === Some(S("115.47.55.160:80")))
    assert(entries ~> "edges" ~> 2 ~> "_label" === Some(S("hasPort")))

    assert(entries ~> "edges" ~> 3 ~> "_id" === Some(S("115.47.55.160:80_to_idba.cc")))
    assert(entries ~> "edges" ~> 3 ~> "_type" === Some(S("edge")))
    assert(entries ~> "edges" ~> 3 ~> "inVType" === Some(S("DNSName")))
    assert(entries ~> "edges" ~> 3 ~> "outVType" === Some(S("address")))
    assert(entries ~> "edges" ~> 3 ~> "source" === Some(S("CleanMx(virus)")))
    assert(entries ~> "edges" ~> 3 ~> "_inV" === Some(S("idba.cc")))
    assert(entries ~> "edges" ~> 3 ~> "_outV" === Some(S("115.47.55.160:80")))
    assert(entries ~> "edges" ~> 3 ~> "_label" === Some(S("hasDNSName")))

    assert(entries ~> "edges" ~> 4 ~> "_id" === Some(S("115.47.55.160:80_to_115.47.55.160")))
    assert(entries ~> "edges" ~> 4 ~> "_type" === Some(S("edge")))
    assert(entries ~> "edges" ~> 4 ~> "inVType" === Some(S("IP")))
    assert(entries ~> "edges" ~> 4 ~> "outVType" === Some(S("address")))
    assert(entries ~> "edges" ~> 4 ~> "source" === Some(S("CleanMx(virus)")))
    assert(entries ~> "edges" ~> 4 ~> "_inV" === Some(S("115.47.55.160")))
    assert(entries ~> "edges" ~> 4 ~> "_outV" === Some(S("115.47.55.160:80")))
    assert(entries ~> "edges" ~> 4 ~> "_label" === Some(S("hasIP")))

    assert(entries ~> "edges" ~> 5 ~> "_id" === Some(S("115.47.55.160_to_115.47.0.0_through_115.47.255.255")))
    assert(entries ~> "edges" ~> 5 ~> "_type" === Some(S("edge")))
    assert(entries ~> "edges" ~> 5 ~> "inVType" === Some(S("addressRange")))
    assert(entries ~> "edges" ~> 5 ~> "outVType" === Some(S("IP")))
    assert(entries ~> "edges" ~> 5 ~> "source" === Some(S("CleanMx(virus)")))
    assert(entries ~> "edges" ~> 5 ~> "_inV" === Some(S("115.47.0.0_through_115.47.255.255")))
    assert(entries ~> "edges" ~> 5 ~> "_outV" === Some(S("115.47.55.160")))
    assert(entries ~> "edges" ~> 5 ~> "_label" === Some(S("inAddressRange")))

    assert(entries ~> "edges" ~> 6 === None)

  }

  test("parse two elements") {
    assert(None === None) //TODO
  }

}

