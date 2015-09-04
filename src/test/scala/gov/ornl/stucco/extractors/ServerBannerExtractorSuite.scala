import org.scalatest.FunSuite

import gov.ornl.stucco.morph.ast._
import gov.ornl.stucco.morph.ast.Implicits._
import gov.ornl.stucco.morph.ast.DSL._
import gov.ornl.stucco.morph.parser._
import gov.ornl.stucco.morph.parser.Interface._
import gov.ornl.stucco.morph.utils.Utils._

import gov.ornl.stucco.extractors._

class ServerBannerExtractorSuite extends FunSuite {

  // to make testing easier
  val O = ObjectNode
  val A = ArrayNode
  val S = StringNode
  val N = NumberNode

  test("parse an empty element (no header)") {
    var text = """,,,,,,,,,,,,,,,,,,,,,,
"""
    val node = CsvParser(text)
    val serverBanners = ServerBannerExtractor(node)

    assert(serverBanners ~> "vertices" ~> 0 === None)
    assert(serverBanners ~> "edges" ~> 0 === None)
  }

  test("parse an empty element (header included)") {
    var text = """filename,recnum,file_type,amp_version,site,banner,addr,server_port,app_protocol,times_seen,first_seen_timet,last_seen_timet,countrycode,organization,lat,long
,,,,,,,,,,,,,,,
"""
    val node = CsvParser(text)
    val serverBanners = ServerBannerExtractor(node)

    assert(serverBanners ~> "vertices" ~> 0 === None)
    assert(serverBanners ~> "edges" ~> 0 === None)
  }

  test("parse one client banner entry") {

    val text = """filename,recnum,file_type,amp_version,site,banner,addr,server_port,app_protocol,times_seen,first_seen_timet,last_seen_timet,countrycode,organization,lat,long
20150817002305-ornl-ampBanS4-1,367,6,2,ornl,Apache,128.219.150.8,80,80,5,2015-08-17 00:14:02+00,2015-08-17 00:14:02+00,US,oak ridge national laboratory,36.02103,-84.25273
"""

    val node = CsvParser(text)
    val serverBanners = ServerBannerExtractor(node)

    //print(serverBanners)

    assert(serverBanners ~> "vertices" ~> 0 ~> "_id" === Some(S("128.219.150.8:80")))
    assert(serverBanners ~> "vertices" ~> 0 ~> "name" === Some(S("128.219.150.8:80")))
    assert(serverBanners ~> "vertices" ~> 0 ~> "description" === Some(S("128.219.150.8, port 80")))
    assert(serverBanners ~> "vertices" ~> 0 ~> "_type" === Some(S("vertex")))
    assert(serverBanners ~> "vertices" ~> 0 ~> "vertexType" === Some(S("address")))
    assert(serverBanners ~> "vertices" ~> 0 ~> "source" === Some(S("client_banner")))

    assert(serverBanners ~> "vertices" ~> 1 ~> "_id" === Some(S("128.219.150.8")))
    assert(serverBanners ~> "vertices" ~> 1 ~> "name" === Some(S("128.219.150.8")))
    assert(serverBanners ~> "vertices" ~> 1 ~> "description" === Some(S("128.219.150.8")))
    assert(serverBanners ~> "vertices" ~> 1 ~> "_type" === Some(S("vertex")))
    assert(serverBanners ~> "vertices" ~> 1 ~> "vertexType" === Some(S("IP")))
    assert(serverBanners ~> "vertices" ~> 1 ~> "source" === Some(S("client_banner")))

    assert(serverBanners ~> "vertices" ~> 2 ~> "_id" === Some(S("80")))
    assert(serverBanners ~> "vertices" ~> 2 ~> "name" === Some(S("80")))
    assert(serverBanners ~> "vertices" ~> 2 ~> "description" === Some(S("80")))
    assert(serverBanners ~> "vertices" ~> 2 ~> "_type" === Some(S("vertex")))
    assert(serverBanners ~> "vertices" ~> 2 ~> "vertexType" === Some(S("port")))
    assert(serverBanners ~> "vertices" ~> 2 ~> "source" === Some(S("client_banner")))

    assert(serverBanners ~> "vertices" ~> 3 ~> "_id" === Some(S("Apache")))
    assert(serverBanners ~> "vertices" ~> 3 ~> "name" === Some(S("Apache")))
    assert(serverBanners ~> "vertices" ~> 3 ~> "description" === Some(S("Apache")))
    assert(serverBanners ~> "vertices" ~> 3 ~> "_type" === Some(S("vertex")))
    assert(serverBanners ~> "vertices" ~> 3 ~> "vertexType" === Some(S("service")))
    assert(serverBanners ~> "vertices" ~> 3 ~> "source" === Some(S("client_banner")))

    assert(serverBanners ~> "vertices" ~> 4 === None)

    assert(serverBanners ~> "edges" ~> 0 ~> "_id" === Some(S("128.219.150.8:80_hasIP_128.219.150.8")))
    assert(serverBanners ~> "edges" ~> 0 ~> "description" === Some(S("128.219.150.8, port 80 has IP 128.219.150.8")))
    assert(serverBanners ~> "edges" ~> 0 ~> "_outV" === Some(S("128.219.150.8:80")))
    assert(serverBanners ~> "edges" ~> 0 ~> "_inV" === Some(S("128.219.150.8")))
    assert(serverBanners ~> "edges" ~> 0 ~> "_type" === Some(S("edge")))
    assert(serverBanners ~> "edges" ~> 0 ~> "_label" === Some(S("hasIP")))
    assert(serverBanners ~> "edges" ~> 0 ~> "source" === Some(S("client_banner")))
    assert(serverBanners ~> "edges" ~> 0 ~> "outVType" === Some(S("address")))
    assert(serverBanners ~> "edges" ~> 0 ~> "inVType" === Some(S("IP")))

    assert(serverBanners ~> "edges" ~> 1 ~> "_id" === Some(S("128.219.150.8:80_hasPort_80")))
    assert(serverBanners ~> "edges" ~> 1 ~> "description" === Some(S("128.219.150.8, port 80 has port 80")))
    assert(serverBanners ~> "edges" ~> 1 ~> "_outV" === Some(S("128.219.150.8:80")))
    assert(serverBanners ~> "edges" ~> 1 ~> "_inV" === Some(S("80")))
    assert(serverBanners ~> "edges" ~> 1 ~> "_type" === Some(S("edge")))
    assert(serverBanners ~> "edges" ~> 1 ~> "_label" === Some(S("hasPort")))
    assert(serverBanners ~> "edges" ~> 1 ~> "source" === Some(S("client_banner")))
    assert(serverBanners ~> "edges" ~> 1 ~> "outVType" === Some(S("address")))
    assert(serverBanners ~> "edges" ~> 1 ~> "inVType" === Some(S("port")))

    assert(serverBanners ~> "edges" ~> 2 ~> "_id" === Some(S("128.219.150.8:80_hasKnownService_Apache")))
    assert(serverBanners ~> "edges" ~> 2 ~> "description" === Some(S("128.219.150.8, port 80 has service Apache")))
    assert(serverBanners ~> "edges" ~> 2 ~> "_outV" === Some(S("128.219.150.8:80")))
    assert(serverBanners ~> "edges" ~> 2 ~> "_inV" === Some(S("Apache")))
    assert(serverBanners ~> "edges" ~> 2 ~> "_type" === Some(S("edge")))
    assert(serverBanners ~> "edges" ~> 2 ~> "_label" === Some(S("hasKnownService")))
    assert(serverBanners ~> "edges" ~> 2 ~> "source" === Some(S("client_banner")))
    assert(serverBanners ~> "edges" ~> 2 ~> "outVType" === Some(S("address")))
    assert(serverBanners ~> "edges" ~> 2 ~> "inVType" === Some(S("service")))

    assert(serverBanners ~> "edges" ~> 3 ~> "_id" === Some(S("80_hasKnownService_Apache")))
    assert(serverBanners ~> "edges" ~> 3 ~> "description" === Some(S("80 has service Apache")))
    assert(serverBanners ~> "edges" ~> 3 ~> "_outV" === Some(S("80")))
    assert(serverBanners ~> "edges" ~> 3 ~> "_inV" === Some(S("Apache")))
    assert(serverBanners ~> "edges" ~> 3 ~> "_type" === Some(S("edge")))
    assert(serverBanners ~> "edges" ~> 3 ~> "_label" === Some(S("hasKnownService")))
    assert(serverBanners ~> "edges" ~> 3 ~> "source" === Some(S("client_banner")))
    assert(serverBanners ~> "edges" ~> 3 ~> "outVType" === Some(S("port")))
    assert(serverBanners ~> "edges" ~> 3 ~> "inVType" === Some(S("service")))

    assert(serverBanners ~> "edges" ~> 4 === None)
  }

  test("parse three client banner entries") {

    val text = """filename,recnum,file_type,amp_version,site,banner,addr,server_port,app_protocol,times_seen,first_seen_timet,last_seen_timet,countrycode,organization,lat,long
20150817002305-ornl-ampBanS4-1,367,6,2,ornl,Apache,128.219.150.8,80,80,5,2015-08-17 00:14:02+00,2015-08-17 00:14:02+00,US,oak ridge national laboratory,36.02103,-84.25273
20150817005305-ornl-ampBanS4-1,5682,6,2,ornl,Apache/2.2.15 (Red Hat),128.219.176.169,80,80,458,2015-08-17 00:38:05+00,2015-08-17 00:38:05+00,US,oak ridge national laboratory,36.02103,-84.25273
20150817005305-ornl-ampBanS4-1,5759,6,2,ornl,Microsoft-IIS/8.5,128.219.176.173,80,80,5,2015-08-17 00:40:13+00,2015-08-17 00:40:13+00,US,oak ridge national laboratory,36.02103,-84.25273
"""
    val node = CsvParser(text)
    val serverBanners = ServerBannerExtractor(node)
   
    //print(serverBanners)

    assert(serverBanners ~> "vertices" ~> 4 ~> "_id" === Some(S("128.219.176.169:80")))
    assert(serverBanners ~> "vertices" ~> 4 ~> "name" === Some(S("128.219.176.169:80")))
    assert(serverBanners ~> "vertices" ~> 4 ~> "description" === Some(S("128.219.176.169, port 80")))
    assert(serverBanners ~> "vertices" ~> 4 ~> "_type" === Some(S("vertex")))
    assert(serverBanners ~> "vertices" ~> 4 ~> "vertexType" === Some(S("address")))
    assert(serverBanners ~> "vertices" ~> 4 ~> "source" === Some(S("client_banner")))

    assert(serverBanners ~> "vertices" ~> 5 ~> "_id" === Some(S("128.219.176.169")))
    assert(serverBanners ~> "vertices" ~> 5 ~> "name" === Some(S("128.219.176.169")))
    assert(serverBanners ~> "vertices" ~> 5 ~> "description" === Some(S("128.219.176.169")))
    assert(serverBanners ~> "vertices" ~> 5 ~> "_type" === Some(S("vertex")))
    assert(serverBanners ~> "vertices" ~> 5 ~> "vertexType" === Some(S("IP")))
    assert(serverBanners ~> "vertices" ~> 5 ~> "source" === Some(S("client_banner")))

    assert(serverBanners ~> "vertices" ~> 6 ~> "_id" === Some(S("80")))
    assert(serverBanners ~> "vertices" ~> 6 ~> "name" === Some(S("80")))
    assert(serverBanners ~> "vertices" ~> 6 ~> "description" === Some(S("80")))
    assert(serverBanners ~> "vertices" ~> 6 ~> "_type" === Some(S("vertex")))
    assert(serverBanners ~> "vertices" ~> 6 ~> "vertexType" === Some(S("port")))
    assert(serverBanners ~> "vertices" ~> 6 ~> "source" === Some(S("client_banner")))

    assert(serverBanners ~> "vertices" ~> 7 ~> "_id" === Some(S("Apache/2.2.15_(Red_Hat)")))
    assert(serverBanners ~> "vertices" ~> 7 ~> "name" === Some(S("Apache/2.2.15 (Red Hat)")))
    assert(serverBanners ~> "vertices" ~> 7 ~> "description" === Some(S("Apache/2.2.15 (Red Hat)")))
    assert(serverBanners ~> "vertices" ~> 7 ~> "_type" === Some(S("vertex")))
    assert(serverBanners ~> "vertices" ~> 7 ~> "vertexType" === Some(S("service")))
    assert(serverBanners ~> "vertices" ~> 7 ~> "source" === Some(S("client_banner")))

    assert(serverBanners ~> "vertices" ~> 8 ~> "_id" === Some(S("128.219.176.173:80")))
    assert(serverBanners ~> "vertices" ~> 8 ~> "name" === Some(S("128.219.176.173:80")))
    assert(serverBanners ~> "vertices" ~> 8 ~> "description" === Some(S("128.219.176.173, port 80")))
    assert(serverBanners ~> "vertices" ~> 8 ~> "_type" === Some(S("vertex")))
    assert(serverBanners ~> "vertices" ~> 8 ~> "vertexType" === Some(S("address")))
    assert(serverBanners ~> "vertices" ~> 8 ~> "source" === Some(S("client_banner")))

    assert(serverBanners ~> "vertices" ~> 9 ~> "_id" === Some(S("128.219.176.173")))
    assert(serverBanners ~> "vertices" ~> 9 ~> "name" === Some(S("128.219.176.173")))
    assert(serverBanners ~> "vertices" ~> 9 ~> "description" === Some(S("128.219.176.173")))
    assert(serverBanners ~> "vertices" ~> 9 ~> "_type" === Some(S("vertex")))
    assert(serverBanners ~> "vertices" ~> 9 ~> "vertexType" === Some(S("IP")))
    assert(serverBanners ~> "vertices" ~> 9 ~> "source" === Some(S("client_banner")))

    assert(serverBanners ~> "vertices" ~> 10 ~> "_id" === Some(S("80")))
    assert(serverBanners ~> "vertices" ~> 10 ~> "name" === Some(S("80")))
    assert(serverBanners ~> "vertices" ~> 10 ~> "description" === Some(S("80")))
    assert(serverBanners ~> "vertices" ~> 10 ~> "_type" === Some(S("vertex")))
    assert(serverBanners ~> "vertices" ~> 10 ~> "vertexType" === Some(S("port")))
    assert(serverBanners ~> "vertices" ~> 10 ~> "source" === Some(S("client_banner")))

    assert(serverBanners ~> "vertices" ~> 11 ~> "_id" === Some(S("Microsoft-IIS/8.5")))
    assert(serverBanners ~> "vertices" ~> 11 ~> "name" === Some(S("Microsoft-IIS/8.5")))
    assert(serverBanners ~> "vertices" ~> 11 ~> "description" === Some(S("Microsoft-IIS/8.5")))
    assert(serverBanners ~> "vertices" ~> 11 ~> "_type" === Some(S("vertex")))
    assert(serverBanners ~> "vertices" ~> 11 ~> "vertexType" === Some(S("service")))
    assert(serverBanners ~> "vertices" ~> 11 ~> "source" === Some(S("client_banner")))

    assert(serverBanners ~> "vertices" ~> 12 === None)

    assert(serverBanners ~> "edges" ~> 4 ~> "_id" === Some(S("128.219.176.169:80_hasIP_128.219.176.169")))
    assert(serverBanners ~> "edges" ~> 4 ~> "description" === Some(S("128.219.176.169, port 80 has IP 128.219.176.169")))
    assert(serverBanners ~> "edges" ~> 4 ~> "_outV" === Some(S("128.219.176.169:80")))
    assert(serverBanners ~> "edges" ~> 4 ~> "_inV" === Some(S("128.219.176.169")))
    assert(serverBanners ~> "edges" ~> 4 ~> "_type" === Some(S("edge")))
    assert(serverBanners ~> "edges" ~> 4 ~> "_label" === Some(S("hasIP")))
    assert(serverBanners ~> "edges" ~> 4 ~> "source" === Some(S("client_banner")))
    assert(serverBanners ~> "edges" ~> 4 ~> "outVType" === Some(S("address")))
    assert(serverBanners ~> "edges" ~> 4 ~> "inVType" === Some(S("IP")))

    assert(serverBanners ~> "edges" ~> 5 ~> "_id" === Some(S("128.219.176.169:80_hasPort_80")))
    assert(serverBanners ~> "edges" ~> 5 ~> "description" === Some(S("128.219.176.169, port 80 has port 80")))
    assert(serverBanners ~> "edges" ~> 5 ~> "_outV" === Some(S("128.219.176.169:80")))
    assert(serverBanners ~> "edges" ~> 5 ~> "_inV" === Some(S("80")))
    assert(serverBanners ~> "edges" ~> 5 ~> "_type" === Some(S("edge")))
    assert(serverBanners ~> "edges" ~> 5 ~> "_label" === Some(S("hasPort")))
    assert(serverBanners ~> "edges" ~> 5 ~> "source" === Some(S("client_banner")))
    assert(serverBanners ~> "edges" ~> 5 ~> "outVType" === Some(S("address")))
    assert(serverBanners ~> "edges" ~> 5 ~> "inVType" === Some(S("port")))

    assert(serverBanners ~> "edges" ~> 6 ~> "_id" === Some(S("128.219.176.169:80_hasKnownService_Apache/2.2.15_(Red_Hat)")))
    assert(serverBanners ~> "edges" ~> 6 ~> "description" === Some(S("128.219.176.169, port 80 has service Apache/2.2.15 (Red Hat)")))
    assert(serverBanners ~> "edges" ~> 6 ~> "_outV" === Some(S("128.219.176.169:80")))
    assert(serverBanners ~> "edges" ~> 6 ~> "_inV" === Some(S("Apache/2.2.15_(Red_Hat)")))
    assert(serverBanners ~> "edges" ~> 6 ~> "_type" === Some(S("edge")))
    assert(serverBanners ~> "edges" ~> 6 ~> "_label" === Some(S("hasKnownService")))
    assert(serverBanners ~> "edges" ~> 6 ~> "source" === Some(S("client_banner")))
    assert(serverBanners ~> "edges" ~> 6 ~> "outVType" === Some(S("address")))
    assert(serverBanners ~> "edges" ~> 6 ~> "inVType" === Some(S("service")))

    assert(serverBanners ~> "edges" ~> 7 ~> "_id" === Some(S("80_hasKnownService_Apache/2.2.15_(Red_Hat)")))
    assert(serverBanners ~> "edges" ~> 7 ~> "description" === Some(S("80 has service Apache/2.2.15 (Red Hat)")))
    assert(serverBanners ~> "edges" ~> 7 ~> "_outV" === Some(S("80")))
    assert(serverBanners ~> "edges" ~> 7 ~> "_inV" === Some(S("Apache/2.2.15_(Red_Hat)")))
    assert(serverBanners ~> "edges" ~> 7 ~> "_type" === Some(S("edge")))
    assert(serverBanners ~> "edges" ~> 7 ~> "_label" === Some(S("hasKnownService")))
    assert(serverBanners ~> "edges" ~> 7 ~> "source" === Some(S("client_banner")))
    assert(serverBanners ~> "edges" ~> 7 ~> "outVType" === Some(S("port")))
    assert(serverBanners ~> "edges" ~> 7 ~> "inVType" === Some(S("service")))

    assert(serverBanners ~> "edges" ~> 8 ~> "_id" === Some(S("128.219.176.173:80_hasIP_128.219.176.173")))
    assert(serverBanners ~> "edges" ~> 8 ~> "description" === Some(S("128.219.176.173, port 80 has IP 128.219.176.173")))
    assert(serverBanners ~> "edges" ~> 8 ~> "_outV" === Some(S("128.219.176.173:80")))
    assert(serverBanners ~> "edges" ~> 8 ~> "_inV" === Some(S("128.219.176.173")))
    assert(serverBanners ~> "edges" ~> 8 ~> "_type" === Some(S("edge")))
    assert(serverBanners ~> "edges" ~> 8 ~> "_label" === Some(S("hasIP")))
    assert(serverBanners ~> "edges" ~> 8 ~> "source" === Some(S("client_banner")))
    assert(serverBanners ~> "edges" ~> 8 ~> "outVType" === Some(S("address")))
    assert(serverBanners ~> "edges" ~> 8 ~> "inVType" === Some(S("IP")))

    assert(serverBanners ~> "edges" ~> 9 ~> "_id" === Some(S("128.219.176.173:80_hasPort_80")))
    assert(serverBanners ~> "edges" ~> 9 ~> "description" === Some(S("128.219.176.173, port 80 has port 80")))
    assert(serverBanners ~> "edges" ~> 9 ~> "_outV" === Some(S("128.219.176.173:80")))
    assert(serverBanners ~> "edges" ~> 9 ~> "_inV" === Some(S("80")))
    assert(serverBanners ~> "edges" ~> 9 ~> "_type" === Some(S("edge")))
    assert(serverBanners ~> "edges" ~> 9 ~> "_label" === Some(S("hasPort")))
    assert(serverBanners ~> "edges" ~> 9 ~> "source" === Some(S("client_banner")))
    assert(serverBanners ~> "edges" ~> 9 ~> "outVType" === Some(S("address")))
    assert(serverBanners ~> "edges" ~> 9 ~> "inVType" === Some(S("port")))

    assert(serverBanners ~> "edges" ~> 10 ~> "_id" === Some(S("128.219.176.173:80_hasKnownService_Microsoft-IIS/8.5")))
    assert(serverBanners ~> "edges" ~> 10 ~> "description" === Some(S("128.219.176.173, port 80 has service Microsoft-IIS/8.5")))
    assert(serverBanners ~> "edges" ~> 10 ~> "_outV" === Some(S("128.219.176.173:80")))
    assert(serverBanners ~> "edges" ~> 10 ~> "_inV" === Some(S("Microsoft-IIS/8.5")))
    assert(serverBanners ~> "edges" ~> 10 ~> "_type" === Some(S("edge")))
    assert(serverBanners ~> "edges" ~> 10 ~> "_label" === Some(S("hasKnownService")))
    assert(serverBanners ~> "edges" ~> 10 ~> "source" === Some(S("client_banner")))
    assert(serverBanners ~> "edges" ~> 10 ~> "outVType" === Some(S("address")))
    assert(serverBanners ~> "edges" ~> 10 ~> "inVType" === Some(S("service")))

    assert(serverBanners ~> "edges" ~> 11 ~> "_id" === Some(S("80_hasKnownService_Microsoft-IIS/8.5")))
    assert(serverBanners ~> "edges" ~> 11 ~> "description" === Some(S("80 has service Microsoft-IIS/8.5")))
    assert(serverBanners ~> "edges" ~> 11 ~> "_outV" === Some(S("80")))
    assert(serverBanners ~> "edges" ~> 11 ~> "_inV" === Some(S("Microsoft-IIS/8.5")))
    assert(serverBanners ~> "edges" ~> 11 ~> "_type" === Some(S("edge")))
    assert(serverBanners ~> "edges" ~> 11 ~> "_label" === Some(S("hasKnownService")))
    assert(serverBanners ~> "edges" ~> 11 ~> "source" === Some(S("client_banner")))
    assert(serverBanners ~> "edges" ~> 11 ~> "outVType" === Some(S("port")))
    assert(serverBanners ~> "edges" ~> 11 ~> "inVType" === Some(S("service")))

    assert(serverBanners ~> "edges" ~> 12 === None)
  }
  
}
