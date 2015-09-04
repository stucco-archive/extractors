import org.scalatest.FunSuite

import gov.ornl.stucco.morph.ast._
import gov.ornl.stucco.morph.ast.Implicits._
import gov.ornl.stucco.morph.ast.DSL._
import gov.ornl.stucco.morph.parser._
import gov.ornl.stucco.morph.parser.Interface._
import gov.ornl.stucco.morph.utils.Utils._

import gov.ornl.stucco.extractors._

class ClientBannerExtractorSuite extends FunSuite {

  // to make testing easier
  val O = ObjectNode
  val A = ArrayNode
  val S = StringNode
  val N = NumberNode

  test("parse an empty element (no header)") {
    var text = """,,,,,,,,,,,,,,,,,,,,,
"""
    val node = CsvParser(text)
    val clientBanners = ClientBannerExtractor(node)

    assert(clientBanners ~> "vertices" ~> 0 === None)
    assert(clientBanners ~> "edges" ~> 0 === None)
  }

  test("parse an empty element (header included)") {
    var text = """filename,recnum,file_type,amp_version,site,banner,addr,app_protocol,times_seen,first_seen_timet,last_seen_timet,countrycode,organization,lat,long
,,,,,,,,,,,,,,
"""
    val node = CsvParser(text)
    val clientBanners = ClientBannerExtractor(node)

    assert(clientBanners ~> "vertices" ~> 0 === None)
    assert(clientBanners ~> "edges" ~> 0 === None)
  }

  test("parse one client banner entry") {

    val text = """filename,recnum,file_type,amp_version,site,banner,addr,app_protocol,times_seen,first_seen_timet,last_seen_timet,countrycode,organization,lat,long
20150817000957-ornl-ampBanC4-1,1680,5,2,ornl,Entrust Entelligence Security Provider,160.91.155.43,80,1,2015-08-17 00:04:49+00,2015-08-17 00:04:49+00,US,oak ridge national laboratory,36.02103,-84.25273
    """
    val node = CsvParser(text)
    val clientBanners = ClientBannerExtractor(node)

    //print(clientBanners)

    assert(clientBanners ~> "vertices" ~> 0 ~> "_id" === Some(S("160.91.155.43:80")))
    assert(clientBanners ~> "vertices" ~> 0 ~> "name" === Some(S("160.91.155.43:80")))
    assert(clientBanners ~> "vertices" ~> 0 ~> "description" === Some(S("160.91.155.43, port 80")))
    assert(clientBanners ~> "vertices" ~> 0 ~> "_type" === Some(S("vertex")))
    assert(clientBanners ~> "vertices" ~> 0 ~> "vertexType" === Some(S("address")))
    assert(clientBanners ~> "vertices" ~> 0 ~> "source" === Some(S("client_banner")))

    assert(clientBanners ~> "vertices" ~> 1 ~> "_id" === Some(S("160.91.155.43")))
    assert(clientBanners ~> "vertices" ~> 1 ~> "name" === Some(S("160.91.155.43")))
    assert(clientBanners ~> "vertices" ~> 1 ~> "description" === Some(S("160.91.155.43")))
    assert(clientBanners ~> "vertices" ~> 1 ~> "_type" === Some(S("vertex")))
    assert(clientBanners ~> "vertices" ~> 1 ~> "vertexType" === Some(S("IP")))
    assert(clientBanners ~> "vertices" ~> 1 ~> "source" === Some(S("client_banner")))

    assert(clientBanners ~> "vertices" ~> 2 ~> "_id" === Some(S("80")))
    assert(clientBanners ~> "vertices" ~> 2 ~> "name" === Some(S("80")))
    assert(clientBanners ~> "vertices" ~> 2 ~> "description" === Some(S("80")))
    assert(clientBanners ~> "vertices" ~> 2 ~> "_type" === Some(S("vertex")))
    assert(clientBanners ~> "vertices" ~> 2 ~> "vertexType" === Some(S("port")))
    assert(clientBanners ~> "vertices" ~> 2 ~> "source" === Some(S("client_banner")))

    assert(clientBanners ~> "vertices" ~> 3 ~> "_id" === Some(S("Entrust_Entelligence_Security_Provider")))
    assert(clientBanners ~> "vertices" ~> 3 ~> "name" === Some(S("Entrust Entelligence Security Provider")))
    assert(clientBanners ~> "vertices" ~> 3 ~> "description" === Some(S("Entrust Entelligence Security Provider")))
    assert(clientBanners ~> "vertices" ~> 3 ~> "_type" === Some(S("vertex")))
    assert(clientBanners ~> "vertices" ~> 3 ~> "vertexType" === Some(S("service")))
    assert(clientBanners ~> "vertices" ~> 3 ~> "source" === Some(S("client_banner")))

    assert(clientBanners ~> "vertices" ~> 4 === None)

    assert(clientBanners ~> "edges" ~> 0 ~> "_id" === Some(S("160.91.155.43:80_hasIP_160.91.155.43")))
    assert(clientBanners ~> "edges" ~> 0 ~> "description" === Some(S("160.91.155.43, port 80 has IP 160.91.155.43")))
    assert(clientBanners ~> "edges" ~> 0 ~> "_outV" === Some(S("160.91.155.43:80")))
    assert(clientBanners ~> "edges" ~> 0 ~> "_inV" === Some(S("160.91.155.43")))
    assert(clientBanners ~> "edges" ~> 0 ~> "_type" === Some(S("edge")))
    assert(clientBanners ~> "edges" ~> 0 ~> "_label" === Some(S("hasIP")))
    assert(clientBanners ~> "edges" ~> 0 ~> "source" === Some(S("client_banner")))
    assert(clientBanners ~> "edges" ~> 0 ~> "outVType" === Some(S("address")))
    assert(clientBanners ~> "edges" ~> 0 ~> "inVType" === Some(S("IP")))

    assert(clientBanners ~> "edges" ~> 1 ~> "_id" === Some(S("160.91.155.43:80_hasPort_80")))
    assert(clientBanners ~> "edges" ~> 1 ~> "description" === Some(S("160.91.155.43, port 80 has port 80")))
    assert(clientBanners ~> "edges" ~> 1 ~> "_outV" === Some(S("160.91.155.43:80")))
    assert(clientBanners ~> "edges" ~> 1 ~> "_inV" === Some(S("80")))
    assert(clientBanners ~> "edges" ~> 1 ~> "_type" === Some(S("edge")))
    assert(clientBanners ~> "edges" ~> 1 ~> "_label" === Some(S("hasPort")))
    assert(clientBanners ~> "edges" ~> 1 ~> "source" === Some(S("client_banner")))
    assert(clientBanners ~> "edges" ~> 1 ~> "outVType" === Some(S("address")))
    assert(clientBanners ~> "edges" ~> 1 ~> "inVType" === Some(S("port")))

    assert(clientBanners ~> "edges" ~> 2 ~> "_id" === Some(S("160.91.155.43:80_hasKnownService_Entrust_Entelligence_Security_Provider")))
    assert(clientBanners ~> "edges" ~> 2 ~> "description" === Some(S("160.91.155.43, port 80 has service Entrust Entelligence Security Provider")))
    assert(clientBanners ~> "edges" ~> 2 ~> "_outV" === Some(S("160.91.155.43:80")))
    assert(clientBanners ~> "edges" ~> 2 ~> "_inV" === Some(S("Entrust_Entelligence_Security_Provider")))
    assert(clientBanners ~> "edges" ~> 2 ~> "_type" === Some(S("edge")))
    assert(clientBanners ~> "edges" ~> 2 ~> "_label" === Some(S("hasKnownService")))
    assert(clientBanners ~> "edges" ~> 2 ~> "source" === Some(S("client_banner")))
    assert(clientBanners ~> "edges" ~> 2 ~> "outVType" === Some(S("address")))
    assert(clientBanners ~> "edges" ~> 2 ~> "inVType" === Some(S("service")))

    assert(clientBanners ~> "edges" ~> 3 ~> "_id" === Some(S("80_hasKnownService_Entrust_Entelligence_Security_Provider")))
    assert(clientBanners ~> "edges" ~> 3 ~> "description" === Some(S("80 has service Entrust Entelligence Security Provider")))
    assert(clientBanners ~> "edges" ~> 3 ~> "_outV" === Some(S("80")))
    assert(clientBanners ~> "edges" ~> 3 ~> "_inV" === Some(S("Entrust_Entelligence_Security_Provider")))
    assert(clientBanners ~> "edges" ~> 3 ~> "_type" === Some(S("edge")))
    assert(clientBanners ~> "edges" ~> 3 ~> "_label" === Some(S("hasKnownService")))
    assert(clientBanners ~> "edges" ~> 3 ~> "source" === Some(S("client_banner")))
    assert(clientBanners ~> "edges" ~> 3 ~> "outVType" === Some(S("port")))
    assert(clientBanners ~> "edges" ~> 3 ~> "inVType" === Some(S("service")))

    assert(clientBanners ~> "edges" ~> 4 === None)
  }

  test("parse three client banner entries") {

    val text = """filename,recnum,file_type,amp_version,site,banner,addr,app_protocol,times_seen,first_seen_timet,last_seen_timet,countrycode,organization,lat,long
20150817000957-ornl-ampBanC4-1,1680,5,2,ornl,Entrust Entelligence Security Provider,160.91.155.43,80,1,2015-08-17 00:04:49+00,2015-08-17 00:04:49+00,US,oak ridge national laboratory,36.02103,-84.25273
20150817000957-ornl-ampBanC4-1,4414,5,2,ornl,Entrust Entelligence Security Provider,160.91.218.146,80,5,2015-08-17 00:00:00+00,2015-08-17 00:00:00+00,US,oak ridge national laboratory,36.02103,-84.25273
20150817000957-ornl-ampBanC4-1,395,5,2,ornl,iTunes/12.2.1 (Macintosh; OS X 10.9.5) AppleWebKit/537.78.2,128.219.49.13,80,2,2015-08-17 00:08:58+00,2015-08-17 00:08:58+00,US,oak ridge national laboratory,36.02103,-84.25273
    """
    val node = CsvParser(text)
    val clientBanners = ClientBannerExtractor(node)
   
    //print(clientBanners)

    assert(clientBanners ~> "vertices" ~> 4 ~> "_id" === Some(S("160.91.218.146:80")))
    assert(clientBanners ~> "vertices" ~> 4 ~> "name" === Some(S("160.91.218.146:80")))
    assert(clientBanners ~> "vertices" ~> 4 ~> "description" === Some(S("160.91.218.146, port 80")))
    assert(clientBanners ~> "vertices" ~> 4 ~> "_type" === Some(S("vertex")))
    assert(clientBanners ~> "vertices" ~> 4 ~> "vertexType" === Some(S("address")))
    assert(clientBanners ~> "vertices" ~> 4 ~> "source" === Some(S("client_banner")))

    assert(clientBanners ~> "vertices" ~> 5 ~> "_id" === Some(S("160.91.218.146")))
    assert(clientBanners ~> "vertices" ~> 5 ~> "name" === Some(S("160.91.218.146")))
    assert(clientBanners ~> "vertices" ~> 5 ~> "description" === Some(S("160.91.218.146")))
    assert(clientBanners ~> "vertices" ~> 5 ~> "_type" === Some(S("vertex")))
    assert(clientBanners ~> "vertices" ~> 5 ~> "vertexType" === Some(S("IP")))
    assert(clientBanners ~> "vertices" ~> 5 ~> "source" === Some(S("client_banner")))

    assert(clientBanners ~> "vertices" ~> 6 ~> "_id" === Some(S("80")))
    assert(clientBanners ~> "vertices" ~> 6 ~> "name" === Some(S("80")))
    assert(clientBanners ~> "vertices" ~> 6 ~> "description" === Some(S("80")))
    assert(clientBanners ~> "vertices" ~> 6 ~> "_type" === Some(S("vertex")))
    assert(clientBanners ~> "vertices" ~> 6 ~> "vertexType" === Some(S("port")))
    assert(clientBanners ~> "vertices" ~> 6 ~> "source" === Some(S("client_banner")))

    assert(clientBanners ~> "vertices" ~> 7 ~> "_id" === Some(S("Entrust_Entelligence_Security_Provider")))
    assert(clientBanners ~> "vertices" ~> 7 ~> "name" === Some(S("Entrust Entelligence Security Provider")))
    assert(clientBanners ~> "vertices" ~> 7 ~> "description" === Some(S("Entrust Entelligence Security Provider")))
    assert(clientBanners ~> "vertices" ~> 7 ~> "_type" === Some(S("vertex")))
    assert(clientBanners ~> "vertices" ~> 7 ~> "vertexType" === Some(S("service")))
    assert(clientBanners ~> "vertices" ~> 7 ~> "source" === Some(S("client_banner")))

    assert(clientBanners ~> "vertices" ~> 8 ~> "_id" === Some(S("128.219.49.13:80")))
    assert(clientBanners ~> "vertices" ~> 8 ~> "name" === Some(S("128.219.49.13:80")))
    assert(clientBanners ~> "vertices" ~> 8 ~> "description" === Some(S("128.219.49.13, port 80")))
    assert(clientBanners ~> "vertices" ~> 8 ~> "_type" === Some(S("vertex")))
    assert(clientBanners ~> "vertices" ~> 8 ~> "vertexType" === Some(S("address")))
    assert(clientBanners ~> "vertices" ~> 8 ~> "source" === Some(S("client_banner")))

    assert(clientBanners ~> "vertices" ~> 9 ~> "_id" === Some(S("128.219.49.13")))
    assert(clientBanners ~> "vertices" ~> 9 ~> "name" === Some(S("128.219.49.13")))
    assert(clientBanners ~> "vertices" ~> 9 ~> "description" === Some(S("128.219.49.13")))
    assert(clientBanners ~> "vertices" ~> 9 ~> "_type" === Some(S("vertex")))
    assert(clientBanners ~> "vertices" ~> 9 ~> "vertexType" === Some(S("IP")))
    assert(clientBanners ~> "vertices" ~> 9 ~> "source" === Some(S("client_banner")))

    assert(clientBanners ~> "vertices" ~> 10 ~> "_id" === Some(S("80")))
    assert(clientBanners ~> "vertices" ~> 10 ~> "name" === Some(S("80")))
    assert(clientBanners ~> "vertices" ~> 10 ~> "description" === Some(S("80")))
    assert(clientBanners ~> "vertices" ~> 10 ~> "_type" === Some(S("vertex")))
    assert(clientBanners ~> "vertices" ~> 10 ~> "vertexType" === Some(S("port")))
    assert(clientBanners ~> "vertices" ~> 10 ~> "source" === Some(S("client_banner")))

    assert(clientBanners ~> "vertices" ~> 11 ~> "_id" === Some(S("iTunes/12.2.1_(Macintosh;_OS_X_10.9.5)_AppleWebKit/537.78.2")))
    assert(clientBanners ~> "vertices" ~> 11 ~> "name" === Some(S("iTunes/12.2.1 (Macintosh; OS X 10.9.5) AppleWebKit/537.78.2")))
    assert(clientBanners ~> "vertices" ~> 11 ~> "description" === Some(S("iTunes/12.2.1 (Macintosh; OS X 10.9.5) AppleWebKit/537.78.2")))
    assert(clientBanners ~> "vertices" ~> 11 ~> "_type" === Some(S("vertex")))
    assert(clientBanners ~> "vertices" ~> 11 ~> "vertexType" === Some(S("service")))
    assert(clientBanners ~> "vertices" ~> 11 ~> "source" === Some(S("client_banner")))

    assert(clientBanners ~> "vertices" ~> 12 === None)

    assert(clientBanners ~> "edges" ~> 4 ~> "_id" === Some(S("160.91.218.146:80_hasIP_160.91.218.146")))
    assert(clientBanners ~> "edges" ~> 4 ~> "description" === Some(S("160.91.218.146, port 80 has IP 160.91.218.146")))
    assert(clientBanners ~> "edges" ~> 4 ~> "_outV" === Some(S("160.91.218.146:80")))
    assert(clientBanners ~> "edges" ~> 4 ~> "_inV" === Some(S("160.91.218.146")))
    assert(clientBanners ~> "edges" ~> 4 ~> "_type" === Some(S("edge")))
    assert(clientBanners ~> "edges" ~> 4 ~> "_label" === Some(S("hasIP")))
    assert(clientBanners ~> "edges" ~> 4 ~> "source" === Some(S("client_banner")))
    assert(clientBanners ~> "edges" ~> 4 ~> "outVType" === Some(S("address")))
    assert(clientBanners ~> "edges" ~> 4 ~> "inVType" === Some(S("IP")))

    assert(clientBanners ~> "edges" ~> 5 ~> "_id" === Some(S("160.91.218.146:80_hasPort_80")))
    assert(clientBanners ~> "edges" ~> 5 ~> "description" === Some(S("160.91.218.146, port 80 has port 80")))
    assert(clientBanners ~> "edges" ~> 5 ~> "_outV" === Some(S("160.91.218.146:80")))
    assert(clientBanners ~> "edges" ~> 5 ~> "_inV" === Some(S("80")))
    assert(clientBanners ~> "edges" ~> 5 ~> "_type" === Some(S("edge")))
    assert(clientBanners ~> "edges" ~> 5 ~> "_label" === Some(S("hasPort")))
    assert(clientBanners ~> "edges" ~> 5 ~> "source" === Some(S("client_banner")))
    assert(clientBanners ~> "edges" ~> 5 ~> "outVType" === Some(S("address")))
    assert(clientBanners ~> "edges" ~> 5 ~> "inVType" === Some(S("port")))

    assert(clientBanners ~> "edges" ~> 6 ~> "_id" === Some(S("160.91.218.146:80_hasKnownService_Entrust_Entelligence_Security_Provider")))
    assert(clientBanners ~> "edges" ~> 6 ~> "description" === Some(S("160.91.218.146, port 80 has service Entrust Entelligence Security Provider")))
    assert(clientBanners ~> "edges" ~> 6 ~> "_outV" === Some(S("160.91.218.146:80")))
    assert(clientBanners ~> "edges" ~> 6 ~> "_inV" === Some(S("Entrust_Entelligence_Security_Provider")))
    assert(clientBanners ~> "edges" ~> 6 ~> "_type" === Some(S("edge")))
    assert(clientBanners ~> "edges" ~> 6 ~> "_label" === Some(S("hasKnownService")))
    assert(clientBanners ~> "edges" ~> 6 ~> "source" === Some(S("client_banner")))
    assert(clientBanners ~> "edges" ~> 6 ~> "outVType" === Some(S("address")))
    assert(clientBanners ~> "edges" ~> 6 ~> "inVType" === Some(S("service")))

    assert(clientBanners ~> "edges" ~> 7 ~> "_id" === Some(S("80_hasKnownService_Entrust_Entelligence_Security_Provider")))
    assert(clientBanners ~> "edges" ~> 7 ~> "description" === Some(S("80 has service Entrust Entelligence Security Provider")))
    assert(clientBanners ~> "edges" ~> 7 ~> "_outV" === Some(S("80")))
    assert(clientBanners ~> "edges" ~> 7 ~> "_inV" === Some(S("Entrust_Entelligence_Security_Provider")))
    assert(clientBanners ~> "edges" ~> 7 ~> "_type" === Some(S("edge")))
    assert(clientBanners ~> "edges" ~> 7 ~> "_label" === Some(S("hasKnownService")))
    assert(clientBanners ~> "edges" ~> 7 ~> "source" === Some(S("client_banner")))
    assert(clientBanners ~> "edges" ~> 7 ~> "outVType" === Some(S("port")))
    assert(clientBanners ~> "edges" ~> 7 ~> "inVType" === Some(S("service")))

    assert(clientBanners ~> "edges" ~> 8 ~> "_id" === Some(S("128.219.49.13:80_hasIP_128.219.49.13")))
    assert(clientBanners ~> "edges" ~> 8 ~> "description" === Some(S("128.219.49.13, port 80 has IP 128.219.49.13")))
    assert(clientBanners ~> "edges" ~> 8 ~> "_outV" === Some(S("128.219.49.13:80")))
    assert(clientBanners ~> "edges" ~> 8 ~> "_inV" === Some(S("128.219.49.13")))
    assert(clientBanners ~> "edges" ~> 8 ~> "_type" === Some(S("edge")))
    assert(clientBanners ~> "edges" ~> 8 ~> "_label" === Some(S("hasIP")))
    assert(clientBanners ~> "edges" ~> 8 ~> "source" === Some(S("client_banner")))
    assert(clientBanners ~> "edges" ~> 8 ~> "outVType" === Some(S("address")))
    assert(clientBanners ~> "edges" ~> 8 ~> "inVType" === Some(S("IP")))

    assert(clientBanners ~> "edges" ~> 9 ~> "_id" === Some(S("128.219.49.13:80_hasPort_80")))
    assert(clientBanners ~> "edges" ~> 9 ~> "description" === Some(S("128.219.49.13, port 80 has port 80")))
    assert(clientBanners ~> "edges" ~> 9 ~> "_outV" === Some(S("128.219.49.13:80")))
    assert(clientBanners ~> "edges" ~> 9 ~> "_inV" === Some(S("80")))
    assert(clientBanners ~> "edges" ~> 9 ~> "_type" === Some(S("edge")))
    assert(clientBanners ~> "edges" ~> 9 ~> "_label" === Some(S("hasPort")))
    assert(clientBanners ~> "edges" ~> 9 ~> "source" === Some(S("client_banner")))
    assert(clientBanners ~> "edges" ~> 9 ~> "outVType" === Some(S("address")))
    assert(clientBanners ~> "edges" ~> 9 ~> "inVType" === Some(S("port")))

    assert(clientBanners ~> "edges" ~> 10 ~> "_id" === Some(S("128.219.49.13:80_hasKnownService_iTunes/12.2.1_(Macintosh;_OS_X_10.9.5)_AppleWebKit/537.78.2")))
    assert(clientBanners ~> "edges" ~> 10 ~> "description" === Some(S("128.219.49.13, port 80 has service iTunes/12.2.1 (Macintosh; OS X 10.9.5) AppleWebKit/537.78.2")))
    assert(clientBanners ~> "edges" ~> 10 ~> "_outV" === Some(S("128.219.49.13:80")))
    assert(clientBanners ~> "edges" ~> 10 ~> "_inV" === Some(S("iTunes/12.2.1_(Macintosh;_OS_X_10.9.5)_AppleWebKit/537.78.2")))
    assert(clientBanners ~> "edges" ~> 10 ~> "_type" === Some(S("edge")))
    assert(clientBanners ~> "edges" ~> 10 ~> "_label" === Some(S("hasKnownService")))
    assert(clientBanners ~> "edges" ~> 10 ~> "source" === Some(S("client_banner")))
    assert(clientBanners ~> "edges" ~> 10 ~> "outVType" === Some(S("address")))
    assert(clientBanners ~> "edges" ~> 10 ~> "inVType" === Some(S("service")))

    assert(clientBanners ~> "edges" ~> 11 ~> "_id" === Some(S("80_hasKnownService_iTunes/12.2.1_(Macintosh;_OS_X_10.9.5)_AppleWebKit/537.78.2")))
    assert(clientBanners ~> "edges" ~> 11 ~> "description" === Some(S("80 has service iTunes/12.2.1 (Macintosh; OS X 10.9.5) AppleWebKit/537.78.2")))
    assert(clientBanners ~> "edges" ~> 11 ~> "_outV" === Some(S("80")))
    assert(clientBanners ~> "edges" ~> 11 ~> "_inV" === Some(S("iTunes/12.2.1_(Macintosh;_OS_X_10.9.5)_AppleWebKit/537.78.2")))
    assert(clientBanners ~> "edges" ~> 11 ~> "_type" === Some(S("edge")))
    assert(clientBanners ~> "edges" ~> 11 ~> "_label" === Some(S("hasKnownService")))
    assert(clientBanners ~> "edges" ~> 11 ~> "source" === Some(S("client_banner")))
    assert(clientBanners ~> "edges" ~> 11 ~> "outVType" === Some(S("port")))
    assert(clientBanners ~> "edges" ~> 11 ~> "inVType" === Some(S("service")))

    assert(clientBanners ~> "edges" ~> 12 === None)
  }
  
}
