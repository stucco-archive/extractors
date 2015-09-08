import org.scalatest.FunSuite

import gov.ornl.stucco.morph.ast._
import gov.ornl.stucco.morph.ast.Implicits._
import gov.ornl.stucco.morph.ast.DSL._
import gov.ornl.stucco.morph.parser._
import gov.ornl.stucco.morph.parser.Interface._
import gov.ornl.stucco.morph.utils.Utils._

import gov.ornl.stucco.extractors._

class ServiceListExtractorSuite extends FunSuite {

  // to make testing easier
  val O = ObjectNode
  val A = ArrayNode
  val S = StringNode
  val N = NumberNode

  test("parse an empty element (no header)") {
    var text = """,,,,,,,,,,,,,,,,,,,,,
"""
    val node = CsvParser(text)
    val serviceList = ServiceListExtractor(node)

    assert(serviceList ~> "vertices" ~> 0 === None)
    assert(serviceList ~> "edges" ~> 0 === None)
  }

  test("parse an empty element (header included)") {
    var text = """Service Name,Port Number,Transport Protocol,Description,Assignee,Contact,Registration Date,Modification Date,Reference,Service Code,Known Unauthorized Uses,Assignment Notes
,,,,,,,,,,,
"""
    val node = CsvParser(text)
    val serviceList = ServiceListExtractor(node)

    assert(serviceList ~> "vertices" ~> 0 === None)
    assert(serviceList ~> "edges" ~> 0 === None)
  }

  test("parse one service entry") {

    val text = """Service Name,Port Number,Transport Protocol,Description,Assignee,Contact,Registration Date,Modification Date,Reference,Service Code,Known Unauthorized Uses,Assignment Notes
ssh,22,tcp,The Secure Shell (SSH) Protocol,,,,,[RFC4251],,,Defined TXT keys: u=<username> p=<password>
    """
    val node = CsvParser(text)
    val serviceList = ServiceListExtractor(node)

    //print(serviceList)

    assert(serviceList ~> "vertices" ~> 0 ~> "_id" === Some(S("ssh")))
    assert(serviceList ~> "vertices" ~> 0 ~> "name" === Some(S("ssh")))
    assert(serviceList ~> "vertices" ~> 0 ~> "description" === Some(S("The Secure Shell (SSH) Protocol")))
    assert(serviceList ~> "vertices" ~> 0 ~> "reference" === Some(S("[RFC4251]")))
    assert(serviceList ~> "vertices" ~> 0 ~> "notes" === Some(S("Defined TXT keys: u=<username> p=<password>")))
    assert(serviceList ~> "vertices" ~> 0 ~> "_type" === Some(S("vertex")))
    assert(serviceList ~> "vertices" ~> 0 ~> "vertexType" === Some(S("service")))
    assert(serviceList ~> "vertices" ~> 0 ~> "source" === Some(S("service_list")))

    assert(serviceList ~> "vertices" ~> 1 ~> "_id" === Some(S("22")))
    assert(serviceList ~> "vertices" ~> 1 ~> "name" === Some(S("22")))
    assert(serviceList ~> "vertices" ~> 1 ~> "description" === Some(S("22")))
    assert(serviceList ~> "vertices" ~> 1 ~> "_type" === Some(S("vertex")))
    assert(serviceList ~> "vertices" ~> 1 ~> "vertexType" === Some(S("port")))
    assert(serviceList ~> "vertices" ~> 1 ~> "source" === Some(S("service_list")))

    assert(serviceList ~> "vertices" ~> 2 === None)

    assert(serviceList ~> "edges" ~> 0 ~> "_id" === Some(S("22_hasKnownService_ssh")))
    assert(serviceList ~> "edges" ~> 0 ~> "description" === Some(S("22 has service ssh")))
    assert(serviceList ~> "edges" ~> 0 ~> "_outV" === Some(S("22")))
    assert(serviceList ~> "edges" ~> 0 ~> "_inV" === Some(S("ssh")))
    assert(serviceList ~> "edges" ~> 0 ~> "_type" === Some(S("edge")))
    assert(serviceList ~> "edges" ~> 0 ~> "_label" === Some(S("hasKnownService")))
    assert(serviceList ~> "edges" ~> 0 ~> "source" === Some(S("service_list")))
    assert(serviceList ~> "edges" ~> 0 ~> "outVType" === Some(S("port")))
    assert(serviceList ~> "edges" ~> 0 ~> "inVType" === Some(S("service")))

    assert(serviceList ~> "edges" ~> 1 === None)
  }

  test("parse some odd client service entries") {

    val text = """Service Name,Port Number,Transport Protocol,Description,Assignee,Contact,Registration Date,Modification Date,Reference,Service Code,Known Unauthorized Uses,Assignment Notes
ssh,22,tcp,The Secure Shell (SSH) Protocol,,,,,[RFC4251],,,Defined TXT keys: u=<username> p=<password>
www-http,80,tcp,World Wide Web HTTP,[Tim_Berners_Lee],[Tim_Berners_Lee],,,,,,"This is a duplicate of the ""http"" service and should not be used for discovery purposes.
      u=<username> p=<password> path=<path to document>
        (see txtrecords.html#http)
        Known Subtypes: _printer
        NOTE: The meaning of this service type, though called just ""http"", actually
        denotes something more precise than just ""any data transported using HTTP"".
        The DNS-SD service type ""http"" should only be used to advertise content that:
        * is served over HTTP,
        * can be displayed by ""typical"" web browser client software, and
        * is intented primarily to be viewed by a human user.
        Of course, the definition of ""typical web browser"" is subjective, and may
        change over time, but for practical purposes the DNS-SD service type ""http""
        can be understood as meaning ""human-readable HTML content served over HTTP"".
        In some cases other widely-supported content types may also be appropriate,
        such as plain text over HTTP, or JPEG image over HTTP.
        Content types not intented primarily for viewing by a human user, or not
        widely-supported in web browsing clients, should not be advertised as
        DNS-SD service type ""http"", even if they do happen to be transported over HTTP.
        Such types should be advertised as their own logical service type with their
        own DNS-SD service type, for example, XUL (XML User Interface Language)
        transported over HTTP is advertised explicitly as DNS-SD service type ""xul-http""."
login,513,tcp,"remote login a la telnet; automatic authentication performed based on priviledged port numbers and distributed data bases which identify ""authentication domains"" ",,,,,,,,
who,513,udp,maintains data bases showing who's logged in to machines on a local net and the load average of the machine,,,,,,,,
sms,,,Short Text Message Sending and Delivery Status Service,[Christian_Flintrup],[Christian_Flintrup],,,,,,Defined TXT keys: Proprietary
    """
    val node = CsvParser(text)
    val serviceList = ServiceListExtractor(node)
   
    //print(serviceList)

    assert(serviceList ~> "vertices" ~> 0 ~> "_id" === Some(S("ssh")))
    assert(serviceList ~> "vertices" ~> 0 ~> "name" === Some(S("ssh")))
    assert(serviceList ~> "vertices" ~> 0 ~> "description" === Some(S("The Secure Shell (SSH) Protocol")))
    assert(serviceList ~> "vertices" ~> 0 ~> "reference" === Some(S("[RFC4251]")))
    assert(serviceList ~> "vertices" ~> 0 ~> "notes" === Some(S("Defined TXT keys: u=<username> p=<password>")))
    assert(serviceList ~> "vertices" ~> 0 ~> "_type" === Some(S("vertex")))
    assert(serviceList ~> "vertices" ~> 0 ~> "vertexType" === Some(S("service")))
    assert(serviceList ~> "vertices" ~> 0 ~> "source" === Some(S("service_list")))

    assert(serviceList ~> "vertices" ~> 1 ~> "_id" === Some(S("22")))
    assert(serviceList ~> "vertices" ~> 1 ~> "name" === Some(S("22")))
    assert(serviceList ~> "vertices" ~> 1 ~> "description" === Some(S("22")))
    assert(serviceList ~> "vertices" ~> 1 ~> "_type" === Some(S("vertex")))
    assert(serviceList ~> "vertices" ~> 1 ~> "vertexType" === Some(S("port")))
    assert(serviceList ~> "vertices" ~> 1 ~> "source" === Some(S("service_list")))

    assert(serviceList ~> "vertices" ~> 2 ~> "_id" === Some(S("www-http")))
    assert(serviceList ~> "vertices" ~> 2 ~> "name" === Some(S("www-http")))
    assert(serviceList ~> "vertices" ~> 2 ~> "description" === Some(S("World Wide Web HTTP")))
    assert(serviceList ~> "vertices" ~> 2 ~> "reference" === Some(S("")))
    assert(serviceList ~> "vertices" ~> 2 ~> "notes" === Some(S("""This is a duplicate of the "http" service and should not be used for discovery purposes.
      u=<username> p=<password> path=<path to document>
        (see txtrecords.html#http)
        Known Subtypes: _printer
        NOTE: The meaning of this service type, though called just "http", actually
        denotes something more precise than just "any data transported using HTTP".
        The DNS-SD service type "http" should only be used to advertise content that:
        * is served over HTTP,
        * can be displayed by "typical" web browser client software, and
        * is intented primarily to be viewed by a human user.
        Of course, the definition of "typical web browser" is subjective, and may
        change over time, but for practical purposes the DNS-SD service type "http"
        can be understood as meaning "human-readable HTML content served over HTTP".
        In some cases other widely-supported content types may also be appropriate,
        such as plain text over HTTP, or JPEG image over HTTP.
        Content types not intented primarily for viewing by a human user, or not
        widely-supported in web browsing clients, should not be advertised as
        DNS-SD service type "http", even if they do happen to be transported over HTTP.
        Such types should be advertised as their own logical service type with their
        own DNS-SD service type, for example, XUL (XML User Interface Language)
        transported over HTTP is advertised explicitly as DNS-SD service type "xul-http".""")))
    assert(serviceList ~> "vertices" ~> 2 ~> "_type" === Some(S("vertex")))
    assert(serviceList ~> "vertices" ~> 2 ~> "vertexType" === Some(S("service")))
    assert(serviceList ~> "vertices" ~> 2 ~> "source" === Some(S("service_list")))

    assert(serviceList ~> "vertices" ~> 3 ~> "_id" === Some(S("80")))
    assert(serviceList ~> "vertices" ~> 3 ~> "name" === Some(S("80")))
    assert(serviceList ~> "vertices" ~> 3 ~> "description" === Some(S("80")))
    assert(serviceList ~> "vertices" ~> 3 ~> "_type" === Some(S("vertex")))
    assert(serviceList ~> "vertices" ~> 3 ~> "vertexType" === Some(S("port")))
    assert(serviceList ~> "vertices" ~> 3 ~> "source" === Some(S("service_list")))

    assert(serviceList ~> "vertices" ~> 4 ~> "_id" === Some(S("login")))
    assert(serviceList ~> "vertices" ~> 4 ~> "name" === Some(S("login")))
    assert(serviceList ~> "vertices" ~> 4 ~> "description" === Some(S("remote login a la telnet; automatic authentication performed based on priviledged port numbers and distributed data bases which identify \"authentication domains\" ")))
    assert(serviceList ~> "vertices" ~> 4 ~> "reference" === Some(S("")))
    assert(serviceList ~> "vertices" ~> 4 ~> "notes" === Some(S("")))
    assert(serviceList ~> "vertices" ~> 4 ~> "_type" === Some(S("vertex")))
    assert(serviceList ~> "vertices" ~> 4 ~> "vertexType" === Some(S("service")))
    assert(serviceList ~> "vertices" ~> 4 ~> "source" === Some(S("service_list")))

    assert(serviceList ~> "vertices" ~> 5 ~> "_id" === Some(S("513")))
    assert(serviceList ~> "vertices" ~> 5 ~> "name" === Some(S("513")))
    assert(serviceList ~> "vertices" ~> 5 ~> "description" === Some(S("513")))
    assert(serviceList ~> "vertices" ~> 5 ~> "_type" === Some(S("vertex")))
    assert(serviceList ~> "vertices" ~> 5 ~> "vertexType" === Some(S("port")))
    assert(serviceList ~> "vertices" ~> 5 ~> "source" === Some(S("service_list")))

    assert(serviceList ~> "vertices" ~> 6 ~> "_id" === Some(S("who")))
    assert(serviceList ~> "vertices" ~> 6 ~> "name" === Some(S("who")))
    assert(serviceList ~> "vertices" ~> 6 ~> "description" === Some(S("maintains data bases showing who's logged in to machines on a local net and the load average of the machine")))
    assert(serviceList ~> "vertices" ~> 6 ~> "reference" === Some(S("")))
    assert(serviceList ~> "vertices" ~> 6 ~> "notes" === Some(S("")))
    assert(serviceList ~> "vertices" ~> 6 ~> "_type" === Some(S("vertex")))
    assert(serviceList ~> "vertices" ~> 6 ~> "vertexType" === Some(S("service")))
    assert(serviceList ~> "vertices" ~> 6 ~> "source" === Some(S("service_list")))

    assert(serviceList ~> "vertices" ~> 7 ~> "_id" === Some(S("513")))
    assert(serviceList ~> "vertices" ~> 7 ~> "name" === Some(S("513")))
    assert(serviceList ~> "vertices" ~> 7 ~> "description" === Some(S("513")))
    assert(serviceList ~> "vertices" ~> 7 ~> "_type" === Some(S("vertex")))
    assert(serviceList ~> "vertices" ~> 7 ~> "vertexType" === Some(S("port")))
    assert(serviceList ~> "vertices" ~> 7 ~> "source" === Some(S("service_list")))

    assert(serviceList ~> "vertices" ~> 8 === None)

    assert(serviceList ~> "edges" ~> 0 ~> "_id" === Some(S("22_hasKnownService_ssh")))
    assert(serviceList ~> "edges" ~> 0 ~> "description" === Some(S("22 has service ssh")))
    assert(serviceList ~> "edges" ~> 0 ~> "_outV" === Some(S("22")))
    assert(serviceList ~> "edges" ~> 0 ~> "_inV" === Some(S("ssh")))
    assert(serviceList ~> "edges" ~> 0 ~> "_type" === Some(S("edge")))
    assert(serviceList ~> "edges" ~> 0 ~> "_label" === Some(S("hasKnownService")))
    assert(serviceList ~> "edges" ~> 0 ~> "source" === Some(S("service_list")))
    assert(serviceList ~> "edges" ~> 0 ~> "outVType" === Some(S("port")))
    assert(serviceList ~> "edges" ~> 0 ~> "inVType" === Some(S("service")))

    assert(serviceList ~> "edges" ~> 1 ~> "_id" === Some(S("80_hasKnownService_www-http")))
    assert(serviceList ~> "edges" ~> 1 ~> "description" === Some(S("80 has service www-http")))
    assert(serviceList ~> "edges" ~> 1 ~> "_outV" === Some(S("80")))
    assert(serviceList ~> "edges" ~> 1 ~> "_inV" === Some(S("www-http")))
    assert(serviceList ~> "edges" ~> 1 ~> "_type" === Some(S("edge")))
    assert(serviceList ~> "edges" ~> 1 ~> "_label" === Some(S("hasKnownService")))
    assert(serviceList ~> "edges" ~> 1 ~> "source" === Some(S("service_list")))
    assert(serviceList ~> "edges" ~> 1 ~> "outVType" === Some(S("port")))
    assert(serviceList ~> "edges" ~> 1 ~> "inVType" === Some(S("service")))

    assert(serviceList ~> "edges" ~> 2 ~> "_id" === Some(S("513_hasKnownService_login")))
    assert(serviceList ~> "edges" ~> 2 ~> "description" === Some(S("513 has service login")))
    assert(serviceList ~> "edges" ~> 2 ~> "_outV" === Some(S("513")))
    assert(serviceList ~> "edges" ~> 2 ~> "_inV" === Some(S("login")))
    assert(serviceList ~> "edges" ~> 2 ~> "_type" === Some(S("edge")))
    assert(serviceList ~> "edges" ~> 2 ~> "_label" === Some(S("hasKnownService")))
    assert(serviceList ~> "edges" ~> 2 ~> "source" === Some(S("service_list")))
    assert(serviceList ~> "edges" ~> 2 ~> "outVType" === Some(S("port")))
    assert(serviceList ~> "edges" ~> 2 ~> "inVType" === Some(S("service")))

    assert(serviceList ~> "edges" ~> 3 ~> "_id" === Some(S("513_hasKnownService_who")))
    assert(serviceList ~> "edges" ~> 3 ~> "description" === Some(S("513 has service who")))
    assert(serviceList ~> "edges" ~> 3 ~> "_outV" === Some(S("513")))
    assert(serviceList ~> "edges" ~> 3 ~> "_inV" === Some(S("who")))
    assert(serviceList ~> "edges" ~> 3 ~> "_type" === Some(S("edge")))
    assert(serviceList ~> "edges" ~> 3 ~> "_label" === Some(S("hasKnownService")))
    assert(serviceList ~> "edges" ~> 3 ~> "source" === Some(S("service_list")))
    assert(serviceList ~> "edges" ~> 3 ~> "outVType" === Some(S("port")))
    assert(serviceList ~> "edges" ~> 3 ~> "inVType" === Some(S("service")))

    assert(serviceList ~> "edges" ~> 4 === None)
  }
  
}
