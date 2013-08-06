import org.scalatest.FunSuite

import morph.ast._
import morph.ast.Implicits._
import morph.ast.DSL._
import morph.parser._
import morph.parser.Interface._
import morph.utils.Utils._

import gov.ornl.stucco.extractors._

class CveExtractorSuite extends FunSuite {

  // to make testing easier
  val O = ObjectNode
  val A = ArrayNode
  val S = StringNode
  val N = NumberNode

test("parse one CVE element with one reference") {
    val node = morph.parser.XmlParser("""
      <?xml version="1.0"?>
      <cve xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
           xmlns="http://cve.mitre.org/cve/downloads"
           xsi:noNamespaceSchemaLocation="http://cve.mitre.org/schema/cve/cve_1.0.xsd">

        <item type="CAN" name="CVE-1999-0001" seq="1999-0001">
        <status>Candidate</status>
        <phase date="20051217">Modified</phase>
        <desc>ip_input.c in BSD-derived TCP/IP implementations allows remote attackers to cause a denial of service (crash or hang) via crafted packets.</desc>
        <refs>
        <ref source="CERT">CA-98-13-tcp-denial-of-service</ref>
        </refs>
        <votes>
        <modify count="1">Frech</modify>
        <noop count="2">Northcutt, Wall</noop>
        <reviewing count="1">Christey</reviewing>
        </votes>
        <comments>
        <comment voter="Christey">A Bugtraq posting indicates that the bug has to do with
        &quot;short packets with certain options set,&quot; so the description
        should be modified accordingly.

        But is this the same as CVE-1999-0052?  That one is related
        to nestea (CVE-1999-0257) and probably the one described in
        BUGTRAQ:19981023 nestea v2 against freebsd 3.0-Release
        The patch for nestea is in ip_input.c around line 750.
        The patches for CVE-1999-0001 are in lines 388&amp;446.  So, 
        CVE-1999-0001 is different from CVE-1999-0257 and CVE-1999-0052.
        The FreeBSD patch for CVE-1999-0052 is in line 750.
        So, CVE-1999-0257 and CVE-1999-0052 may be the same, though
        CVE-1999-0052 should be RECAST since this bug affects Linux
        and other OSes besides FreeBSD.</comment>
        <comment voter="Frech">XF:teardrop(338)
        This assignment was based solely on references to the CERT advisory.</comment>
        <comment voter="Christey">The description for BID:190, which links to CVE-1999-0052 (a
        FreeBSD advisory), notes that the patches provided by FreeBSD in
        CERT:CA-1998-13 suggest a connection between CVE-1999-0001 and
        CVE-1999-0052.  CERT:CA-1998-13 is too vague to be sure without
        further analysis.</comment>
        </comments>
        </item>

      </cve>
      """)
    val cve = CveExtractor(node)
    assert( cve ~> "vertices" ~> 0 ~> "_id" === Some(S("CVE-1999-0001")) )
    assert( cve ~> "vertices" ~> 0 ~> "_type" === Some(S("vertex")) )
    assert( cve ~> "vertices" ~> 0 ~> "source" === Some(S("CVE")) )
    assert( cve ~> "vertices" ~> 0 ~> "description" === Some(S("ip_input.c in BSD-derived TCP/IP implementations allows remote attackers to cause a denial of service (crash or hang) via crafted packets.")) )
    assert( cve ~> "vertices" ~> 0 ~> "status" === Some(S("Candidate")) )
    assert( cve ~> "vertices" ~> 0 ~> "references" ~> 0 === Some(S("CERT:CA-98-13-tcp-denial-of-service")) )
    assert( (cve get "vertices" get 0 get "phaseDate") === Some(N(20051217)) )
    assert( (cve get "vertices" get 0 get "phase") === Some(S("Modified")) )
  }

  test("parse two CVE elements with several references") {
    val node = morph.parser.XmlParser("""
      <?xml version="1.0"?>
      <cve xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
           xmlns="http://cve.mitre.org/cve/downloads"
           xsi:noNamespaceSchemaLocation="http://cve.mitre.org/schema/cve/cve_1.0.xsd">

        <item type="CVE" name="CVE-1999-0002" seq="1999-0002">
        <status>Entry</status>
        <desc>Buffer overflow in NFS mountd gives root access to remote attackers, mostly in Linux systems.</desc>
        <refs>
        <ref source="SGI" url="ftp://patches.sgi.com/support/free/security/advisories/19981006-01-I">19981006-01-I</ref>
        <ref source="CERT">CA-98.12.mountd</ref>
        <ref source="CIAC" url="http://www.ciac.org/ciac/bulletins/j-006.shtml">J-006</ref>
        <ref source="BID" url="http://www.securityfocus.com/bid/121">121</ref>
        <ref source="XF">linux-mountd-bo</ref>
        </refs>
        </item>

        <item type="CAN" name="CVE-2011-0528" seq="2011-0528">
        <status>Candidate</status>
        <phase date="20110120">Assigned</phase>
        <desc>** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem.  When the candidate has been publicized, the details for this candidate will be provided.</desc>
        <refs>
        </refs>
        <votes>
        </votes>
        <comments>
        </comments>
        </item>

      </cve>
      """)
    val cve = CveExtractor(node)
    assert( cve ~> "vertices" ~> 0 ~> "_id" === Some(S("CVE-1999-0002")) )
    assert( cve ~> "vertices" ~> 0 ~> "_type" === Some(S("vertex")) )
    assert( cve ~> "vertices" ~> 0 ~> "source" === Some(S("CVE")) )
    assert( cve ~> "vertices" ~> 0 ~> "description" === Some(S("Buffer overflow in NFS mountd gives root access to remote attackers, mostly in Linux systems.")) )
    assert( cve ~> "vertices" ~> 0 ~> "status" === Some(S("Entry")) )
    assert( cve ~> "vertices" ~> 0 ~> "references" ~> 0 === Some(S("ftp://patches.sgi.com/support/free/security/advisories/19981006-01-I")) )
    assert( cve ~> "vertices" ~> 0 ~> "references" ~> 1 === Some(S("CERT:CA-98.12.mountd")) )
    assert( cve ~> "vertices" ~> 0 ~> "references" ~> 2 === Some(S("http://www.ciac.org/ciac/bulletins/j-006.shtml")) )
    assert( cve ~> "vertices" ~> 0 ~> "references" ~> 3 === Some(S("http://www.securityfocus.com/bid/121")) )
    assert( cve ~> "vertices" ~> 0 ~> "references" ~> 4 === Some(S("XF:linux-mountd-bo")) )

    assert( cve ~> "vertices" ~> 1 ~> "_id" === Some(S("CVE-2011-0528")) )
    assert( cve ~> "vertices" ~> 1 ~> "_type" === Some(S("vertex")) )
    assert( cve ~> "vertices" ~> 1 ~> "source" === Some(S("CVE")) )
    assert( cve ~> "vertices" ~> 1 ~> "description" === Some(S("** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem.  When the candidate has been publicized, the details for this candidate will be provided.")) )
    assert( (cve get "vertices" get 1 get "phaseDate") === Some(N(20110120)) )
    assert( (cve get "vertices" get 1 get "phase") === Some(S("Assigned")) )
    assert( (cve get "vertices" get 1 get "status") === Some(S("Candidate")) )
  }

}



