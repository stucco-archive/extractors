import org.scalatest.FunSuite

import morph.ast._
import morph.ast.Implicits._
import morph.ast.DSL._
import morph.parser._
import morph.parser.Interface._
import morph.utils.Utils._

import gov.ornl.stucco.extractors._

class NvdExtractorSuite extends FunSuite {

  // to make testing easier
  val O = ObjectNode
  val A = ArrayNode
  val S = StringNode
  val N = NumberNode

  test("parse one simple NVD element") {
    val node = morph.parser.XmlParser("""
    <?xml version='1.0' encoding='UTF-8'?>
    <nvd xmlns:scap-core="http://scap.nist.gov/schema/scap-core/0.1" xmlns="http://scap.nist.gov/schema/feed/vulnerability/2.0" xmlns:cpe-lang="http://cpe.mitre.org/language/2.0" xmlns:cvss="http://scap.nist.gov/schema/cvss-v2/0.2" xmlns:patch="http://scap.nist.gov/schema/patch/0.1" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:vuln="http://scap.nist.gov/schema/vulnerability/0.4" nvd_xml_version="2.0" pub_date="2013-07-22T10:00:00" xsi:schemaLocation="http://scap.nist.gov/schema/patch/0.1 http://nvd.nist.gov/schema/patch_0.1.xsd http://scap.nist.gov/schema/scap-core/0.1 http://nvd.nist.gov/schema/scap-core_0.1.xsd http://scap.nist.gov/schema/feed/vulnerability/2.0 http://nvd.nist.gov/schema/nvd-cve-feed_2.0.xsd">

      <entry id="CVE-2013-2361">
        <vuln:cve-id>CVE-2013-2361</vuln:cve-id>
        <vuln:published-datetime>2013-07-22T07:19:36.253-04:00</vuln:published-datetime>
        <vuln:last-modified-datetime>2013-07-22T07:19:36.253-04:00</vuln:last-modified-datetime>
        
        <vuln:references xml:lang="en" reference_type="UNKNOWN">
          <vuln:source>HP</vuln:source>
          <vuln:reference href="https://h20564.www2.hp.com/portal/site/hpsc/public/kb/docDisplay?docId=emr_na-c03839862" xml:lang="en">HPSBMU02900</vuln:reference>
        </vuln:references>
        <vuln:references xml:lang="en" reference_type="UNKNOWN">
          <vuln:source>SOURCE</vuln:source>
          <vuln:reference xml:lang="en">description</vuln:reference>
        </vuln:references>

        <vuln:vulnerable-software-list>
          <vuln:product>cpe:/a:HP:System_Management_Homepage:7.2.0</vuln:product>
        </vuln:vulnerable-software-list>

        <vuln:summary>Cross-site scripting (XSS) vulnerability in HP System Management Homepage (SMH) before 7.2.1 allows remote attackers to inject arbitrary web script or HTML via unspecified vectors.</vuln:summary>
      </entry>

    </nvd>
      """)
    val nvd = NvdExtractor(node)
    //print(nvd)
    assert(nvd ~> "vertices" ~> 0 ~> "_id" === Some(S("CVE-2013-2361")))
    assert(nvd ~> "vertices" ~> 0 ~> "_type" === Some(S("vertex")))
    assert(nvd ~> "vertices" ~> 0 ~> "source" === Some(S("NVD")))
    assert(nvd ~> "vertices" ~> 0 ~> "description" === Some(S("Cross-site scripting (XSS) vulnerability in HP System Management Homepage (SMH) before 7.2.1 allows remote attackers to inject arbitrary web script or HTML via unspecified vectors.")))
    assert(nvd ~> "vertices" ~> 0 ~> "references" ~> 0 === Some(S("https://h20564.www2.hp.com/portal/site/hpsc/public/kb/docDisplay?docId=emr_na-c03839862")))
    assert(nvd ~> "vertices" ~> 0 ~> "references" ~> 1 === Some(S("SOURCE:description")))
    assert((nvd get "vertices" get 0 get "publishedDate") === Some(S("2013-07-22T07:19:36.253-04:00")))
    assert((nvd get "vertices" get 0 get "modifiedDate") === Some(S("2013-07-22T07:19:36.253-04:00")))

    assert(nvd ~> "edges" ~> 0 ~> "_id" === Some(S("CVE-2013-2361")))
    assert(nvd ~> "edges" ~> 0 ~> "_type" === Some(S("edge")))
    assert(nvd ~> "edges" ~> 0 ~> "inVType" === Some(S("vulnerability")))
    assert(nvd ~> "edges" ~> 0 ~> "outVType" === Some(S("software")))
    assert(nvd ~> "edges" ~> 0 ~> "source" === Some(S("NVD")))
    assert(nvd ~> "edges" ~> 0 ~> "_inV" === Some(S("CVE-2013-2361")))
    assert(nvd ~> "edges" ~> 0 ~> "_outV" === Some(S("cpe:/a:HP:System_Management_Homepage:7.2.0")))
    assert(nvd ~> "edges" ~> 0 ~> "_label" === Some(S("cpe:/a:HP:System_Management_Homepage:7.2.0_to_CVE-2013-2361")))

  }

  test("parse two NVD elements (w/o references)") {
    val node = morph.parser.XmlParser("""
    <?xml version='1.0' encoding='UTF-8'?>
    <nvd xmlns:scap-core="http://scap.nist.gov/schema/scap-core/0.1" xmlns="http://scap.nist.gov/schema/feed/vulnerability/2.0" xmlns:cpe-lang="http://cpe.mitre.org/language/2.0" xmlns:cvss="http://scap.nist.gov/schema/cvss-v2/0.2" xmlns:patch="http://scap.nist.gov/schema/patch/0.1" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:vuln="http://scap.nist.gov/schema/vulnerability/0.4" nvd_xml_version="2.0" pub_date="2013-07-22T10:00:00" xsi:schemaLocation="http://scap.nist.gov/schema/patch/0.1 http://nvd.nist.gov/schema/patch_0.1.xsd http://scap.nist.gov/schema/scap-core/0.1 http://nvd.nist.gov/schema/scap-core_0.1.xsd http://scap.nist.gov/schema/feed/vulnerability/2.0 http://nvd.nist.gov/schema/nvd-cve-feed_2.0.xsd">

      <entry id="CVE-2013-4878">

        <vuln:vulnerable-configuration id="http://nvd.nist.gov/">
          <cpe-lang:logical-test negate="false" operator="AND">
            <cpe-lang:logical-test negate="false" operator="OR">
              <cpe-lang:fact-ref name="cpe:/a:parallels:parallels_plesk_panel:9.2"/>
              <cpe-lang:fact-ref name="cpe:/a:parallels:parallels_plesk_panel:9.0"/>
              <cpe-lang:fact-ref name="cpe:/a:parallels:parallels_small_business_panel:10.0"/>
            </cpe-lang:logical-test>
            <cpe-lang:logical-test negate="false" operator="OR">
              <cpe-lang:fact-ref name="cpe:/o:linux:linux_kernel"/>
            </cpe-lang:logical-test>
          </cpe-lang:logical-test>
        </vuln:vulnerable-configuration>

        <vuln:cve-id>CVE-2013-4878</vuln:cve-id>

        <vuln:published-datetime>2013-07-18T12:51:56.227-04:00</vuln:published-datetime>
        <vuln:last-modified-datetime>2013-07-19T16:51:21.577-04:00</vuln:last-modified-datetime>

        <vuln:cvss>
          <cvss:base_metrics>
            <cvss:score>6.8</cvss:score>
            <cvss:access-vector>NETWORK</cvss:access-vector>
            <cvss:access-complexity>MEDIUM</cvss:access-complexity>
            <cvss:authentication>NONE</cvss:authentication>
            <cvss:confidentiality-impact>PARTIAL</cvss:confidentiality-impact>
            <cvss:integrity-impact>PARTIAL</cvss:integrity-impact>
            <cvss:availability-impact>PARTIAL</cvss:availability-impact>
            <cvss:source>http://nvd.nist.gov</cvss:source>
            <cvss:generated-on-datetime>2013-07-19T16:37:00.000-04:00</cvss:generated-on-datetime>
          </cvss:base_metrics>
        </vuln:cvss>

        <vuln:cwe id="CWE-264"/>

        <vuln:summary>The default configuration of Parallels Plesk Panel 9.0.x and 9.2.x on UNIX, and Small Business Panel 10.x on UNIX, has an improper ScriptAlias directive for phppath, which makes it easier for remote attackers to execute arbitrary code via a crafted request, a different vulnerability than CVE-2012-1823.</vuln:summary>
      </entry>

      <entry id="CVE-2013-5217">
        <vuln:cve-id>CVE-2013-5217</vuln:cve-id>
        <vuln:published-datetime>2013-07-22T07:20:46.637-04:00</vuln:published-datetime>
        <vuln:last-modified-datetime>2013-07-22T07:20:47.053-04:00</vuln:last-modified-datetime>
        <vuln:summary>** REJECT **  DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: CVE-2012-5217.  Reason: This candidate is a duplicate of CVE-2012-5217.  A typo caused the wrong ID to be used.  Notes: All CVE users should reference CVE-2012-5217 instead of this candidate.  All references and descriptions in this candidate have been removed to prevent accidental usage.</vuln:summary>
      </entry>

    </nvd>
      """)
    val nvd = NvdExtractor(node)
    //print(nvd)
    assert(nvd ~> "vertices" ~> 0 ~> "_id" === Some(S("CVE-2013-4878")))
    assert(nvd ~> "vertices" ~> 0 ~> "_type" === Some(S("vertex")))
    assert(nvd ~> "vertices" ~> 0 ~> "source" === Some(S("NVD")))
    assert(nvd ~> "vertices" ~> 0 ~> "description" === Some(S("The default configuration of Parallels Plesk Panel 9.0.x and 9.2.x on UNIX, and Small Business Panel 10.x on UNIX, has an improper ScriptAlias directive for phppath, which makes it easier for remote attackers to execute arbitrary code via a crafted request, a different vulnerability than CVE-2012-1823.")))
    assert((nvd get "vertices" get 0 get "publishedDate") === Some(S("2013-07-18T12:51:56.227-04:00")))
    assert((nvd get "vertices" get 0 get "modifiedDate") === Some(S("2013-07-19T16:51:21.577-04:00")))

    assert(nvd ~> "vertices" ~> 0 ~> "cweNumber" === Some(S("CWE-264")))
    assert(nvd ~> "vertices" ~> 0 ~> "cvssScore" === Some(N(6.8)))
    assert(nvd ~> "vertices" ~> 0 ~> "cvssDate" === Some(S("2013-07-19T16:37:00.000-04:00")))
    assert(nvd ~> "vertices" ~> 0 ~> "accessVector" === Some(S("NETWORK")))
    assert(nvd ~> "vertices" ~> 0 ~> "accessComplexity" === Some(S("MEDIUM")))
    assert(nvd ~> "vertices" ~> 0 ~> "accessAuthentication" === Some(S("NONE")))
    assert(nvd ~> "vertices" ~> 0 ~> "confidentialityImpact" === Some(S("PARTIAL")))
    assert(nvd ~> "vertices" ~> 0 ~> "integrityImpact" === Some(S("PARTIAL")))
    assert(nvd ~> "vertices" ~> 0 ~> "availabilityImpact" === Some(S("PARTIAL")))

    assert(nvd ~> "vertices" ~> 1 ~> "_id" === Some(S("CVE-2013-5217")))
    assert(nvd ~> "vertices" ~> 1 ~> "_type" === Some(S("vertex")))
    assert(nvd ~> "vertices" ~> 1 ~> "source" === Some(S("NVD")))
    assert(nvd ~> "vertices" ~> 1 ~> "description" === Some(S("** REJECT **  DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: CVE-2012-5217.  Reason: This candidate is a duplicate of CVE-2012-5217.  A typo caused the wrong ID to be used.  Notes: All CVE users should reference CVE-2012-5217 instead of this candidate.  All references and descriptions in this candidate have been removed to prevent accidental usage.")))
    assert((nvd get "vertices" get 1 get "publishedDate") === Some(S("2013-07-22T07:20:46.637-04:00")))
    assert((nvd get "vertices" get 1 get "modifiedDate") === Some(S("2013-07-22T07:20:47.053-04:00")))
  }

  test("check CPE->NVD edges") {
    val node = morph.parser.XmlParser("""
    <?xml version='1.0' encoding='UTF-8'?>
    <nvd xmlns:scap-core="http://scap.nist.gov/schema/scap-core/0.1" xmlns="http://scap.nist.gov/schema/feed/vulnerability/2.0" xmlns:cpe-lang="http://cpe.mitre.org/language/2.0" xmlns:cvss="http://scap.nist.gov/schema/cvss-v2/0.2" xmlns:patch="http://scap.nist.gov/schema/patch/0.1" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:vuln="http://scap.nist.gov/schema/vulnerability/0.4" nvd_xml_version="2.0" pub_date="2013-07-22T10:00:00" xsi:schemaLocation="http://scap.nist.gov/schema/patch/0.1 http://nvd.nist.gov/schema/patch_0.1.xsd http://scap.nist.gov/schema/scap-core/0.1 http://nvd.nist.gov/schema/scap-core_0.1.xsd http://scap.nist.gov/schema/feed/vulnerability/2.0 http://nvd.nist.gov/schema/nvd-cve-feed_2.0.xsd">

      <entry id="CVE-2099-0001">
      </entry>

      <entry id="CVE-2099-0002">
        <vuln:vulnerable-software-list>
          <vuln:product>cpe:/a:parallels:parallels_plesk_panel:9.2</vuln:product>
        </vuln:vulnerable-software-list>
      </entry>

      <entry id="CVE-2099-0003">
        <vuln:vulnerable-software-list>
          <vuln:product>cpe:/a:parallels:parallels_small_business_panel:10.0</vuln:product>
          <vuln:product>cpe:/a:parallels:parallels_plesk_panel:9.0</vuln:product>
          <vuln:product>cpe:/a:parallels:parallels_plesk_panel:9.2</vuln:product>
        </vuln:vulnerable-software-list>
      </entry>

    </nvd>
      """)
    val nvd = NvdExtractor(node)
    //print(nvd)
    assert(nvd ~> "edges" ~> 0 ~> "_id" === Some(S("CVE-2099-0002")))
    assert(nvd ~> "edges" ~> 0 ~> "_type" === Some(S("edge")))
    assert(nvd ~> "edges" ~> 0 ~> "inVType" === Some(S("vulnerability")))
    assert(nvd ~> "edges" ~> 0 ~> "outVType" === Some(S("software")))
    assert(nvd ~> "edges" ~> 0 ~> "source" === Some(S("NVD")))
    assert(nvd ~> "edges" ~> 0 ~> "_inV" === Some(S("CVE-2099-0002")))
    assert(nvd ~> "edges" ~> 0 ~> "_outV" === Some(S("cpe:/a:parallels:parallels_plesk_panel:9.2")))
    assert(nvd ~> "edges" ~> 0 ~> "_label" === Some(S("cpe:/a:parallels:parallels_plesk_panel:9.2_to_CVE-2099-0002")))

    assert(nvd ~> "edges" ~> 1 ~> "_id" === Some(S("CVE-2099-0003")))
    assert(nvd ~> "edges" ~> 1 ~> "_type" === Some(S("edge")))
    assert(nvd ~> "edges" ~> 1 ~> "inVType" === Some(S("vulnerability")))
    assert(nvd ~> "edges" ~> 1 ~> "outVType" === Some(S("software")))
    assert(nvd ~> "edges" ~> 1 ~> "source" === Some(S("NVD")))
    assert(nvd ~> "edges" ~> 1 ~> "_inV" === Some(S("CVE-2099-0003")))
    assert(nvd ~> "edges" ~> 1 ~> "_outV" === Some(S("cpe:/a:parallels:parallels_small_business_panel:10.0")))
    assert(nvd ~> "edges" ~> 1 ~> "_label" === Some(S("cpe:/a:parallels:parallels_small_business_panel:10.0_to_CVE-2099-0003")))

    assert(nvd ~> "edges" ~> 2 ~> "_id" === Some(S("CVE-2099-0003")))
    assert(nvd ~> "edges" ~> 2 ~> "_type" === Some(S("edge")))
    assert(nvd ~> "edges" ~> 2 ~> "inVType" === Some(S("vulnerability")))
    assert(nvd ~> "edges" ~> 2 ~> "outVType" === Some(S("software")))
    assert(nvd ~> "edges" ~> 2 ~> "source" === Some(S("NVD")))
    assert(nvd ~> "edges" ~> 2 ~> "_inV" === Some(S("CVE-2099-0003")))
    assert(nvd ~> "edges" ~> 2 ~> "_outV" === Some(S("cpe:/a:parallels:parallels_plesk_panel:9.0")))
    assert(nvd ~> "edges" ~> 2 ~> "_label" === Some(S("cpe:/a:parallels:parallels_plesk_panel:9.0_to_CVE-2099-0003")))

    assert(nvd ~> "edges" ~> 3 ~> "_id" === Some(S("CVE-2099-0003")))
    assert(nvd ~> "edges" ~> 3 ~> "_type" === Some(S("edge")))
    assert(nvd ~> "edges" ~> 3 ~> "inVType" === Some(S("vulnerability")))
    assert(nvd ~> "edges" ~> 3 ~> "outVType" === Some(S("software")))
    assert(nvd ~> "edges" ~> 3 ~> "source" === Some(S("NVD")))
    assert(nvd ~> "edges" ~> 3 ~> "_inV" === Some(S("CVE-2099-0003")))
    assert(nvd ~> "edges" ~> 3 ~> "_outV" === Some(S("cpe:/a:parallels:parallels_plesk_panel:9.2")))
    assert(nvd ~> "edges" ~> 3 ~> "_label" === Some(S("cpe:/a:parallels:parallels_plesk_panel:9.2_to_CVE-2099-0003")))

  }

}

