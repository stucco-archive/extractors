import org.scalatest.FunSuite

import gov.ornl.stucco.morph.ast._
import gov.ornl.stucco.morph.ast.Implicits._
import gov.ornl.stucco.morph.ast.DSL._
import gov.ornl.stucco.morph.parser._
import gov.ornl.stucco.morph.parser.Interface._
import gov.ornl.stucco.morph.utils.Utils._

import gov.ornl.stucco.extractors._

class CpeExtractorSuite extends FunSuite {

  // to make testing easier
  val O = ObjectNode
  val A = ArrayNode
  val S = StringNode
  val N = NumberNode

  test("parse one simple CPE element") {
    val node = XmlParser("""
    <?xml version='1.0' encoding='UTF-8'?>
    <cpe-list xmlns:meta="http://scap.nist.gov/schema/cpe-dictionary-metadata/0.2" xmlns:scap-core="http://scap.nist.gov/schema/scap-core/0.3" xmlns:config="http://scap.nist.gov/schema/configuration/0.1" xmlns="http://cpe.mitre.org/dictionary/2.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:ns6="http://scap.nist.gov/schema/scap-core/0.1" xsi:schemaLocation="http://scap.nist.gov/schema/configuration/0.1 http://nvd.nist.gov/schema/configuration_0.1.xsd http://scap.nist.gov/schema/scap-core/0.3 http://nvd.nist.gov/schema/scap-core_0.3.xsd http://cpe.mitre.org/dictionary/2.0 http://cpe.mitre.org/files/cpe-dictionary_2.2.xsd http://scap.nist.gov/schema/scap-core/0.1 http://nvd.nist.gov/schema/scap-core_0.1.xsd http://scap.nist.gov/schema/cpe-dictionary-metadata/0.2 http://nvd.nist.gov/schema/cpe-dictionary-metadata_0.2.xsd">
      <generator>
        <product_name>National Vulnerability Database (NVD)</product_name>
        <product_version>2.18.0-SNAPSHOT (PRODUCTION)</product_version>
        <schema_version>2.2</schema_version>
        <timestamp>2013-03-19T03:50:00.109Z</timestamp>
      </generator>
      <cpe-item name="cpe:/a:1024cms:1024_cms:0.7">
        <title xml:lang="en-US">1024cms.org 1024 CMS 0.7</title>
        <meta:item-metadata modification-date="2010-12-14T19:38:32.197Z" status="DRAFT" nvd-id="121218"/>
      </cpe-item>
    </cpe-list>
      """)
    val cpe = CpeExtractor(node)
    //print(cpe)
    assert(cpe ~> "vertices" ~> 0 ~> "_id" === Some(S("cpe:/a:1024cms:1024_cms:0.7")))
    assert(cpe ~> "vertices" ~> 0 ~> "_type" === Some(S("vertex")))
    assert(cpe ~> "vertices" ~> 0 ~> "source" === Some(S("CPE")))
    assert(cpe ~> "vertices" ~> 0 ~> "vertexType" === Some(S("software")))

    assert(cpe ~> "vertices" ~> 0 ~> "description" === Some(S("1024cms.org 1024 CMS 0.7")))
    assert(cpe ~> "vertices" ~> 0 ~> "nvdId" === Some(N(121218)))
    assert(cpe ~> "vertices" ~> 0 ~> "status" === Some(S("DRAFT")))
    assert(cpe ~> "vertices" ~> 0 ~> "modifiedDate" === Some(S("2010-12-14T19:38:32.197Z")))

    assert(cpe ~> "vertices" ~> 0 ~> "part" === Some(S("/a")))
    assert(cpe ~> "vertices" ~> 0 ~> "vendor" === Some(S("1024cms")))
    assert(cpe ~> "vertices" ~> 0 ~> "product" === Some(S("1024_cms")))
    assert(cpe ~> "vertices" ~> 0 ~> "version" === Some(S("0.7")))
    assert(cpe ~> "vertices" ~> 0 ~> "update" === None)
    assert(cpe ~> "vertices" ~> 0 ~> "edition" === None)
    assert(cpe ~> "vertices" ~> 0 ~> "language" === None)
  }

  test("parse several CPE elements") {
    val node = XmlParser("""
    <?xml version='1.0' encoding='UTF-8'?>
    <cpe-list xmlns:meta="http://scap.nist.gov/schema/cpe-dictionary-metadata/0.2" xmlns:scap-core="http://scap.nist.gov/schema/scap-core/0.3" xmlns:config="http://scap.nist.gov/schema/configuration/0.1" xmlns="http://cpe.mitre.org/dictionary/2.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:ns6="http://scap.nist.gov/schema/scap-core/0.1" xsi:schemaLocation="http://scap.nist.gov/schema/configuration/0.1 http://nvd.nist.gov/schema/configuration_0.1.xsd http://scap.nist.gov/schema/scap-core/0.3 http://nvd.nist.gov/schema/scap-core_0.3.xsd http://cpe.mitre.org/dictionary/2.0 http://cpe.mitre.org/files/cpe-dictionary_2.2.xsd http://scap.nist.gov/schema/scap-core/0.1 http://nvd.nist.gov/schema/scap-core_0.1.xsd http://scap.nist.gov/schema/cpe-dictionary-metadata/0.2 http://nvd.nist.gov/schema/cpe-dictionary-metadata_0.2.xsd">
      <generator>
        <product_name>National Vulnerability Database (NVD)</product_name>
        <product_version>2.18.0-SNAPSHOT (PRODUCTION)</product_version>
        <schema_version>2.2</schema_version>
        <timestamp>2013-03-19T03:50:00.109Z</timestamp>
      </generator>
      <cpe-item name="cpe:/a:microsoft:hotmail">
        <title xml:lang="en-US">Microsoft Hotmail</title>
        <meta:item-metadata modification-date="2007-09-14T17:36:49.090Z" status="DRAFT" nvd-id="7005"/>
      </cpe-item>
      <cpe-item deprecation_date="2011-04-20T14:22:38.607Z" deprecated_by="cpe:/o:yamaha:rtx1100:8.03.82" deprecated="true" name="cpe:/o:yahama:rtx1100:8.03.82">
        <title xml:lang="en-US">Yamaha RTX1100 8.03.82</title>
        <title xml:lang="ja-JP">ヤマハ RTX1100 8.03.82</title>
        <meta:item-metadata modification-date="2011-04-20T14:22:38.607Z" status="DRAFT" deprecated-by-nvd-id="145415" nvd-id="144720"/>
      </cpe-item>
      <cpe-item name="cpe:/o:yamaha:srt100:10.00.56">
        <title xml:lang="en-US">Yamaha SRT100 10.00.56</title>
        <title xml:lang="ja-JP">ヤマハ SRT100 10.00.56</title>
        <meta:item-metadata modification-date="2011-04-20T02:08:53.277Z" status="DRAFT" nvd-id="145456"/>
      </cpe-item>
    </cpe-list>
      """)
    val cpe = CpeExtractor(node)
    //print(cpe)

    assert(cpe ~> "vertices" ~> 0 ~> "_id" === Some(S("cpe:/a:microsoft:hotmail")))
    assert(cpe ~> "vertices" ~> 0 ~> "_type" === Some(S("vertex")))
    assert(cpe ~> "vertices" ~> 0 ~> "source" === Some(S("CPE")))
    assert(cpe ~> "vertices" ~> 0 ~> "vertexType" === Some(S("software")))
    assert(cpe ~> "vertices" ~> 0 ~> "description" === Some(S("Microsoft Hotmail")))
    assert(cpe ~> "vertices" ~> 0 ~> "nvdId" === Some(N(7005)))
    assert(cpe ~> "vertices" ~> 0 ~> "status" === Some(S("DRAFT")))
    assert(cpe ~> "vertices" ~> 0 ~> "modifiedDate" === Some(S("2007-09-14T17:36:49.090Z")))
    assert(cpe ~> "vertices" ~> 0 ~> "part" === Some(S("/a")))
    assert(cpe ~> "vertices" ~> 0 ~> "vendor" === Some(S("microsoft")))
    assert(cpe ~> "vertices" ~> 0 ~> "product" === Some(S("hotmail")))
    assert(cpe ~> "vertices" ~> 0 ~> "version" === None)
    assert(cpe ~> "vertices" ~> 0 ~> "update" === None)
    assert(cpe ~> "vertices" ~> 0 ~> "edition" === None)
    assert(cpe ~> "vertices" ~> 0 ~> "language" === None)

    //TODO also is dep., presumably because of typo.  Should probably be marked as such somehow.
    assert(cpe ~> "vertices" ~> 1 ~> "_id" === Some(S("cpe:/o:yahama:rtx1100:8.03.82")))
    assert(cpe ~> "vertices" ~> 1 ~> "_type" === Some(S("vertex")))
    assert(cpe ~> "vertices" ~> 1 ~> "source" === Some(S("CPE")))
    assert(cpe ~> "vertices" ~> 1 ~> "vertexType" === Some(S("software")))
    assert(cpe ~> "vertices" ~> 1 ~> "description" === Some(S("Yamaha RTX1100 8.03.82")))
    assert(cpe ~> "vertices" ~> 1 ~> "nvdId" === Some(N(144720)))
    assert(cpe ~> "vertices" ~> 1 ~> "status" === Some(S("DRAFT")))
    assert(cpe ~> "vertices" ~> 1 ~> "modifiedDate" === Some(S("2011-04-20T14:22:38.607Z")))
    assert(cpe ~> "vertices" ~> 1 ~> "part" === Some(S("/o")))
    assert(cpe ~> "vertices" ~> 1 ~> "vendor" === Some(S("yahama")))
    assert(cpe ~> "vertices" ~> 1 ~> "product" === Some(S("rtx1100")))
    assert(cpe ~> "vertices" ~> 1 ~> "version" === Some(S("8.03.82")))
    assert(cpe ~> "vertices" ~> 1 ~> "update" === None)
    assert(cpe ~> "vertices" ~> 1 ~> "edition" === None)
    assert(cpe ~> "vertices" ~> 1 ~> "language" === None)

    assert(cpe ~> "vertices" ~> 2 ~> "_id" === Some(S("cpe:/o:yamaha:srt100:10.00.56")))
    assert(cpe ~> "vertices" ~> 2 ~> "_type" === Some(S("vertex")))
    assert(cpe ~> "vertices" ~> 2 ~> "source" === Some(S("CPE")))
    assert(cpe ~> "vertices" ~> 2 ~> "vertexType" === Some(S("software")))
    assert(cpe ~> "vertices" ~> 2 ~> "description" === Some(S("Yamaha SRT100 10.00.56")))
    assert(cpe ~> "vertices" ~> 2 ~> "nvdId" === Some(N(145456)))
    assert(cpe ~> "vertices" ~> 2 ~> "status" === Some(S("DRAFT")))
    assert(cpe ~> "vertices" ~> 2 ~> "modifiedDate" === Some(S("2011-04-20T02:08:53.277Z")))
    assert(cpe ~> "vertices" ~> 2 ~> "part" === Some(S("/o")))
    assert(cpe ~> "vertices" ~> 2 ~> "vendor" === Some(S("yamaha")))
    assert(cpe ~> "vertices" ~> 2 ~> "product" === Some(S("srt100")))
    assert(cpe ~> "vertices" ~> 2 ~> "version" === Some(S("10.00.56")))
    assert(cpe ~> "vertices" ~> 2 ~> "update" === None)
    assert(cpe ~> "vertices" ~> 2 ~> "edition" === None)
    assert(cpe ~> "vertices" ~> 2 ~> "language" === None)
  }

}

