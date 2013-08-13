import org.scalatest.FunSuite

import morph.ast._
import morph.ast.Implicits._
import morph.ast.DSL._
import morph.parser._
import morph.parser.Interface._
import morph.utils.Utils._

import gov.ornl.stucco.extractors._

class CpeExtractorSuite extends FunSuite {

  // to make testing easier
  val O = ObjectNode
  val A = ArrayNode
  val S = StringNode
  val N = NumberNode

  test("parse one simple CPE element") {
    val node = morph.parser.XmlParser("""
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
      <cpe-item name="cpe:/a:microsoft:hotmail">
        <title xml:lang="en-US">Microsoft Hotmail</title>
        <meta:item-metadata modification-date="2007-09-14T17:36:49.090Z" status="DRAFT" nvd-id="7005"/>
      </cpe-item>
      <cpe-item deprecation_date="2011-04-20T14:22:38.607Z" deprecated_by="cpe:/o:yamaha:rtx1100:8.03.82" deprecated="true" name="cpe:/o:yahama:rtx1100:8.03.82">
        <title xml:lang="en-US">Yamaha RTX1100 8.03.82</title>
        <title xml:lang="ja-JP">ヤマハ RTX1100 8.03.82</title>
        <meta:item-metadata modification-date="2011-04-20T14:22:38.607Z" status="DRAFT" deprecated-by-nvd-id="145415" nvd-id="144720"/>
      </cpe-item>
      <cpe-item deprecation_date="2011-04-20T14:22:38.920Z" deprecated_by="cpe:/o:yamaha:rtx1100:8.03.83" deprecated="true" name="cpe:/o:yahama:rtx1100:8.03.83">
        <title xml:lang="en-US">Yamaha RTX1100 8.03.83</title>
        <title xml:lang="ja-JP">ヤマハ RTX1100 8.03.83</title>
        <meta:item-metadata modification-date="2011-04-20T14:22:38.920Z" status="DRAFT" deprecated-by-nvd-id="145416" nvd-id="144721"/>
      </cpe-item>
      <cpe-item deprecation_date="2011-04-20T14:22:39.247Z" deprecated_by="cpe:/o:yamaha:rtx1100:8.03.87" deprecated="true" name="cpe:/o:yahama:rtx1100:8.03.87">
        <title xml:lang="en-US">Yamaha RTX1100 8.03.87</title>
        <title xml:lang="ja-JP">ヤマハ RTX1100 8.03.87</title>
        <meta:item-metadata modification-date="2011-04-20T14:22:39.247Z" status="DRAFT" deprecated-by-nvd-id="145417" nvd-id="144722"/>
      </cpe-item>
      <cpe-item name="cpe:/o:yamaha:rtx1100:8.03.37">
        <title xml:lang="en-US">Yamaha RTX1100 8.03.37</title>
        <title xml:lang="ja-JP">ヤマハ RTX1100 8.03.37</title>
        <meta:item-metadata modification-date="2011-04-20T02:08:41.340Z" status="DRAFT" nvd-id="145402"/>
      </cpe-item>
      <cpe-item name="cpe:/o:yamaha:rtx1100:8.03.41">
        <title xml:lang="en-US">Yamaha RTX1100 8.03.41</title>
        <title xml:lang="ja-JP">ヤマハ RTX1100 8.03.41</title>
        <meta:item-metadata modification-date="2011-04-20T02:08:41.573Z" status="DRAFT" nvd-id="145403"/>
      </cpe-item>
      <cpe-item name="cpe:/o:yamaha:rtx1100:8.03.42">
        <title xml:lang="en-US">Yamaha RTX1100 8.03.42</title>
        <title xml:lang="ja-JP">ヤマハ RTX1100 8.03.42</title>
        <meta:item-metadata modification-date="2011-04-20T02:08:41.807Z" status="DRAFT" nvd-id="145404"/>
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

}

