package gov.ornl.stucco.extractors

import gov.ornl.stucco.morph.ast._
import gov.ornl.stucco.morph.extractor.Extractor

import org.mitre.stix.stix_1.STIXPackage
import org.mitre.stix.stix_1.STIXHeaderType
import org.mitre.stix.common_1.ExploitTargetsType
import org.mitre.stix.exploittarget_1.ExploitTarget

import org.mitre.stix.exploittarget_1.VulnerabilityType
import org.mitre.stix.common_1.StructuredTextType
import org.mitre.stix.exploittarget_1.CVSSVectorType
import org.mitre.stix.common_1.DateTimeWithPrecisionType
import org.mitre.stix.exploittarget_1.AffectedSoftwareType
import org.mitre.stix.common_1.ReferencesType
import org.mitre.stix.common_1.RelatedObservableType
import org.mitre.cybox.cybox_2.Observables
import org.mitre.cybox.cybox_2.Observable
import org.mitre.cybox.cybox_2.ObjectType
import org.mitre.cybox.common_2.MeasureSourceType
import org.mitre.cybox.objects.Product
import org.mitre.cybox.common_2.StringObjectPropertyType

import javax.xml.datatype.XMLGregorianCalendar
import javax.xml.datatype.DatatypeFactory
import javax.xml.datatype.DatatypeConfigurationException
import javax.xml.namespace.QName				
import javax.xml.parsers.ParserConfigurationException

import java.util.GregorianCalendar

import STIX._

/**								
 * NVD data extractor.
 *
 * @author Mike Iannacone
 * @author Anish Athalye
 */
object NvdToStixExtractor extends Extractor {

 val O = ObjectNode
 val A = ArrayNode
 val S = StringNode
 val N = NumberNode

  val format = new java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX")
  
  def makeCpeDesc(node: Option[ValueNode]): Option[ValueNode] = {
    val substrings = node.asString split ":"
    val vendor = (substrings lift 2)
    val product = (substrings lift 3)
    val version = (substrings lift 4)
    val update = (substrings lift 5)
    val edition = (substrings lift 6)
    val language = (substrings lift 7)
    var res = ""

	
    if(vendor.isDefined){
      res = vendor.get + " "
    }
    if(product.isDefined){
      res += product.get
      if(version.isDefined){
        res += " version " + version.get
        if(update.isDefined){
          res += " " + update.get
          if(edition.isDefined){
            res += " " + edition.get
          }
        }
      }
      if(language.isDefined){
        res += ", " + language.get + " language version"
      }
    }
    if(res != "")
      Some(res)
    else
      None
  }
	
	def extractStixPackage(node: ValueNode): STIXPackage = {
		
		var calendar = new GregorianCalendar()
		var stixPackage = new STIXPackage()
		var ets = new ExploitTargetsType()
		
		node ~> "nvd" ~> "entry" %%->	{ item => 
				
			var et = new ExploitTarget()
			var vulnerability = new VulnerabilityType()

			//description
			if ((item ~> "vuln:summary").isDefined)	
				vulnerability
					.withDescriptions(new StructuredTextType()              //list
 						.withValue((item ~> "vuln:summary").asString))

			//CVE number
			if ((item ~> "@id").isDefined)
				vulnerability
 					.withCVEID((item ~> "@id").asString)
			
			//CVSS Score
			if ((item ~> "vuln:cvss" ~> "cvss:base_metrics" ~> "cvss:score").isDefined)	
				vulnerability
 					.withCVSSScore(new CVSSVectorType()
						.withBaseScore((item ~> "vuln:cvss" ~> "cvss:base_metrics" ~> "cvss:score" ).asNumber.toString))
				
			//References
			if ((item ~> "vuln:references").isDefined)	{
				
				var references = new ReferencesType()

				item ~> "vuln:references" %%->	{ obj =>
			
						var a =  obj ~> "vuln:reference" ~> "@href" orElse Safely {
                                                                 (obj ~> "vuln:source").asString + ":" +
                                                                 (obj ~> "vuln:reference" ~> "#text").asString}
						if (a.isDefined)	
							references
								.withReferences(a.asString)
					None
				}
				vulnerability
					.withReferences(references)
			}
	
			//packing vulnerability into Exploit Target and adding to the Exploit Targets list
			ets
				.withExploitTargets(et
					.withTitle("Vulnerability")
					.withVulnerabilities(vulnerability
 						.withSource("NVD")))

			//software vertices
        	//	if ((item ~> "vuln:vulnerable-software-list" ~> "vuln:product").isDefined)	{
			
				var observables = new Observables()
			 
				item ~> "vuln:vulnerable-software-list" ~> "vuln:product"  %%-> { cpeItem =>
			
					val observable = new Observable() 	
					val obj = new ObjectType()
					
					if (makeCpeDesc(cpeItem).isDefined)
						obj			
							.withDescription(new org.mitre.cybox.common_2.StructuredTextType()
								.withValue((makeCpeDesc(cpeItem)).asString))
					
					observable	//-> description
							.withObservableSources(new MeasureSourceType()
								.withName("NVD")
								.withInformationSourceType(new org.mitre.cybox.common_2.ControlledVocabularyStringType()
									.withValue("National Vulnerability Database")))
							.withObject(obj	  //-> description ... description will go here
								.withProperties(new Product() 	//-> customFields
									.withProduct(new StringObjectPropertyType()
										.withValue(cpeItem.asString))))
					observables
						.withObservables(observable)
					None
				}
			
				stixPackage
					.withObservables(observables)		
				None
		//	}
		}

		stixPackage
			.withSTIXHeader(new STIXHeaderType()
				.withTitle("Vulnerability"))            //list -> add ip, malware, dns, etc
			.withExploitTargets(ets)

		println(stixPackage.toXMLString(true))
		return stixPackage;
	}

  	def extract(node: ValueNode): ValueNode = {
		extractStixPackage(node)

	^("vertices" -> (node ~> "nvd" ~> "entry" %%-> { item =>
      *(
        ^(
          "_id" -> item ~> "@id",
          "name" -> item ~> "@id",
          "_type" -> "vertex",
          "vertexType" -> "vulnerability",
          "source" -> "NVD",
          "description" -> item ~> "vuln:summary",
          "publishedDate" -> Safely{ format.parse( (item ~> "vuln:published-datetime").asString ).getTime() },
          "modifiedDate" -> Safely{ format.parse( (item ~> "vuln:last-modified-datetime").asString ).getTime() },
          "cweNumber" -> item ~> "vuln:cwe" ~> "@id",

          "cvssScore" -> item ~> "vuln:cvss" ~> "cvss:base_metrics" ~> "cvss:score",
          "accessVector" -> {item ~> "vuln:cvss" ~> "cvss:base_metrics" ~> "cvss:access-vector" ~> "#text" orElse item ~> "vuln:cvss" ~> "cvss:base_metrics" ~> "cvss:access-vector"},
          "accessComplexity" -> item ~> "vuln:cvss" ~> "cvss:base_metrics" ~> "cvss:access-complexity",
          "accessAuthentication" -> item ~> "vuln:cvss" ~> "cvss:base_metrics" ~> "cvss:authentication",
          "confidentialityImpact" -> item ~> "vuln:cvss" ~> "cvss:base_metrics" ~> "cvss:confidentiality-impact",
          "integrityImpact" -> item ~> "vuln:cvss" ~> "cvss:base_metrics" ~> "cvss:integrity-impact",
          "availabilityImpact" -> item ~> "vuln:cvss" ~> "cvss:base_metrics" ~> "cvss:availability-impact",
          "cvssDate" -> Safely{ format.parse( (item ~> "vuln:cvss" ~> "cvss:base_metrics" ~> "cvss:generated-on-datetime").asString ).getTime() },

          "references" -> (
            item ~> "vuln:references" %%-> { obj =>
              obj ~> "vuln:reference" ~> "@href" orElse Safely {
                (obj ~> "vuln:source").asString + ":" +
                  (obj ~> "vuln:reference" ~> "#text").asString
              }
            }).encapsulate
        ),
        (item ~> "vuln:vulnerable-software-list" ~> "vuln:product" %%-> { cpeItem =>
          ^(
            "_id" -> (cpeItem.asString),
            "name" -> (cpeItem.asString),
            "description" -> makeCpeDesc(cpeItem),
            "_type" -> "vertex",
            "vertexType" -> "software",
            "source" -> "NVD"
          )
        })
      )
    }).autoFlatten.autoFlatten,

    "edges" -> (node ~> "nvd" ~> "entry" %%-> { nvdItem =>
      (nvdItem ~> "vuln:vulnerable-software-list" ~> "vuln:product" %%-> { cpeItem =>
        ^(
          "_id" -> (cpeItem.asString + "_to_" + (nvdItem ~> "@id").asString),
          "description" -> (makeCpeDesc(cpeItem).asString + " to " + (nvdItem ~> "@id").asString),
          "_type" -> "edge",
          "inVType" -> "vulnerability",
          "outVType" -> "software",
          "source" -> "NVD",
          "_inV" -> nvdItem ~> "@id",
          "_outV" -> cpeItem,
          "_label" -> "hasVulnerability"
        )
      }).encapsulate
    }).autoFlatten
  )
	}
}
/*

					.withVulnerabilities(new VulnerabilityType()
						.withDescriptions(new StructuredTextType()              //list
 							.withValue((item ~> "vuln:summary").asString))
 						.withCVEID((item ~> "@id").asString)
 						.withSource("NVD")
 						.withCVSSScore(new CVSSVectorType()
							.withBaseScore((item ~> "vuln:cvss" ~> "cvss:base_metrics" ~> "cvss:score" ).asString))
				//		.withPublishedDateTime(new DateTimeWithPrecisionType()
 				//			.withValue(DatatypeFactory.newInstance().newXMLGregorianCalendar(calendar.setTimeInMillis((
				//				Safely{ format.parse( (item ~> "vuln:published-datetime").asString ).getTime() }).asLong))))
 				//		.withAffectedSoftware(new AffectedSoftwareType())
 				//			.withAffectedSoftwares(relatedObservable))      //construct observable
 						.withReferences(new ReferencesType()
 							.withReferences("refString"))))
*/
