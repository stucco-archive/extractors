package gov.ornl.stucco.extractors

import gov.ornl.stucco.morph.ast._
import gov.ornl.stucco.morph.extractor.Extractor

import org.mitre.stix.stix_1.{	STIXPackage,
				STIXHeaderType, 
				IndicatorsType }
import org.mitre.stix.common_1.{ ExploitTargetsType,
				 StructuredTextType,
				 DateTimeWithPrecisionType,
				 ControlledVocabularyStringType,
				 RelatedPackageRefsType,
				 RelatedPackageRefType,
				 RelatedExploitTargetType, 
				 RelatedObservableType,
				 ReferencesType }
import org.mitre.stix.exploittarget_1.{ ExploitTarget,
					VulnerabilityType,
					CVSSVectorType,
					AffectedSoftwareType }
import org.mitre.stix.indicator_2.Indicator
import org.mitre.cybox.common_2.{ MeasureSourceType,
				  StringObjectPropertyType }
import org.mitre.cybox.cybox_2.{ Observables,
				 Observable,
				 ObjectType }
import org.mitre.cybox.objects.Product

import javax.xml.datatype.{ XMLGregorianCalendar,
			    DatatypeFactory,
			    DatatypeConfigurationException }
import javax.xml.namespace.QName				
import javax.xml.parsers.ParserConfigurationException

import java.util.{ GregorianCalendar,
		   UUID,
		   TimeZone }

/**								
 * NVD data extractor.
 *
 * @author Mike Iannacone
 * @author Anish Athalye
 * @author Maria Vincent
 */
object NvdToStixExtractor extends Extractor {

	val O = ObjectNode
 	val A = ArrayNode
 	val S = StringNode
 	val N = NumberNode

	val stixPackage = new STIXPackage
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
	
    		if(vendor.isDefined)	{
      			res = vendor.get + " "
    		}
    		if(product.isDefined)	{
      			res += product.get
      			if(version.isDefined)	{
        			res += " version " + version.get
        			if(update.isDefined)	{
          				res += " " + update.get
          				if(edition.isDefined)	{
            					res += " " + edition.get
          				}
        			}
      			}
      			if(language.isDefined)	{
        			res += ", " + language.get + " language version"
      			}
    		}
    		if(res != "")
      			Some(res)
    		else
      			None
  	}

	def extract (node: ValueNode): ValueNode = {
		extractSTIXPackage(node)
		println(stixPackage.toXMLString(true))
		if (validate(stixPackage))
			println("STIX Package is valid")
		return node
	}
	
	def validate(stixPackage: STIXPackage): Boolean = {
		stixPackage.validate()
	}				

	def extractSTIXPackage (node: ValueNode): STIXPackage = {
		
		var indicator = new Indicator()
		var calendar = new GregorianCalendar()
		var ets = new ExploitTargetsType()
		
		node ~> "nvd" ~> "entry" %%->	{ item => 
				
			var et = new ExploitTarget()
			var vulnerability = new VulnerabilityType()
			var exploitTargetId = new QName("gov.ornl.stucco", "vulnerability-" + UUID.randomUUID().toString(), "stucco")
			
			//assigning id to the vulnerability	
			et
				.withId(exploitTargetId)
			//description
			if ((item ~> "vuln:summary").isDefined)	
				vulnerability
					.withDescriptions(new StructuredTextType()              //list
 						.withValue((item ~> "vuln:summary").asString))
			//publishedDate
			if ((Safely{ format.parse( (item ~> "vuln:published-datetime").asString ).getTime() }).isDefined)	{
			
				calendar.setTimeInMillis(((Safely{ format.parse( (item ~> "vuln:published-datetime").asString ).getTime() }).asNumber).longValue)	
				vulnerability
					.withPublishedDateTime(new DateTimeWithPrecisionType()
					.withValue(DatatypeFactory.newInstance().newXMLGregorianCalendar(calendar)))
			}
			//CVE number
			if ((item ~> "@id").isDefined)
				vulnerability
 					.withCVEID((item ~> "@id").asString)
			//CVSS Score
			if ((item ~> "vuln:cvss" ~> "cvss:base_metrics" ~> "cvss:score").isDefined)	
				vulnerability
 					.withCVSSScore(new CVSSVectorType()
						.withBaseScore((item ~> "vuln:cvss" ~> "cvss:base_metrics" ~> "cvss:score" ).asNumber.doubleValue.toString))
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
			
			//software vertices
        		if ((item ~> "vuln:vulnerable-software-list" ~> "vuln:product").isDefined)	{
			
				var indicators = new IndicatorsType()
				var observables = new Observables()
					.withCyboxMajorVersion("2.0")
					.withCyboxMinorVersion("1.0")
			 
				item ~> "vuln:vulnerable-software-list" ~> "vuln:product"  %%-> { cpeItem =>
			
					val obj = new ObjectType()
					
					if (makeCpeDesc(cpeItem).isDefined)	{

						val observable = new Observable() 	
						var softwareId = new QName("gov.ornl.stucco", "software-" + UUID.randomUUID().toString(), "stucco")

						obj			
							.withDescription(new org.mitre.cybox.common_2.StructuredTextType()
								.withValue((makeCpeDesc(cpeItem)).asString))
						//software observable
						observable	//-> description
							.withTitle("Software")
							.withId(softwareId)
							.withObservableSources(new MeasureSourceType()
								.withName("NVD")
								.withInformationSourceType(new org.mitre.cybox.common_2.ControlledVocabularyStringType()
									.withValue("National Vulnerability Database")))
							.withObject(obj	  //-> description ... description will go here
								.withProperties(new Product() 	//-> customFields
									.withProduct(new StringObjectPropertyType()
										.withValue(cpeItem.asString))))
						//packing software observable into observables
						observables
							.withObservables(observable)
						//creating a software indicator
						indicators
							.withIndicators(new Indicator()
								.withId(softwareId)
								.withTitle("Software")
								.withObservable(new Observable()
									.withIdref(softwareId))
								.withRelatedPackages(new RelatedPackageRefsType()
									.withPackageReferences(new RelatedPackageRefType()
										.withIdref(exploitTargetId)
										.withRelationship(new ControlledVocabularyStringType()
											.withValue("Has vulnerability")))))
						//adding a reference to the affected software
						vulnerability
							.withAffectedSoftware(new AffectedSoftwareType()
								.withAffectedSoftwares(new RelatedObservableType()
                        						.withObservable(new Observable()
										.withIdref(softwareId))))
						None
					}
					None
				}
				//packing software indicators and observables into package
				stixPackage
					.withIndicators(indicators)		
					.withObservables(observables)
				None
			}
			//packing vulnerability into Exploit Target and adding to the Exploit Targets list
			ets
				.withExploitTargets(et
					.withTitle("Vulnerability")
					.withVulnerabilities(vulnerability
 						.withSource("NVD")))
			None

		}
		stixPackage
			.withId(new QName("gov.ornl.stucco", "NVD-" + UUID.randomUUID().toString(), "stucco"))
			.withTimestamp(DatatypeFactory.newInstance().newXMLGregorianCalendar(				
				new GregorianCalendar(TimeZone.getTimeZone("UTC"))))
			.withSTIXHeader(new STIXHeaderType()
				.withTitle("NVD"))            //list -> add ip, malware, dns, etc
			.withExploitTargets(ets)

		return stixPackage
	}
}
