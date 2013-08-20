package gov.ornl.stucco.extractors

import morph.ast._
import morph.extractor.Extractor

/**
 * CPE data extractor.
 *
 * @author Mike Iannacone
 */
object GeoIPExtractor extends Extractor {

  //I'd like to name the nodes like "a.b.c.d/mask", but some ranges are not proper CIDR blocks.  Tabling that.
  //def log2(x: Double) = scala.math.log(x)/scala.math.log(2)
  //def subnetMask(start: Int, end: Int) = 32 - scala.math.round( log2(end-start) )

  def extract(node: ValueNode): ValueNode = {
    val headers = node.get(0)
    ^(
      "vertices" -> (node mapPartial { 
        //this will ignore header row and will ignore last row if it is just an empty string.
        case item if (item ~> 0 != headers ~> 0) && (item ~> 1 != None) =>
          ^(
            "_id" -> Safely{(item ~> 0).asString + "_through_" + (item ~> 1).asString},
            "_type" -> "vertex",
            "vertexType" -> "addressRange",
            "source" -> "maxmind",
            "startIP" -> item ~> 0,
            "endIP" -> item ~> 1,
            "startIPInt" -> Safely{(item ~> 2).asString.toInt},
            "endIPInt" -> Safely{(item ~> 3).asString.toInt},
            "countryCode" -> item ~> 4,
            "countryName" -> item ~> 5
          )
        }
      ).encapsulate
    )
  }
}
