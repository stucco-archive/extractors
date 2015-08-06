package gov.ornl.stucco.extractors

import gov.ornl.stucco.morph.ast._
import gov.ornl.stucco.morph.extractor.Extractor

/**
 * CIF 1d4 data extractor.
 *
 * see https://github.com/csirtgadgets/massive-octo-spice/blob/develop/src/rules/default/1d4_us.yml
 *
 * @author Mike Iannacone
 */
object CIF1d4Extractor extends Extractor {

  // to make testing easier
  val O = ObjectNode
  val A = ArrayNode
  val S = StringNode
  val N = NumberNode

  //see https://gist.github.com/TimothyKlim/3251750
  def ip2Long(ip: String): Long = {
    val atoms: Array[Long] = ip.split("\\.").map(java.lang.Long.parseLong(_))
    val result: Long = (3 to 0 by -1).foldLeft(0L)(
      (result, position) => result | (atoms(3 - position) << position * 8))
    result & 0xFFFFFFFF
  }

  def extract(node: ValueNode): ValueNode = {
    val headers = *("ip")
    ^(
      "vertices" -> (node mapPartial {
        //this will ignore header row and will ignore last row if it is just an empty string.
        case item if (item ~> 0 != headers ~> 0) && (item ~> 0 != None) && (item ~> 0 != Some(S(""))) =>
          ^(
            "_id" -> Safely { (item ~> 0).asString },
            "name" -> Safely { (item ~> 0).asString },
            "description" -> Safely { (item ~> 0).asString },
            "_type" -> "vertex",
            "vertexType" -> "IP",
            "source" -> "1d4.us",
            "ipInt" -> Safely { ip2Long((item ~> 0).asString) },
            "tags" -> "scanner"
          )
      }
      ).encapsulate
    )
  }
}
