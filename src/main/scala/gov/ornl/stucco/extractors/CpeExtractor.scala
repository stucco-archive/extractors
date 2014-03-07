package gov.ornl.stucco.extractors

import gov.ornl.stucco.morph.ast._
import gov.ornl.stucco.morph.extractor.Extractor

/**
 * CPE data extractor.
 *
 * @author Mike Iannacone
 */
object CpeExtractor extends Extractor {

  def extract(node: ValueNode): ValueNode = ^(
    "vertices" -> (node ~> "cpe-list" ~> "cpe-item" %%-> { item =>
      val substrings = (item ~> "@name").asString split ":"
      ^(
        "_id" -> item ~> "@name",
        "_type" -> "vertex",
        "vertexType" -> "software",
        "source" -> "CPE",
        //TODO better handling for multiple lang desc., don't just assume english is first.
        "description" -> {
          (item ~> "title" ~> "#text") orElse (item ~> "title" ~> 0 ~> "#text")
        },
        "nvdId" -> item ~> "meta:item-metadata" ~> "@nvd-id",
        "status" -> item ~> "meta:item-metadata" ~> "@status",
        "modifiedDate" -> item ~> "meta:item-metadata" ~> "@modification-date",

        //index 0 is the "source", which is always "cpe", and is redundant with above.
        "part" -> (substrings lift 1),
        "vendor" -> (substrings lift 2),
        "product" -> (substrings lift 3),
        "version" -> (substrings lift 4),
        "update" -> (substrings lift 5),
        "edition" -> (substrings lift 6),
        "language" -> (substrings lift 7)
      //TODO: above is not great, but we are likely re-doing how morph does regexes & such soon anyway.
      )
    }).encapsulate
  )
}
