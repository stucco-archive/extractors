package gov.ornl.stucco.extractors

import morph.ast._
import morph.extractor.Extractor

/**
 * CPE data extractor.
 *
 * @author Mike Iannacone
 */
object CpeExtractor extends Extractor {

  def extract(node: ValueNode): ValueNode = ^(
    "vertices" -> (node ~> "cpe-list" ~> "cpe-item" %%-> { item: ValueNode =>
      val substrings = ((item ~> "@name").asString.split(":"))
      ^(
        "_id" -> item ~> "@name",
        "_type" -> "vertex",
        "vertexType" -> "software",
        "source" -> "CPE",
        //TODO better handling for multiple lang desc., don't just assume english is first.
        "description" -> {(item ~> "title" ~> "#text") orElse (item ~> "title" ~> 0 ~> "#text")},
        "nvdId" -> item ~> "meta:item-metadata" ~> "@nvd-id",
        "status" -> item ~> "meta:item-metadata" ~> "@status",
        "modifiedDate" -> item ~> "meta:item-metadata" ~> "@modification-date",

        //index 0 is the "source", which is always "cpe", and is redundant with above.
        "part" -> { if (substrings.length > 1) substrings(1) else None },
        "vendor" -> { if (substrings.length > 2) substrings(2) else None },
        "product" -> { if (substrings.length > 3) substrings(3) else None },
        "version" -> { if (substrings.length > 4) substrings(4) else None },
        "update" -> { if (substrings.length > 5) substrings(5) else None },
        "edition" -> { if (substrings.length > 6) substrings(6) else None },
        "language" -> { if (substrings.length > 7) substrings(7) else None }
        //TODO: above is not great, but we are likely re-doing how morph does regexes & such soon anyway.
      )
    }).encapsulate

  )
}
