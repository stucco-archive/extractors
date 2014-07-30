extractors
==========

Extractors for structured data sources
--------------------------------------

These are the [morph](https://github.com/stucco/morph) extractors for
transforming structured data sources into
[GraphSON](https://github.com/tinkerpop/blueprints/wiki/GraphSON-Reader-and-Writer-Library)
for alignment into the Stucco knowledge graph.

Running the tests
------------

Tests can be run with `mvn test`

Adding extractors
------------

New extractors will need to extend the `Extractor` class, and implement the `extract(ValueNode)` method, which is how they will receive input.

Extractors use the Morph DSL, so please refer to the [Morph documentation.](https://stucco.github.io/morph/Morph.html)

The easiest way to test any new extractors is to add new test cases for them when you begin, instead of passing them input by some other means and writing test cases later.

Larger tests should add their data to `./testData/` (but *do not* add excessively large test datasets to this repo.)

build status
------------

master: [![Build Status]
(https://travis-ci.org/stucco/extractors.png?branch=master)]
(https://travis-ci.org/stucco/extractors)
