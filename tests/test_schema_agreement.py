"""The runner's hand-written checks and the JSON schemas must accept exactly the same things.

The runner has no runtime dependencies, so it cannot run the schemas; these tests run both over a
shared corpus and fail on any disagreement, so a schema-valid case or response is always one the
runner reads the same way.
"""

import json

import pytest
from conftest import ROOT
from jsonschema import Draft202012Validator

from keri_conformance.assertions import normalize_threshold

CASE = json.loads((ROOT / "schema" / "case.schema.json").read_text(encoding="utf-8"))
PROTOCOL = json.loads((ROOT / "schema" / "adapter-protocol.schema.json").read_text(
    encoding="utf-8"))


def validator(schema, ref):
    # Only the definitions: the case schema's top-level constraints describe a whole case.
    return Draft202012Validator({"$defs": schema["$defs"], "$ref": ref})


# --- thresholds ---------------------------------------------------------------------------------

THRESHOLDS = [
    # numeric
    "1", "0", "0x1", "0xA", "a", "ff", "0x1f", "10", "01", "", "0x", "0X1", "-1", "1.5", "g", " 1",
    "1 ", "0x-1",
    # one weighted clause
    ["1/2", "1/2"], ["1"], ["0"], ["2/4", "1/1"], ["1/0"], ["1/00"], ["0/1"], ["1/10"], [],
    ["x/2"], ["1 / 2"], ["-1/2"], ["0.5"], ["1/2/3"], [1], [None], ["/2"], ["1/"],
    # several clauses
    [["1/2"], ["1/3", "2/3"]], [["1"]], [[]], [["1/2"], []], [["1/2", 3]], [["1/0"]],
    [[["1/2"]]],
    # mixed and other types
    ["1/2", ["1/2"]], [{"1/2": ["1/2"]}], {"a": 1}, None, 1, True, 1.5,
]


@pytest.mark.parametrize("schema", [CASE, PROTOCOL], ids=["case", "protocol"])
@pytest.mark.parametrize("value", THRESHOLDS, ids=[json.dumps(t) for t in THRESHOLDS])
def test_threshold_schema_accepts_exactly_what_the_runner_normalizes(schema, value):
    accepted = validator(schema, "#/$defs/threshold").is_valid(value)
    assert accepted == (normalize_threshold(value) is not None)


def test_the_corpus_has_both_verdicts():
    verdicts = {normalize_threshold(t) is not None for t in THRESHOLDS}
    assert verdicts == {True, False}


# --- decoded items ------------------------------------------------------------------------------

ITEMS = [
    ({"kind": "primitive", "start": 0, "end": 44, "code": "E", "raw": "00"}, True),
    ({"kind": "primitive", "start": 0, "end": 44, "code": "E"}, False),
    ({"kind": "primitive", "start": 0, "end": 44, "code": "E", "raw": "0A"}, False),
    ({"kind": "primitive", "start": 0, "end": 44, "code": "E", "raw": "00", "index": 0}, False),
    ({"kind": "indexed", "start": 0, "end": 88, "code": "A", "raw": "00", "index": 0}, True),
    ({"kind": "indexed", "start": 0, "end": 88, "code": "A", "raw": "00", "index": 0,
      "ondex": 1}, True),
    ({"kind": "indexed", "start": 0, "end": 88, "code": "A", "raw": "00"}, False),
    ({"kind": "counter", "start": 0, "end": 4, "code": "-K", "size": 1, "group_end": 92}, True),
    ({"kind": "counter", "start": 0, "end": 8, "code": "-_AAA", "size": 1, "group_end": 8,
      "genus": "AAA", "gvrsn": "CAA"}, True),
    ({"kind": "counter", "start": 0, "end": 4, "code": "-K", "size": 1}, False),
    ({"kind": "counter", "start": 0, "end": 4, "code": "-K", "size": 1, "group_end": 4,
      "raw": "00"}, False),
    ({"kind": "message", "start": 0, "end": 343, "proto": "KERI", "version": "2.0",
      "serialization": "JSON", "size": 343}, True),
    ({"kind": "message", "start": 0, "end": 343, "proto": "KERI", "version": "2.0",
      "serialization": "YAML", "size": 343}, False),
    ({"kind": "message", "start": 0, "end": 343, "proto": "KERI", "version": "2.0",
      "serialization": "JSON"}, False),
    ({"kind": "group", "start": 0, "end": 1}, False),
    ({"kind": "primitive", "start": -1, "end": 44, "code": "E", "raw": "00"}, False),
]


@pytest.mark.parametrize(("item", "valid"), ITEMS)
def test_case_items_are_closed_and_kind_specific(item, valid):
    assert validator(CASE, "#/$defs/item").is_valid(item) == valid
    assert validator(PROTOCOL, "#/$defs/item").is_valid(item) == valid


def test_the_item_definition_is_identical_in_both_schemas():
    # Both schemas must stand alone, so the definition is duplicated; this keeps the copies equal,
    # which is what makes every schema-valid expected item one a conforming adapter can report.
    assert CASE["$defs"]["item"] == PROTOCOL["$defs"]["item"]
    decoded = PROTOCOL["$defs"]["result_decoded"]["properties"]["items"]["items"]
    assert decoded == {"$ref": "#/$defs/item"}
    expected = CASE["$defs"]
    assert expected["item"]["oneOf"]
