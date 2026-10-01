"""The runner's hand-written checks and the JSON schemas must accept exactly the same things.

The runner has no runtime dependencies, so it cannot run the schemas; these tests run both over a
shared corpus and fail on any disagreement, so a schema-valid case or response is always one the
runner reads the same way.
"""

import copy
import json
import re

import pytest
from conftest import CLAUSE, ROOT, assertion, make_case
from jsonschema import Draft202012Validator as _Draft202012
from jsonschema import ValidationError, validators


def _ecma_pattern(validator, pattern, instance, schema):
    # JSON Schema patterns are ECMA-262, where "$" matches only at the true end of the string.
    # Python's jsonschema uses re.search, whose "$" also matches before a final newline; that is
    # the fail-open the runner closes, so the reference validator here closes it too.
    if not validator.is_type(instance, "string"):
        return
    found = re.search(pattern, instance)
    if found is None or (pattern.endswith("$") and found.end() != len(instance)):
        yield ValidationError(f"{instance!r} does not match {pattern!r}")


Draft202012Validator = validators.extend(_Draft202012, {"pattern": _ecma_pattern})

from keri_conformance.assertions import normalize_threshold
from keri_conformance.cases import case_problem
from keri_conformance.jsonfile import loads
from keri_conformance.session import check_result_shape

CASE = json.loads((ROOT / "schema" / "case.schema.json").read_text(encoding="utf-8"))
PROTOCOL = json.loads((ROOT / "schema" / "adapter-protocol.schema.json").read_text(
    encoding="utf-8"))


def validator(schema, ref):
    # Only the definitions: the case schema's top-level constraints describe a whole case.
    return Draft202012Validator({"$defs": schema["$defs"], "$ref": ref})


CASE_VALIDATOR = Draft202012Validator(CASE)


# --- thresholds ---------------------------------------------------------------------------------

THRESHOLDS = [
    # numeric
    "1", "0", "0x1", "0xA", "a", "ff", "0x1f", "10", "01", "", "0x", "0X1", "-1", "1.5", "g", " 1",
    "1 ", "0x-1", "1\n", "1\n\n",
    # one weighted clause
    ["1/2", "1/2"], ["1"], ["0"], ["2/4", "1/1"], ["1/0"], ["1/00"], ["0/1"], ["1/10"], [],
    ["x/2"], ["1 / 2"], ["-1/2"], ["0.5"], ["1/2/3"], [1], [None], ["/2"], ["1/"], ["1/2\n"],
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


# --- mutation corpus ----------------------------------------------------------------------------
#
# Every node of each well-formed document is deleted, replaced by each probe value, and (for an
# object) given an unexpected extra field. The runner's check and the schema must agree on every
# one of the resulting documents.

PROBES = [None, True, 1, -1, 1.0, 1.5, "", "x", "0a", "0a\n", [], {}, ["x"]]


def _paths(node, path=()):
    yield path
    if isinstance(node, dict):
        for key, value in node.items():
            yield from _paths(value, (*path, key))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _paths(value, (*path, index))


def _replace(doc, path, value):
    doc = copy.deepcopy(doc)
    if not path:
        return value
    target = doc
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    return doc


def _delete(doc, path):
    doc = copy.deepcopy(doc)
    target = doc
    for key in path[:-1]:
        target = target[key]
    del target[path[-1]]
    return doc


def mutations(doc):
    for path in _paths(doc):
        for probe in PROBES:
            yield _replace(doc, path, probe)
        target = doc
        for key in path:
            target = target[key]
        if path and isinstance(path[-1], str):
            yield _delete(doc, path)
        if isinstance(target, dict):
            yield _replace(doc, path, {**target, "zz": 1})
        if isinstance(target, list) and target:
            yield _replace(doc, path, [])


def disagreements(documents, ours, schema_validator):
    found = []
    for doc in documents:
        # The runner sees a document only after decoding it from JSON text, which turns an
        # integral number such as 1.0 into the integer 1, as the schema's "integer" type allows.
        mine = ours(loads(json.dumps(doc))) is None
        theirs = schema_validator.is_valid(doc)
        if mine != theirs:
            found.append((mine, theirs, doc))
    return found


# --- cases (E) ----------------------------------------------------------------------------------

STATE = {"sn": 0, "said": "EAbc", "keys": ["DAbc"], "kt": "1", "ndigs": ["EGhi"],
         "nt": ["1/2", "1/2"], "wits": [], "bt": "0", "delegator": None}
INTEROP = {"id": "a9", "check": "rejected", "level": "INTEROP", "basis": "keripy 1.x"}

BASE_CASES = [
    make_case("CESR-0001", "cesr.parse", {"stream": "2d4b"}, [assertion("rejected"), INTEROP],
              features=["cesr.genus-2.00"]),
    make_case("CESR-0002", "cesr.parse", {"stream": "00"}, [assertion("decoded", expected=[
        {"kind": "counter", "start": 0, "end": 4, "code": "-K", "size": 1, "group_end": 4},
        {"kind": "indexed", "start": 4, "end": 92, "code": "A", "raw": "00", "index": 0}])],
        status="draft", reference={"implementation": "keripy", "commit": "9a8b7aa"}),
    make_case("CESR-0003", "cesr.encode", {"code": "E", "raw": "00", "domain": "text"},
              [assertion("encoded", expected="10", note="n")], status="deprecated"),
    make_case("KERI-0001", "keri.process",
              {"perspective": {"role": "validator"},
               "messages": [{"stream": "7b7d", "source": "controller"}]},
              [assertion("disposition", message=0, phase="final", expected="superseded"),
               assertion("key_state", name="a2", level="SHOULD", aid="EAbc", expected=STATE)],
              status="disputed"),
    make_case("KERI-0002", "keri.emit", {"event": {"t": "icp"}, "seeds": {"DAbc": "00"}},
              [assertion("emitted_body", expected="7b7d"),
               assertion("signatures_verify", name="a2", level="MAY"),
               assertion("attachments_equivalent", name="a3", expected=[{"i": 0}])]),
]
BASE_CASES[0]["assertions"][0]["clause"] = {**CLAUSE, "quote": "A stream MUST ..."}


def test_the_base_cases_are_valid_in_both():
    for case in BASE_CASES:
        assert CASE_VALIDATOR.is_valid(case), case["id"]
        assert case_problem(case) is None, case["id"]


@pytest.mark.parametrize("base", BASE_CASES, ids=[c["id"] for c in BASE_CASES])
def test_case_checks_agree_with_the_case_schema(base):
    found = disagreements(mutations(base), case_problem, CASE_VALIDATOR)
    assert found == [], found[:3]


SEMANTIC = [
    ("status", "disputed"), ("status", "deprecated"), ("operation", "cesr.encode"),
    ("operation", "keri.process"), ("operation", "keri.emit"), ("operation", "cesr.parse"),
]


@pytest.mark.parametrize("base", BASE_CASES, ids=[c["id"] for c in BASE_CASES])
def test_cross_field_rules_agree_with_the_case_schema(base):
    documents = [_replace(base, (field,), value) for field, value in SEMANTIC]
    for a, assertion_ in enumerate(base["assertions"]):
        for level in ("MUST", "INTEROP"):
            documents.append(_replace(base, ("assertions", a, "level"), level))
        documents.append(_replace(base, ("assertions", a, "basis"), "b"))
        if assertion_["check"] == "disposition":
            documents.append(_replace(base, ("assertions", a, "phase"), "initial"))
            documents.append(_replace(base, ("assertions", a, "expected"), "accepted"))
    found = disagreements(documents, case_problem, CASE_VALIDATOR)
    assert found == [], found[:3]


def test_an_integral_number_is_an_integer_as_the_schema_says():
    # JSON Schema counts 1.0 as an integer. The runner's decoder turns integral numbers into
    # ints, so a case written with 0.0 loads with the integer 0 and is accepted; 0.5 is not.
    text = json.dumps(_replace(BASE_CASES[3], ("assertions", 0, "message"), 0.0))
    case = loads(text)
    assert CASE_VALIDATOR.is_valid(json.loads(text))
    assert case_problem(case) is None
    assert type(case["assertions"][0]["message"]) is int
    half = loads(text.replace('"message": 0.0', '"message": 0.5'))
    assert "message" in case_problem(half)


def test_duplicate_assertion_ids_are_a_runtime_rule_beyond_the_schema():
    case = _replace(BASE_CASES[4], ("assertions", 1, "id"), "a1")
    assert CASE_VALIDATOR.is_valid(case)
    assert "twice" in case_problem(case)


# --- adapter results (J) ------------------------------------------------------------------------

RESULT_DEFS = {
    "cesr.parse": {"oneOf": [{"$ref": "#/$defs/result_decoded"},
                             {"$ref": "#/$defs/result_rejected"}]},
    "cesr.encode": {"$ref": "#/$defs/result_encoded"},
    "keri.process": {"$ref": "#/$defs/result_processed"},
    "keri.emit": {"$ref": "#/$defs/result_emitted"},
}

BASE_RESULTS = [
    ("cesr.parse", {"items": [
        {"kind": "primitive", "start": 0, "end": 44, "code": "E", "raw": "00"},
        {"kind": "indexed", "start": 44, "end": 132, "code": "A", "raw": "00", "index": 0,
         "ondex": 0},
        {"kind": "counter", "start": 132, "end": 136, "code": "-K", "size": 1,
         "group_end": 224, "genus": "AAA", "gvrsn": "CAA"},
        {"kind": "message", "start": 224, "end": 567, "proto": "KERI", "version": "2.0",
         "serialization": "CBOR", "size": 343}]}),
    ("cesr.parse", {"reject": {"class": "truncated"}}),
    ("cesr.encode", {"encoded": "0aff"}),
    ("keri.process", {"dispositions": [{"initial": "pending", "final": "superseded",
                                        "reason": "out-of-order"}],
                      "key_states": {"EAbc": {**STATE, "delegator": "EDel"}}}),
    ("keri.emit", {"stream": "7b7d"}),
]


@pytest.mark.parametrize(("op", "result"), BASE_RESULTS,
                         ids=[f"{op}-{n}" for n, (op, _) in enumerate(BASE_RESULTS)])
def test_result_checks_agree_with_the_protocol_schema(op, result):
    schema = Draft202012Validator({"$defs": PROTOCOL["$defs"], **RESULT_DEFS[op]})
    assert schema.is_valid(result)
    assert check_result_shape(op, result) is None
    found = disagreements(mutations(result), lambda r: check_result_shape(op, r), schema)
    assert found == [], found[:3]


def test_every_operation_has_a_result_check():
    from keri_conformance.session import OPERATIONS

    assert set(RESULT_DEFS) == set(OPERATIONS)


def test_keyed_refuses_a_non_object_on_its_own():
    # Results reach it only after an object check, but the combinator does not rely on that.
    from keri_conformance.shapes import keyed, string

    assert keyed({"a": string()})(["a"], "x") == "x must be an object"


def test_runner_refuses_a_trailing_newline_that_python_jsonschema_admits():
    # Python's jsonschema matches patterns with re.search, where "$" also matches before a final
    # newline; ECMA-262 (the JSON Schema regex dialect) does not. The runner is deliberately
    # stricter: a value with a trailing newline is malformed, never normalized into a match.
    from keri_conformance import assertions, contracts

    assert assertions.normalize_threshold("0xabc\n") is None or assertions.normalize_threshold(
        "0xabc\n") != assertions.normalize_threshold("0xabc")
    assert contracts.THRESHOLD("0xabc\n", ["kt"]) is not None
    assert contracts.HEX_STRING("abcd\n", ["raw"]) is not None


# --- checks that fit the operation (K) and a non-empty encode code (Q) ---------------------------

SAMPLE_ASSERTIONS = {a["check"]: a for case in BASE_CASES for a in case["assertions"]
                     if a["level"] != "INTEROP"}
OPERATION_CHECKS = {
    "cesr.parse": {"decoded", "rejected"},
    "cesr.encode": {"encoded"},
    "keri.process": {"disposition", "key_state"},
    "keri.emit": {"emitted_body", "signatures_verify", "attachments_equivalent"},
}


def test_every_check_has_a_sample():
    assert set(SAMPLE_ASSERTIONS) == set().union(*OPERATION_CHECKS.values())


@pytest.mark.parametrize("base", BASE_CASES, ids=[c["id"] for c in BASE_CASES])
@pytest.mark.parametrize("check", sorted(SAMPLE_ASSERTIONS))
def test_an_assertion_check_must_fit_the_operation(base, check):
    case = _replace(base, ("assertions",), [SAMPLE_ASSERTIONS[check]])
    fits = check in OPERATION_CHECKS[base["operation"]]
    assert CASE_VALIDATOR.is_valid(case) == fits
    assert (case_problem(case) is None) == fits
    if not fits:
        assert "operation" in case_problem(case)


def test_cesr_encode_needs_a_non_empty_code():
    case = _replace(BASE_CASES[2], ("input", "code"), "")
    assert not CASE_VALIDATOR.is_valid(case)
    assert "code" in case_problem(case)
