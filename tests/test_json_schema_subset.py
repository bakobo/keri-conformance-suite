"""The generators' JSON Schema 2020-12 subset evaluator (docs/design.md, ACDC, "Schemas").

The vectors follow the semantics of the official JSON Schema test suite for each keyword the subset
implements, written out here so that no test needs the network. The refusals matter as much as the
verdicts: a schema that uses a keyword outside the subset must never be evaluated as though the
keyword were absent, because that would publish a verdict the full dialect contradicts."""

import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from generators.spec_tables import json_schema_subset as js
from generators.spec_tables.errors import GeneratorError

# (schema, instance, valid) per keyword, after the official suite's tests for draft 2020-12.
TYPE = [
    ({"type": "integer"}, 1, True),
    ({"type": "integer"}, 1.0, True),  # a float with zero fractional part is an integer
    ({"type": "integer"}, 1.5, False),
    ({"type": "integer"}, True, False),  # a boolean is not a number
    ({"type": "integer"}, "1", False),
    ({"type": "number"}, 1.5, True),
    ({"type": "number"}, 1, True),
    ({"type": "number"}, False, False),
    ({"type": "string"}, "", True),
    ({"type": "string"}, 1, False),
    ({"type": "object"}, {}, True),
    ({"type": "object"}, [], False),
    ({"type": "array"}, [], True),
    ({"type": "array"}, {}, False),
    ({"type": "boolean"}, False, True),
    ({"type": "boolean"}, 0, False),
    ({"type": "null"}, None, True),
    ({"type": "null"}, 0, False),
    ({"type": ["integer", "string"]}, "a", True),
    ({"type": ["integer", "string"]}, 1, True),
    ({"type": ["integer", "string"]}, None, False),
]
PROPERTIES = [
    ({"properties": {"a": {"type": "integer"}}}, {"a": 1}, True),
    ({"properties": {"a": {"type": "integer"}}}, {"a": "x"}, False),
    ({"properties": {"a": {"type": "integer"}}}, {}, True),  # only present properties apply
    ({"properties": {"a": {"type": "integer"}}}, {"b": "x"}, True),
    ({"properties": {"a": {"type": "integer"}}}, [1], True),  # ignores non-objects
    ({"properties": {"a": {"type": "integer"}}}, "a", True),
    ({"properties": {"a": False}}, {"a": 1}, False),
    ({"properties": {"a": True}}, {"a": 1}, True),
]
REQUIRED = [
    ({"required": ["a"]}, {"a": None}, True),
    ({"required": ["a"]}, {"b": 1}, False),
    ({"required": ["a"]}, [], True),  # ignores non-objects
    ({"required": ["a"]}, "a", True),
    ({"required": []}, {}, True),
]
ONE_OF = [
    ({"oneOf": [{"type": "integer"}, {"type": "string"}]}, 1, True),
    ({"oneOf": [{"type": "integer"}, {"type": "string"}]}, None, False),  # none
    ({"oneOf": [{"type": "integer"}, {"type": "number"}]}, 1, False),  # both
    ({"oneOf": [{"type": "integer"}, {"type": "number"}]}, 1.5, True),
    ({"oneOf": [True, True]}, 1, False),
    ({"oneOf": [True, False]}, 1, True),
]
ANY_OF = [
    ({"anyOf": [{"type": "integer"}, {"type": "number"}]}, 1, True),  # both is fine
    ({"anyOf": [{"type": "integer"}, {"type": "string"}]}, None, False),
    ({"anyOf": [False, True]}, 1, True),
]
CONST = [
    ({"const": 1}, 1, True),
    ({"const": 1}, 1.0, True),  # numbers compare by value
    ({"const": 0}, False, False),  # but booleans are not numbers
    ({"const": False}, 0, False),
    ({"const": True}, True, True),
    ({"const": None}, None, True),
    ({"const": None}, 0, False),
    ({"const": "a"}, "a", True),
    ({"const": {"a": 1, "b": [1, 2]}}, {"b": [1, 2], "a": 1}, True),  # object key order
    ({"const": {"a": 1}}, {"a": 1, "b": 2}, False),
    ({"const": {"a": 1}}, {"b": 1}, False),
    ({"const": [1, 2]}, [2, 1], False),  # array order matters
    ({"const": [1, 2]}, [1, 2, 3], False),
    ({"const": [{"a": False}]}, [{"a": 0}], False),
    ({"const": [1]}, {"0": 1}, False),
]
REF = [
    ({"$defs": {"i": {"type": "integer"}}, "$ref": "#/$defs/i"}, 1, True),
    ({"$defs": {"i": {"type": "integer"}}, "$ref": "#/$defs/i"}, "x", False),
    # In 2020-12 a $ref's siblings still apply: both must hold.
    ({"$defs": {"i": {"type": "integer"}}, "$ref": "#/$defs/i", "const": 2}, 1, False),
    ({"$defs": {"i": {"type": "integer"}}, "$ref": "#/$defs/i", "const": 2}, 2, True),
    # Recursion through the root, bounded by the instance.
    ({"properties": {"n": {"$ref": "#"}}, "type": "object"}, {"n": {"n": {}}}, True),
    ({"properties": {"n": {"$ref": "#"}}, "type": "object"}, {"n": {"n": 1}}, False),
    # JSON pointer escapes: ~1 is '/', ~0 is '~', and percent-encoding is decoded first.
    ({"$defs": {"a/b": {"type": "string"}}, "$ref": "#/$defs/a~1b"}, "x", True),
    ({"$defs": {"a~b": {"type": "string"}}, "$ref": "#/$defs/a~0b"}, 1, False),
    ({"$defs": {"a%b": {"type": "string"}}, "$ref": "#/$defs/a%25b"}, "x", True),
    # A pointer into a schema position other than $defs.
    ({"properties": {"a": {"type": "string"}, "b": {"$ref": "#/properties/a"}}}, {"b": 1},
     False),
    ({"properties": {"a": {"oneOf": [{"type": "string"}]},
                     "b": {"$ref": "#/properties/a/oneOf/0"}}}, {"b": "x"}, True),
]
BOOLEAN = [(True, 1, True), (False, 1, False), (True, None, True)]


@pytest.mark.parametrize("schema,instance,valid",
                         TYPE + PROPERTIES + REQUIRED + ONE_OF + ANY_OF + CONST + REF + BOOLEAN)
def test_subset_follows_the_2020_12_semantics(schema, instance, valid):
    assert js.validate(schema, instance) is valid


def test_annotations_and_identifiers_are_allowed_and_ignored():
    schema = {"$id": "Exyz", "$schema": js.DIALECT, "title": "t", "description": "d",
              "version": "1.0.0", "type": "object", "required": ["a"]}
    js.check(schema)
    assert js.validate(schema, {"a": 1})
    assert not js.validate(schema, {})


@pytest.mark.parametrize("keyword,value", [
    ("additionalProperties", False),
    ("items", {"type": "string"}),
    ("allOf", [True]),
    ("not", {"type": "string"}),
    ("enum", [1]),
    ("minimum", 0),
    ("pattern", "^a"),
    ("if", True),
    ("credentialType", "x"),  # unknown words are refused too, not ignored
])
def test_a_keyword_outside_the_subset_is_refused(keyword, value):
    with pytest.raises(GeneratorError) as e:
        js.check({"type": "object", keyword: value})
    assert e.value.code == js.E_KEYWORD
    assert keyword in str(e.value)
    with pytest.raises(GeneratorError):
        js.validate({"type": "object", keyword: value}, {})


def test_a_keyword_outside_the_subset_is_refused_however_deep():
    schema = {"$defs": {"x": {"oneOf": [{"anyOf": [{"properties": {"a": {"enum": [1]}}}]}]}}}
    with pytest.raises(GeneratorError) as e:
        js.check(schema)
    assert e.value.code == js.E_KEYWORD
    assert "/$defs/x/oneOf/0/anyOf/0/properties/a" in str(e.value)


@pytest.mark.parametrize("schema", [
    {"$ref": "https://example.com/lei.json"},
    {"$ref": "lei.json#/a"},
    {"$ref": "sad:EABC"},
    {"$dynamicRef": "#meta"},
    {"properties": {"a": {"$id": "https://example.com/a"}}},
    {"properties": {"a": {"$ref": "#anchor"}}},  # a plain-name fragment needs $anchor
    {"oneOf": [{"type": "string"}, {"$ref": "did:webs:example#lei"}]},
])
def test_non_local_and_dynamic_references_are_recognized_and_refused(schema):
    assert js.nonlocal_references(schema)
    with pytest.raises(GeneratorError) as e:
        js.check(schema)
    assert e.value.code == js.E_REFERENCE
    with pytest.raises(GeneratorError):
        js.validate(schema, {})


def test_a_schema_with_only_local_references_has_no_nonlocal_reference():
    assert js.nonlocal_references({"$defs": {"a": True}, "$ref": "#/$defs/a"}) == []
    assert js.nonlocal_references(True) == []


def test_check_can_admit_a_non_local_reference_that_a_case_refuses_without_evaluating():
    schema = {"type": "object", "properties": {"lei": {"$ref": "https://example.com/lei"}}}
    js.check(schema, allow_nonlocal=True)
    js.check({"anyOf": [{"$dynamicRef": "#m"}, {"$id": "x"}]}, allow_nonlocal=True)
    with pytest.raises(GeneratorError) as e:
        js.check({**schema, "enum": [1]}, allow_nonlocal=True)
    assert e.value.code == js.E_KEYWORD


@pytest.mark.parametrize("ref", ["#/$defs/missing", "#/properties/a/0", "#/required/9",
                                 "#/$defs/a/x"])
def test_a_local_reference_that_resolves_to_nothing_is_refused(ref):
    schema = {"$defs": {"a": True}, "properties": {"a": {"type": "string"}}, "required": [],
              "$ref": ref}
    with pytest.raises(GeneratorError) as e:
        js.check(schema)
    assert e.value.code == js.E_REFERENCE


def test_a_reference_that_resolves_to_something_other_than_a_schema_is_refused():
    with pytest.raises(GeneratorError) as e:
        js.check({"required": ["a"], "$ref": "#/required"})
    assert e.value.code == js.E_REFERENCE


def test_a_reference_loop_that_consumes_no_instance_is_refused_not_followed_forever():
    for schema in ({"$ref": "#"}, {"$defs": {"a": {"$ref": "#/$defs/b"}, "b": {"$ref": "#/$defs/a"}},
                                   "$ref": "#/$defs/a"}):
        js.check(schema)  # statically fine: every pointer resolves
        with pytest.raises(GeneratorError) as e:
            js.validate(schema, 1)
        assert e.value.code == js.E_DEPTH


@pytest.mark.parametrize("schema", [
    1, "string", None, [], {"type": "decimal"}, {"type": []}, {"type": ["string", "string"]},
    {"type": 3}, {"properties": []}, {"properties": {"a": 1}}, {"required": "a"},
    {"required": [1]}, {"required": ["a", "a"]}, {"oneOf": []}, {"oneOf": {}}, {"anyOf": [1]},
    {"$ref": 1}, {"$defs": []}, {"$defs": {"a": 1}}, {"$schema": 1}, {"$id": 1},
    {"title": 1}, {"description": []}, {"version": 1},
])
def test_a_malformed_schema_is_refused(schema):
    with pytest.raises(GeneratorError) as e:
        js.check(schema)
    assert e.value.code == js.E_FORM


@pytest.mark.parametrize("schema", [{"properties": {"a": {"$schema": js.DIALECT}}},
                                    {"$defs": {"a": {"$schema": js.DIALECT}}}])
def test_schema_keyword_only_at_the_root(schema):
    with pytest.raises(GeneratorError) as e:
        js.check(schema)
    assert e.value.code == js.E_FORM


def test_validate_checks_the_schema_first():
    with pytest.raises(GeneratorError) as e:
        js.validate({"type": "decimal"}, 1)
    assert e.value.code == js.E_FORM


def test_the_dialect_is_named():
    assert js.dialect({"$schema": js.DIALECT}) == js.DIALECT
    assert js.dialect({}) is None
    assert js.dialect(True) is None
