"""The adapter-protocol schema accepts the messages docs/adapter-protocol.md describes and refuses
malformed ones. Adapter authors run this schema in their own test suites, so it is a contract: a
message it accepts must be one the runner can read."""

import copy
import json
import pathlib

import pytest
from jsonschema import Draft202012Validator

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCHEMA = json.loads((ROOT / "schema" / "adapter-protocol.schema.json").read_text(encoding="utf-8"))
REQUEST = Draft202012Validator({**SCHEMA, "$ref": "#/$defs/request"})
RESPONSE = Draft202012Validator({**SCHEMA, "$ref": "#/$defs/response"})

HELLO_RESULT = {
    "id": 0,
    "result": {
        "protocol": 1,
        "adapter": {"name": "keriox-adapter", "version": "0.17.13-1"},
        "implementation": {"name": "keriox", "version": "0.17.13", "commit": "ddcd2aba"},
        "operations": ["cesr.parse", "keri.process"],
        "features": ["cesr.genus-2.00", "kel.basic"],
        "composes": ["keri.escrow"],
    },
}

GOOD_REQUESTS = [
    {"id": 0, "op": "hello", "protocol": 1, "supported": [1]},
    {"id": 1, "op": "cesr.parse", "stream": "2d4b"},
    {"id": 2, "op": "cesr.encode", "code": "E", "raw": "4b2a", "domain": "text"},
    {"id": 3, "op": "keri.process", "perspective": {"role": "validator"},
     "messages": [{"stream": "7b22", "source": "controller"}]},
    {"id": 4, "op": "keri.emit", "event": {"t": "icp"}, "seeds": {"DAbc": "a1b2"}},
]

GOOD_RESPONSES = [
    HELLO_RESULT,
    {"id": 1, "result": {"items": [
        {"kind": "counter", "start": 0, "end": 4, "code": "-K", "size": 1, "group_end": 92},
        {"kind": "indexed", "start": 4, "end": 92, "code": "A", "index": 0, "raw": "9c1f"},
        {"kind": "primitive", "start": 92, "end": 136, "code": "E", "raw": "4b2a"},
        {"kind": "message", "start": 136, "end": 479, "proto": "KERI", "version": "2.0",
         "serialization": "JSON", "size": 343},
    ]}},
    {"id": 1, "result": {"reject": {"class": "truncated"}}},
    {"id": 2, "result": {"encoded": "45457371"}},
    {"id": 1, "result": {"accepted": {"consumed": 479}}},
    {"id": 3, "result": {
        "dispositions": [{"initial": "pending", "final": "seen", "trunk": True,
                          "reason": "partially signed"},
                         {"initial": "seen", "final": "seen", "trunk": False},
                         {"initial": "rejected", "final": "rejected", "trunk": False}],
        "key_states": {"EAbc": {"sn": 0, "said": "EAbc", "keys": ["DAbc"], "kt": "1",
                                "ndigs": [], "nt": "0", "wits": [], "bt": "0", "delegator": None}},
    }},
    {"id": 4, "result": {"stream": "7b22"}},
    {"id": 5, "error": {"kind": "harness", "message": "panic in parser"}},
    {"id": 6, "error": {"kind": "unsupported", "message": "no ed448"}},
]


def test_schema_is_itself_valid():
    Draft202012Validator.check_schema(SCHEMA)


@pytest.mark.parametrize("message", GOOD_REQUESTS, ids=lambda m: m["op"])
def test_good_requests_validate(message):
    assert list(REQUEST.iter_errors(message)) == []


@pytest.mark.parametrize("message", GOOD_RESPONSES, ids=range(len(GOOD_RESPONSES)))
def test_good_responses_validate(message):
    assert list(RESPONSE.iter_errors(message)) == []


def test_request_needs_id_and_known_op():
    assert list(REQUEST.iter_errors({"op": "hello", "protocol": 1}))
    assert list(REQUEST.iter_errors({"id": 1, "op": "keri.guess"}))


def test_request_fields_follow_the_op():
    assert list(REQUEST.iter_errors({"id": 1, "op": "cesr.parse"})), "stream is required"
    assert list(REQUEST.iter_errors({"id": 1, "op": "cesr.parse", "stream": "XYZ"})), "hex only"


def test_response_is_result_xor_error():
    assert list(RESPONSE.iter_errors({"id": 1}))
    both = {"id": 1, "result": {"encoded": "E"}, "error": {"kind": "harness", "message": "x"}}
    assert list(RESPONSE.iter_errors(both))


def test_error_kind_is_closed():
    assert list(RESPONSE.iter_errors({"id": 1, "error": {"kind": "timeout", "message": "x"}}))


def test_hello_requires_identity_and_capabilities():
    for field in ("protocol", "adapter", "implementation", "operations", "features"):
        message = copy.deepcopy(HELLO_RESULT)
        del message["result"][field]
        assert list(RESPONSE.iter_errors(message)), field


def test_hello_composes_is_optional():
    message = copy.deepcopy(HELLO_RESULT)
    del message["result"]["composes"]
    assert list(RESPONSE.iter_errors(message)) == []


def test_unknown_disposition_is_refused():
    message = copy.deepcopy(GOOD_RESPONSES[5])
    message["result"]["dispositions"][0]["initial"] = "escrowed"
    assert list(RESPONSE.iter_errors(message))


@pytest.mark.parametrize("value", ["seen", "pending", "rejected", "duplicitous"])
@pytest.mark.parametrize("phase", ["initial", "final"])
def test_each_reading_is_seen_or_a_refinement_of_not_seen(phase, value):
    message = copy.deepcopy(GOOD_RESPONSES[5])
    message["result"]["dispositions"][1][phase] = value
    message["result"]["dispositions"][1]["trunk"] = False
    assert list(RESPONSE.iter_errors(message)) == []


@pytest.mark.parametrize("value", ["not-accepted", "not-seen", "accepted", "superseded"])
@pytest.mark.parametrize("phase", ["initial", "final"])
def test_case_projections_and_retired_values_are_not_report_values(phase, value):
    # Adapters report what their implementation did; "not-seen" is how cases grade it, and
    # "accepted" and "superseded" were replaced by the seen and trunk readings.
    message = copy.deepcopy(GOOD_RESPONSES[5])
    message["result"]["dispositions"][0][phase] = value
    assert list(RESPONSE.iter_errors(message))


def test_trunk_is_required_and_boolean():
    message = copy.deepcopy(GOOD_RESPONSES[5])
    del message["result"]["dispositions"][0]["trunk"]
    assert list(RESPONSE.iter_errors(message))
    message["result"]["dispositions"][0]["trunk"] = "yes"
    assert list(RESPONSE.iter_errors(message))


@pytest.mark.parametrize("final", ["pending", "rejected", "duplicitous"])
def test_only_a_finally_seen_message_can_be_on_the_trunk(final):
    message = copy.deepcopy(GOOD_RESPONSES[5])
    message["result"]["dispositions"][0]["final"] = final
    assert list(RESPONSE.iter_errors(message))
    message["result"]["dispositions"][0]["trunk"] = False
    assert list(RESPONSE.iter_errors(message)) == []


def test_items_need_offsets():
    message = copy.deepcopy(GOOD_RESPONSES[1])
    del message["result"]["items"][0]["start"]
    assert list(RESPONSE.iter_errors(message))


def test_key_state_shape_matches_the_case_schema():
    # Both schemas must stand alone (no cross-file $ref, which validators resolve over the
    # network), so the key-state definition is duplicated; this keeps the copies identical.
    case = json.loads((ROOT / "schema" / "case.schema.json").read_text(encoding="utf-8"))
    for name in ("key_state", "threshold"):
        assert SCHEMA["$defs"][name] == case["$defs"][name], name


def test_encoded_result_is_hex():
    assert list(RESPONSE.iter_errors({"id": 2, "result": {"encoded": "EEsq"}}))


def test_unreadable_request_error_uses_null_id():
    assert list(RESPONSE.iter_errors({"id": None, "error": {"kind": "harness", "message": "x"}})) == []
    assert list(RESPONSE.iter_errors({"id": None, "result": {"encoded": "45"}}))


def test_counter_reports_group_end():
    message = copy.deepcopy(GOOD_RESPONSES[1])
    del message["result"]["items"][0]["group_end"]
    assert list(RESPONSE.iter_errors(message))


def test_genus_item_carries_no_size_and_a_two_digit_minor():
    good = {"kind": "genus", "start": 0, "end": 8, "code": "-_AAACAA", "genus": "AAA",
            "version": "2.00"}
    assert list(RESPONSE.iter_errors({"id": 1, "result": {"items": [good]}})) == []
    for bad in ({**good, "size": 8192}, {**good, "version": "2.0"}, {**good, "group_end": 8},
                {"kind": "counter", "start": 0, "end": 8, "code": "-_AAA", "size": 0,
                 "group_end": 8, "genus": "AAA"}):
        assert list(RESPONSE.iter_errors({"id": 1, "result": {"items": [bad]}})), bad


def test_hello_request_carries_supported_versions():
    assert list(REQUEST.iter_errors({"id": 0, "op": "hello", "protocol": 1}))


def test_requests_tolerate_unknown_fields():
    assert list(REQUEST.iter_errors({"id": 0, "op": "hello", "protocol": 2, "supported": [1, 2],
                                      "future": True})) == []


def _walk(node):
    yield node
    if isinstance(node, dict):
        for value in node.values():
            yield from _walk(value)
    elif isinstance(node, list):
        for value in node:
            yield from _walk(value)


def test_nested_request_objects_tolerate_unknown_fields_too():
    request = {"id": 3, "op": "keri.process", "perspective": {"role": "validator", "future": 1},
               "messages": [{"stream": "7b22", "source": "controller", "future": 1}]}
    assert list(REQUEST.iter_errors(request)) == []


def test_no_request_object_is_closed():
    # The forward-compatibility rule: an adapter ignores unknown fields anywhere in a request, so
    # no part of a request may forbid them.
    for node in _walk(SCHEMA["$defs"]["request"]):
        if isinstance(node, dict):
            assert node.get("additionalProperties") is not False


def test_an_accepted_summary_carries_only_a_non_negative_integer_consumed():
    good = {"id": 1, "result": {"accepted": {"consumed": 0}}}
    assert list(RESPONSE.iter_errors(good)) == []
    for bad in ({"consumed": -1}, {"consumed": 1.5}, {"consumed": "4"}, {"consumed": True},
                {}, {"consumed": 4, "items": []}, 4):
        assert list(RESPONSE.iter_errors({"id": 1, "result": {"accepted": bad}})), bad
    both = {"id": 1, "result": {"accepted": {"consumed": 4}, "items": []}}
    assert list(RESPONSE.iter_errors(both))


def test_hello_operations_match_the_operations_the_runner_runs():
    """The keripy adapter found the hello enum lagging session.OPERATIONS after #17: an adapter
    offering acdc.verify failed the published schema while the runner accepted it."""
    from keri_conformance.session import OPERATIONS

    enums = [node["items"]["enum"] for node in _walk(SCHEMA)
             if isinstance(node, dict) and node.get("type") == "array"
             and isinstance(node.get("items"), dict)
             and "cesr.parse" in node["items"].get("enum", [])]
    assert enums, "the hello operations enum was not found"
    for enum in enums:
        assert set(enum) == set(OPERATIONS)


def _walk(node):
    yield node
    if isinstance(node, dict):
        for value in node.values():
            yield from _walk(value)
    elif isinstance(node, list):
        for value in node:
            yield from _walk(value)
