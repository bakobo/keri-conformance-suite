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
    {"id": 0, "op": "hello", "protocol": 1},
    {"id": 1, "op": "cesr.parse", "stream": "2d4b"},
    {"id": 2, "op": "cesr.encode", "code": "E", "raw": "4b2a", "domain": "text"},
    {"id": 3, "op": "keri.process", "perspective": {"role": "validator"},
     "messages": [{"stream": "7b22", "source": "controller"}]},
    {"id": 4, "op": "keri.emit", "event": {"t": "icp"}, "seeds": {"DAbc": "a1b2"}},
]

GOOD_RESPONSES = [
    HELLO_RESULT,
    {"id": 1, "result": {"items": [
        {"kind": "counter", "start": 0, "end": 4, "code": "-K", "size": 1},
        {"kind": "indexed", "start": 4, "end": 92, "code": "A", "index": 0, "raw": "9c1f"},
        {"kind": "primitive", "start": 92, "end": 136, "code": "E", "raw": "4b2a"},
        {"kind": "message", "start": 136, "end": 479, "proto": "KERI", "version": "2.0",
         "serialization": "JSON", "size": 343},
    ]}},
    {"id": 1, "result": {"reject": {"class": "truncated"}}},
    {"id": 2, "result": {"encoded": "EEsq"}},
    {"id": 3, "result": {
        "dispositions": [{"initial": "pending", "final": "accepted", "reason": "out-of-order"}],
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
    message = copy.deepcopy(GOOD_RESPONSES[4])
    message["result"]["dispositions"][0]["initial"] = "escrowed"
    assert list(RESPONSE.iter_errors(message))


def test_not_accepted_is_a_case_projection_not_a_report_value():
    # Adapters report what their implementation did; "not-accepted" is how cases grade it.
    message = copy.deepcopy(GOOD_RESPONSES[4])
    message["result"]["dispositions"][0]["initial"] = "not-accepted"
    assert list(RESPONSE.iter_errors(message))


def test_superseded_is_final_only():
    message = copy.deepcopy(GOOD_RESPONSES[4])
    message["result"]["dispositions"][0]["initial"] = "superseded"
    assert list(RESPONSE.iter_errors(message))


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
