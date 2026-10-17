"""The issuer and holder operations, acdc.issue and acdc.present, and acdc.verify's presentation
context: the messages docs/adapter-protocol.md gives them, as the protocol schema and the runner
read them."""

import copy
import json

import pytest
from conftest import ROOT, good
from jsonschema import Draft202012Validator

from keri_conformance.cases import INPUTS
from keri_conformance.session import (
    OPERATIONS,
    AdapterSession,
    Failure,
    Limits,
    Reply,
    beyond_schema,
    check_result_shape,
    validate_hello,
)

PROTOCOL = json.loads((ROOT / "schema" / "adapter-protocol.schema.json").read_text(
    encoding="utf-8"))
REQUEST = Draft202012Validator({**PROTOCOL, "$ref": "#/$defs/request"})
RESPONSE = Draft202012Validator({**PROTOCOL, "$ref": "#/$defs/response"})

GENUS = "2d5f414141434141"
KELS = [{"stream": GENUS + "7b7d", "source": "issuer"}]
ISSUE = {
    "id": 7, "op": "acdc.issue",
    "roles": ["issuer", "holder"],
    "schemas": ["7b7d"],
    "credentials": [
        {"name": "core", "issuer": "issuer", "issuee": "holder", "schema": "EBdX",
         "attributes": {"givenName": "Guy"}, "registry": "bup"},
        {"name": "guardian", "issuer": "holder", "schema": "EBdX", "attributes": {},
         "registry": "bup", "edges": {"core": {"credential": "core", "o": "I2I"}}},
    ],
}
BUNDLE = {
    "kels": KELS,
    "registry": [{"stream": GENUS + "7b7d"}],
    "schemas": ["7b7d"],
    "acdcs": [],
}
PRESENT = {"id": 8, "op": "acdc.present", "perspective": {"role": "holder"}, **BUNDLE,
           "held": {"stream": GENUS + "7b00"}, "disclosure": {"form": "compact"}}
VERIFY = {"id": 9, "op": "acdc.verify", "perspective": {"role": "validator"}, **BUNDLE,
          "presented": {"stream": GENUS + "7b00"},
          "presentation": {"messages": [{"stream": GENUS + "7b01", "source": "holder"}],
                           "verifier": "EVer"}}

ISSUED = {"kels": {"issuer": GENUS + "7b7d", "holder": GENUS + "7b7e"},
          "credentials": {"core": {"acdc": "7b7d", "registry": GENUS + "7b7d",
                                   "disclosure": "EBlid"},
                          "guardian": {"acdc": "7b7e", "registry": GENUS + "7b7e"}}}
PRESENTED = {"presented": {"stream": GENUS + "7b00"}}
REFUSED = {"refused": {"reason": "salt shorter than 128 bits"}}

DISCLOSURES = [
    {"form": "compact"},
    {"form": "expanded"},
    {"form": "partial", "expand": ["a", "e.le"]},
    {"form": "partial", "expand": []},
    {"form": "selective", "disclose": ["givenName", "familyName"]},
    # A holder refuses these, so a case can require the refusal; the schema must let them through.
    {"form": "selective", "disclose": []},
    {"form": "selective", "disclose": ["givenName", "givenName"]},
    {"form": "partial", "expand": ["no.such.block"]},
]


def _without(message, *path):
    message = copy.deepcopy(message)
    node = message
    for key in path[:-1]:
        node = node[key]
    del node[path[-1]]
    return message


def _with(message, value, *path):
    message = copy.deepcopy(message)
    node = message
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    return message


# --- requests -------------------------------------------------------------------------------------

GOOD_REQUESTS = [
    ISSUE,
    _with(ISSUE, [], "schemas"),
    *(_with(PRESENT, d, "disclosure") for d in DISCLOSURES),
    VERIFY,
    _without(VERIFY, "presentation"),
]


@pytest.mark.parametrize("request_", GOOD_REQUESTS, ids=range(len(GOOD_REQUESTS)))
def test_the_new_requests_validate(request_):
    assert list(REQUEST.iter_errors(request_)) == []


BAD_REQUESTS = [
    _without(ISSUE, "roles"),
    _with(ISSUE, [], "roles"),
    _without(ISSUE, "schemas"),
    _without(ISSUE, "credentials"),
    _with(ISSUE, [], "credentials"),
    _with(ISSUE, "XYZ", "schemas", 0),
    _without(ISSUE, "credentials", 0, "name"),
    _without(ISSUE, "credentials", 0, "issuer"),
    _without(ISSUE, "credentials", 0, "schema"),
    _without(ISSUE, "credentials", 0, "attributes"),
    _with(ISSUE, "upd", "credentials", 0, "registry"),
    _with(ISSUE, "7b7d", "credentials", 0, "attributes"),
    _without(PRESENT, "held"),
    _without(PRESENT, "disclosure"),
    _with(PRESENT, {"role": "validator"}, "perspective"),
    _with(PRESENT, {"form": "redacted"}, "disclosure"),
    _with(PRESENT, {"form": "partial"}, "disclosure"),
    _with(PRESENT, {"form": "selective"}, "disclosure"),
    _with(PRESENT, {"form": "partial", "expand": [""]}, "disclosure"),
    _with(PRESENT, {"form": "selective", "disclose": [7]}, "disclosure"),
    _without(VERIFY, "presentation", "messages"),
    _without(VERIFY, "presentation", "verifier"),
    _with(VERIFY, [], "presentation", "messages"),
    _with(VERIFY, "", "presentation", "verifier"),
]


@pytest.mark.parametrize("request_", BAD_REQUESTS, ids=range(len(BAD_REQUESTS)))
def test_the_new_requests_are_refused_without_what_they_need(request_):
    assert list(REQUEST.iter_errors(request_))


# --- results --------------------------------------------------------------------------------------

GOOD_RESULTS = [
    ("acdc.issue", ISSUED),
    ("acdc.issue", _without(ISSUED, "credentials", "core", "disclosure")),
    ("acdc.issue", REFUSED),
    ("acdc.issue", {"refused": {}}),
    ("acdc.present", PRESENTED),
    ("acdc.present", REFUSED),
]


@pytest.mark.parametrize(("op", "result"), GOOD_RESULTS, ids=range(len(GOOD_RESULTS)))
def test_the_new_results_are_read(op, result):
    assert list(RESPONSE.iter_errors({"id": 1, "result": result})) == []
    assert check_result_shape(op, result) is None


BAD_RESULTS = [
    ("acdc.issue", {}),
    ("acdc.issue", _without(ISSUED, "kels")),
    ("acdc.issue", _without(ISSUED, "credentials")),
    ("acdc.issue", _with(ISSUED, "XYZ", "kels", "issuer")),
    ("acdc.issue", _without(ISSUED, "credentials", "core", "acdc")),
    ("acdc.issue", _without(ISSUED, "credentials", "core", "registry")),
    ("acdc.issue", _with(ISSUED, "EAcd", "credentials", "core", "acdc")),
    ("acdc.issue", _with(ISSUED, 7, "credentials", "core", "disclosure")),
    ("acdc.issue", _with(ISSUED, {"acdc": "7b", "registry": "7b", "x": 1}, "credentials",
                         "core")),
    ("acdc.issue", {**ISSUED, **REFUSED}),
    ("acdc.issue", {"refused": {"reason": 7}}),
    ("acdc.issue", {"refused": "no"}),
    ("acdc.present", {}),
    ("acdc.present", {"presented": {}}),
    ("acdc.present", {"presented": {"stream": "zz"}}),
    ("acdc.present", {**PRESENTED, **REFUSED}),
    ("acdc.present", ISSUED),
    ("acdc.issue", PRESENTED),
]


@pytest.mark.parametrize(("op", "result"), BAD_RESULTS, ids=range(len(BAD_RESULTS)))
def test_off_shape_new_results_are_malformed(op, result):
    assert check_result_shape(op, result) is not None


def test_the_runner_knows_the_new_operations():
    assert {"acdc.issue", "acdc.present"} <= set(OPERATIONS)


def test_an_adapter_may_declare_the_new_operations_and_the_presentation_feature(vocabulary):
    hello = {"protocol": 1, "adapter": {"name": "a", "version": "1"},
             "implementation": {"name": "i", "version": "1", "commit": "c"},
             "operations": ["acdc.issue", "acdc.present", "acdc.verify"],
             "features": ["acdc.version-2.x", "acdc.presentation"]}
    assert validate_hello(hello, vocabulary) == []


def test_the_presentation_feature_is_composable():
    # An implementation that admits only its own grant shape has its adapter judge the context with
    # the implementation's parts and declare it composed (this.i 7krs5hfz, 9fg9ufsm).
    features = json.loads((ROOT / "profiles" / "features.json").read_text(encoding="utf-8"))
    assert features["features"]["acdc.presentation"]["composable"] is True


def test_holder_cases_have_inputs_and_checks():
    # acdc.present got case inputs and checks with sedi-1's holder cases
    # (tests/test_presentation_checks.py); acdc.issue has them too (tests/test_issuance.py).
    assert "acdc.present" in INPUTS and "acdc.issue" in INPUTS
    case = json.loads((ROOT / "schema" / "case.schema.json").read_text(encoding="utf-8"))
    assert "acdc.present" in case["properties"]["operation"]["enum"]


# --- what a result must match in its request ------------------------------------------------------

def _fields(request):
    return {k: v for k, v in request.items() if k not in ("id", "op")}


def test_an_issue_result_answers_every_requested_part():
    assert beyond_schema("acdc.issue", _fields(ISSUE), ISSUED) is None


@pytest.mark.parametrize(("result", "words"), [
    (_without(ISSUED, "kels", "holder"), "one KEL per role"),
    (_with(ISSUED, GENUS, "kels", "stranger"), "one KEL per role"),
    (_without(ISSUED, "credentials", "guardian"), "one entry per credential"),
    (_with(ISSUED, ISSUED["credentials"]["core"], "credentials", "extra"),
     "one entry per credential"),
])
def test_an_issue_result_that_does_not_match_its_request_is_malformed(result, words):
    problem = beyond_schema("acdc.issue", _fields(ISSUE), result)
    assert problem is not None and words in problem


def test_a_refusal_matches_any_request():
    assert beyond_schema("acdc.issue", _fields(ISSUE), REFUSED) is None
    assert beyond_schema("acdc.present", _fields(PRESENT), REFUSED) is None
    assert beyond_schema("acdc.present", _fields(PRESENT), PRESENTED) is None


def test_a_mismatched_issue_result_is_a_failure_through_the_session(write_json, vocabulary):
    hello = {"protocol": 1, "adapter": {"name": "a", "version": "1"},
             "implementation": {"name": "i", "version": "1", "commit": "c"},
             "operations": ["acdc.issue"], "features": []}
    table = [{"match": {"op": "acdc.issue"},
              "result": _without(ISSUED, "credentials", "guardian")}]
    argv = good("--table", write_json("t.json", table), "--hello", write_json("h.json", hello))
    with AdapterSession(argv, vocabulary, limits=Limits(timeout=5.0)) as session:
        session.open()
        outcome = session.request("acdc.issue", _fields(ISSUE))
    assert isinstance(outcome, Failure) and outcome.kind == "malformed"
    assert "one entry per credential" in outcome.detail


def test_a_matching_issue_result_is_read_through_the_session(write_json, vocabulary):
    hello = {"protocol": 1, "adapter": {"name": "a", "version": "1"},
             "implementation": {"name": "i", "version": "1", "commit": "c"},
             "operations": ["acdc.issue"], "features": []}
    table = [{"match": {"op": "acdc.issue"}, "result": ISSUED}]
    argv = good("--table", write_json("t.json", table), "--hello", write_json("h.json", hello))
    with AdapterSession(argv, vocabulary, limits=Limits(timeout=5.0)) as session:
        session.open()
        outcome = session.request("acdc.issue", _fields(ISSUE))
    assert isinstance(outcome, Reply) and outcome.result == ISSUED
