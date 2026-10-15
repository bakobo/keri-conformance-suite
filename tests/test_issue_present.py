"""The issuer and holder operations, acdc.issue and acdc.present, and acdc.verify's presentation
context: the messages docs/adapter-protocol.md gives them, as the protocol schema and the runner
read them. No case uses them yet, so they are checked at the protocol level only."""

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
    "kels": KELS,
    "seeds": {"DOYg": "a1b2"},
    "acdc": {"v": "", "t": "acm", "d": "", "u": "0ABn", "i": "EKBC", "rd": "EAz1", "s": "EBdX",
             "a": {"d": "", "u": "0ACx", "i": "EDB8", "givenName": "Guy"}, "e": {}, "r": {}},
    "registry": [
        {"event": {"v": "", "t": "bup", "d": "", "rd": "EAz1", "n": "1", "p": "EAz1",
                   "dt": "2026-10-15T00:00:00.000000+00:00", "b": ""},
         "blind": {"salt": "0ABz", "state": {"d": "", "u": "", "td": "", "ts": "issued"}}},
        {"event": {"v": "", "t": "upd", "d": "", "rd": "EAz1", "n": "2", "p": "EBup"}},
    ],
    "anchor": {"event": {"v": "", "t": "ixn", "d": "", "i": "EKBC", "s": "1", "p": "EKBC",
                         "a": [{"s": "1", "d": "EGsP"}]}},
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

ISSUED = {"acdc": "7b7d", "registry": [{"event": "7b7d", "blind": "7b7e"},
                                       {"event": "7b7f", "blind": None}],
          "anchor": GENUS + "7b7d"}
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
    _without(ISSUE, "anchor"),
    _with(ISSUE, [], "registry"),
    *(_with(PRESENT, d, "disclosure") for d in DISCLOSURES),
    VERIFY,
    _without(VERIFY, "presentation"),
]


@pytest.mark.parametrize("request_", GOOD_REQUESTS, ids=range(len(GOOD_REQUESTS)))
def test_the_new_requests_validate(request_):
    assert list(REQUEST.iter_errors(request_)) == []


BAD_REQUESTS = [
    _without(ISSUE, "kels"),
    _without(ISSUE, "seeds"),
    _without(ISSUE, "acdc"),
    _without(ISSUE, "registry"),
    _with(ISSUE, "7b7d", "acdc"),  # a template is an object, not bytes
    _with(ISSUE, {"DOYg": "XYZ"}, "seeds"),
    _without(ISSUE, "registry", 0, "event"),
    _without(ISSUE, "registry", 0, "blind", "salt"),
    _without(ISSUE, "registry", 0, "blind", "state"),
    _with(ISSUE, "", "registry", 0, "blind", "salt"),
    _without(ISSUE, "anchor", "event"),
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
    ("acdc.issue", _without(ISSUED, "anchor")),
    ("acdc.issue", {"acdc": "7b7d", "registry": []}),
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
    ("acdc.issue", _without(ISSUED, "acdc")),
    ("acdc.issue", _without(ISSUED, "registry")),
    ("acdc.issue", _with(ISSUED, "EAcd", "acdc")),
    ("acdc.issue", _without(ISSUED, "registry", 1, "blind")),
    ("acdc.issue", _with(ISSUED, {"event": "7b7d", "blind": "7b7e", "x": 1}, "registry", 0)),
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


def test_the_presentation_feature_is_not_composable():
    features = json.loads((ROOT / "profiles" / "features.json").read_text(encoding="utf-8"))
    assert features["features"]["acdc.presentation"]["composable"] is False


def test_no_case_may_present_until_the_holder_cases_exist():
    # acdc.present gets case inputs and checks with its first cases, and until then the case
    # schema and the runner refuse such a case. acdc.issue has them (tests/test_issuance.py).
    assert "acdc.present" not in INPUTS and "acdc.issue" in INPUTS
    case = json.loads((ROOT / "schema" / "case.schema.json").read_text(encoding="utf-8"))
    assert "acdc.present" not in case["properties"]["operation"]["enum"]


# --- what a result must match in its request ------------------------------------------------------

def _fields(request):
    return {k: v for k, v in request.items() if k not in ("id", "op")}


def test_an_issue_result_answers_every_requested_part():
    assert beyond_schema("acdc.issue", _fields(ISSUE), ISSUED) is None


@pytest.mark.parametrize(("result", "words"), [
    (_with(ISSUED, ISSUED["registry"][:1], "registry"), "2 registry events"),
    (_with(ISSUED, None, "registry", 0, "blind"), "blinded state"),
    (_with(ISSUED, "7b7d", "registry", 1, "blind"), "blinded state"),
    (_without(ISSUED, "anchor"), "anchor"),
])
def test_an_issue_result_that_does_not_match_its_request_is_malformed(result, words):
    problem = beyond_schema("acdc.issue", _fields(ISSUE), result)
    assert problem is not None and words in problem


def test_an_anchor_not_asked_for_is_malformed():
    problem = beyond_schema("acdc.issue", _fields(_without(ISSUE, "anchor")), ISSUED)
    assert problem is not None and "anchor" in problem


def test_a_refusal_matches_any_request():
    assert beyond_schema("acdc.issue", _fields(ISSUE), REFUSED) is None
    assert beyond_schema("acdc.present", _fields(PRESENT), REFUSED) is None
    assert beyond_schema("acdc.present", _fields(PRESENT), PRESENTED) is None


def test_a_mismatched_issue_result_is_a_failure_through_the_session(write_json, vocabulary):
    hello = {"protocol": 1, "adapter": {"name": "a", "version": "1"},
             "implementation": {"name": "i", "version": "1", "commit": "c"},
             "operations": ["acdc.issue"], "features": []}
    table = [{"match": {"op": "acdc.issue"},
              "result": _with(ISSUED, ISSUED["registry"][:1], "registry")}]
    argv = good("--table", write_json("t.json", table), "--hello", write_json("h.json", hello))
    with AdapterSession(argv, vocabulary, limits=Limits(timeout=5.0)) as session:
        session.open()
        outcome = session.request("acdc.issue", _fields(ISSUE))
    assert isinstance(outcome, Failure) and outcome.kind == "malformed"
    assert "registry events" in outcome.detail


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
