"""acdc.issue cases: the case contract, and the two issuance checks, which grade what was issued
by verifying it rather than by its bytes (docs/adapter-protocol.md, acdc.issue; this.i 2u2ps8mt).
The verification itself is tested in tests/test_issued.py."""

import copy
import json
import shlex

import issued_world as w
import pytest
from conftest import ROOT, assertion, make_case

from keri_conformance import cli
from keri_conformance.assertions import evaluate
from keri_conformance.cases import case_problem

REQUEST, RESULT, _ = w.issuance()
BASIS = "Hand-built for the runner's tests."


def issue_case(request=None, assertions=None, **kwargs):
    assertions = assertions or [assertion("issued", level="INTEROP", basis=BASIS)]
    return make_case("ACDC-0901", "acdc.issue", copy.deepcopy(request or REQUEST), assertions,
                     profile="sedi-1", **kwargs)


# --- the case contract ------------------------------------------------------------------------

def test_an_issuance_case_is_valid():
    assert case_problem(issue_case()) is None
    refused = assertion("issue_refused", level="INTEROP", basis=BASIS)
    assert case_problem(issue_case(assertions=[refused])) is None
    with_edges = copy.deepcopy(REQUEST)
    with_edges["credentials"].append({**with_edges["credentials"][0], "name": "n", "edges": {
        "o": "OR", "g": {"le": {"credential": "c", "o": "I2I"}}}})
    assert case_problem(issue_case(with_edges)) is None


def changed(change):
    request = copy.deepcopy(REQUEST)
    change(request)
    return request


@pytest.mark.parametrize(("request_", "words"), [
    (changed(lambda r: r["roles"].append("issuer")), "role twice"),
    (changed(lambda r: r["credentials"].append(copy.deepcopy(r["credentials"][0]))),
     "credential twice"),
    (changed(lambda r: r["credentials"][0].update(issuer="nobody")), "nobody"),
    (changed(lambda r: r["credentials"][0].update(issuee="nobody")), "nobody"),
    (changed(lambda r: r["credentials"][0].update(edges={"le": {"credential": "c"}})),
     "another credential"),
    (changed(lambda r: r["credentials"][0].update(edges={"le": {"credential": "x"}})),
     "another credential"),
    (changed(lambda r: r["credentials"][0].update(edges={"le": "x"})), "another credential"),
    (changed(lambda r: r["credentials"][0].update(edges={"le": {"credential": 7}})),
     "another credential"),
    (changed(lambda r: r["credentials"][0].update(edges={"g": {"le": "x"}})),
     "another credential"),
])
def test_an_issuance_case_must_agree_with_itself(request_, words):
    problem = case_problem(issue_case(request_))
    assert problem is not None and words in problem


def test_an_issuance_case_belongs_to_the_acdc_layer():
    case = issue_case()
    case["id"] = "KERI-0901"
    assert "ACDC-" in case_problem(case)


# --- the checks -------------------------------------------------------------------------------

def check(name, result):
    return evaluate({"id": "a1", "check": name, "level": "INTEROP", "basis": BASIS}, result,
                    REQUEST)


def test_an_issuance_that_verifies_passes():
    assert check("issued", RESULT).outcome == "pass"
    assert check("issue_refused", RESULT).outcome == "fail"


def test_an_issuance_that_does_not_verify_fails_and_says_why():
    result = copy.deepcopy(RESULT)
    result["kels"]["issuer"] = "00"
    evaluation = check("issued", result)
    assert evaluation.outcome == "fail" and "issuer's KEL" in evaluation.detail


def test_a_refusal_passes_only_a_case_that_must_be_refused():
    assert check("issue_refused", {"refused": {}}).outcome == "pass"
    evaluation = check("issued", {"refused": {"reason": "x"}})
    assert evaluation.outcome == "fail" and "refused" in evaluation.detail


# --- end to end -------------------------------------------------------------------------------

def test_kcs_run_grades_an_issuance(cases_dir, tmp_path, write_json):
    hello = {"protocol": 1, "adapter": {"name": "a", "version": "1"},
             "implementation": {"name": "i", "version": "1", "commit": "c"},
             "operations": ["acdc.issue"], "features": []}
    table = [{"match": {"op": "acdc.issue"}, "result": RESULT}]
    from conftest import good
    argv = good("--table", write_json("t.json", table), "--hello", write_json("h.json", hello))
    report_path = tmp_path / "report.json"
    code = cli.main(["run", "--adapter", shlex.join(argv), "--suite", str(ROOT), "--cases",
                     str(cases_dir(issue_case())), "--report", str(report_path)])
    report = json.loads(report_path.read_text())
    assert [r["outcome"] for r in report["cases"][0]["assertions"]] == ["pass"]
    assert code == 0
