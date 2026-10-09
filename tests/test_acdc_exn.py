"""ACDC and exchange-message cases: loading them, checking adapters' answers to acdc.verify and
exn.verify, evaluating their assertions, and running them end to end.

The rules come from docs/design.md (ACDC: the bundle, Verdicts, Registry state, Edges; IPEX: the
exchange-message reading) and docs/adapter-protocol.md (acdc.verify, exn.verify).
"""

import copy
import json
import shlex

import pytest
from conftest import ROOT, assertion, good, make_case
from jsonschema import Draft202012Validator

from keri_conformance import cli, errors
from keri_conformance.assertions import evaluate
from keri_conformance.cases import MAX_DAG_ACDCS, MAX_DAG_DEPTH, case_problem, load_cases
from keri_conformance.session import OPERATIONS, check_result_shape, validate_hello

CASE_SCHEMA = Draft202012Validator(
    json.loads((ROOT / "schema" / "case.schema.json").read_text(encoding="utf-8")))
PROTOCOL = json.loads((ROOT / "schema" / "adapter-protocol.schema.json").read_text(
    encoding="utf-8"))
REQUEST = Draft202012Validator({**PROTOCOL, "$ref": "#/$defs/request"})
RESPONSE = Draft202012Validator({**PROTOCOL, "$ref": "#/$defs/response"})

GENUS = "2d5f414141434141"
REGISTRY = {"rd": "EReg", "n": 1, "d": "EBup", "td": "EAcd", "ts": "issued"}
BUNDLE = {
    "perspective": {"role": "validator"},
    "kels": [{"stream": GENUS + "7b7d", "source": "issuer"}],
    "registry": [{"stream": GENUS + "7b7d"}, {"stream": GENUS + "7b7e"}],
    "schemas": ["7b7d"],
    "acdcs": [{"stream": GENUS + "7b01"}],
    "presented": {"stream": GENUS + "7b00"},
}
DAG = {"root": "EAcd", "edges": [{"near": "EAcd", "path": "e.le", "n": "EFar"}]}
AS_OF = {"EIss": 2, "EReg": 1}


def acdc_case(case_id, assertions, *, presented="7b00", dag=DAG, **kwargs):
    bundle = {**BUNDLE, "presented": {"stream": GENUS + presented}}
    case = make_case(case_id, "acdc.verify", bundle, assertions, profile="acdc-1.0",
                     features=["acdc.version-2.x"], **kwargs)
    case["dag"] = copy.deepcopy(dag)
    case["as_of"] = dict(AS_OF)
    return case


def exn_case(case_id, assertions, *, messages=2, stream="7b7d", **kwargs):
    return make_case(case_id, "exn.verify",
                     {"perspective": {"role": "validator"},
                      "kels": [{"stream": GENUS + "7b7d", "source": "issuer"}],
                      "messages": [{"stream": GENUS + stream, "source": "issuer"}] * messages},
                     assertions, profile="keri-1.0", **kwargs)


ALL_ACDC_CHECKS = [
    assertion("verdict", expected="valid", level="SHOULD"),
    assertion("registry_reported", name="a2", level="SHOULD", expected=True),
    assertion("registry_state", name="a3", expected=REGISTRY),
    assertion("edge_reported", name="a4", level="SHOULD", near="EAcd", path="e.le"),
    assertion("edge_valid", name="a5", level="SHOULD", near="EAcd", path="e.le", expected=True),
]


# --- operations and features ---------------------------------------------------------------------


def test_the_runner_knows_both_new_operations():
    assert "acdc.verify" in OPERATIONS
    assert "exn.verify" in OPERATIONS


def test_an_adapter_may_declare_the_new_operations_and_features():
    from keri_conformance.session import load_vocabulary

    vocabulary = load_vocabulary(ROOT)
    hello = {"protocol": 1, "adapter": {"name": "a", "version": "1"},
             "implementation": {"name": "i", "version": "1", "commit": "c"},
             "operations": ["acdc.verify", "exn.verify"],
             "features": ["acdc.version-2.x", "acdc.edges", "acdc.registry.bup",
                          "acdc.keripy-1x", "acdc.ptel-1x"]}
    assert validate_hello(hello, vocabulary) == []


@pytest.mark.parametrize("name", ["acdc.version-2.x", "acdc.edges", "acdc.registry.bup",
                                  "acdc.keripy-1x", "acdc.ptel-1x"])
def test_the_acdc_features_are_not_composable(name):
    # An adapter that verified ACDCs itself would be what the case tests, not the implementation.
    features = json.loads((ROOT / "profiles" / "features.json").read_text())["features"]
    assert features[name]["composable"] is False


# --- cases ---------------------------------------------------------------------------------------

GOOD_CASES = [
    acdc_case("ACDC-0001", ALL_ACDC_CHECKS),
    acdc_case("ACDC-0002", [assertion("verdict", expected="not-valid"),
                            assertion("registry_reported", name="a2", level="SHOULD",
                                      expected=False),
                            assertion("edge_valid", name="a3", near="EAcd", path="e.le",
                                      expected=False)],
              dag={"root": "EAcd", "edges": []}),
    exn_case("KERI-0101", [assertion("exn_verdict", message=0, expected="rejected"),
                           assertion("exn_verdict", name="a2", level="SHOULD", message=1,
                                     expected="accepted")]),
]


@pytest.mark.parametrize("case", GOOD_CASES, ids=[c["id"] for c in GOOD_CASES])
def test_acdc_and_exn_cases_satisfy_the_schema_and_the_runtime_check(case):
    assert list(CASE_SCHEMA.iter_errors(case)) == []
    assert case_problem(case) is None


def test_an_acdc_case_may_name_the_schema_the_validator_expects():
    case = acdc_case("ACDC-0001", ALL_ACDC_CHECKS)
    case["input"]["expect_schema"] = "ESch"
    assert CASE_SCHEMA.is_valid(case)
    assert case_problem(case) is None


def test_an_acdc_case_needs_a_dag_and_an_evaluation_point():
    for field in ("dag", "as_of"):
        case = acdc_case("ACDC-0001", ALL_ACDC_CHECKS)
        del case[field]
        assert not CASE_SCHEMA.is_valid(case)
        assert field in case_problem(case)


def test_only_an_acdc_case_carries_a_dag_or_an_evaluation_point():
    for field, value in (("dag", DAG), ("as_of", AS_OF)):
        case = copy.deepcopy(GOOD_CASES[2])
        case[field] = value
        assert not CASE_SCHEMA.is_valid(case)
        assert field in case_problem(case)


def test_the_bundle_holds_at_most_fifteen_acdcs_beside_the_presented_one():
    assert MAX_DAG_ACDCS == 16
    case = acdc_case("ACDC-0001", ALL_ACDC_CHECKS)
    case["input"]["acdcs"] = [{"stream": GENUS}] * (MAX_DAG_ACDCS - 1)
    assert CASE_SCHEMA.is_valid(case)
    assert case_problem(case) is None
    case["input"]["acdcs"].append({"stream": GENUS})
    assert not CASE_SCHEMA.is_valid(case)
    assert "acdcs" in case_problem(case)


def chain(length, root="N0"):
    """A provenance chain of `length` edges from `root`."""
    return {"root": root, "edges": [{"near": f"N{i}", "path": "e.up", "n": f"N{i + 1}"}
                                    for i in range(length)]}


def test_the_longest_path_from_the_presented_acdc_has_at_most_eight_edges():
    assert MAX_DAG_DEPTH == 8
    assert case_problem(acdc_case("ACDC-0001", ALL_ACDC_CHECKS, dag=chain(8))) is None
    problem = case_problem(acdc_case("ACDC-0001", ALL_ACDC_CHECKS, dag=chain(9)))
    assert "9 edges" in problem and "8" in problem


def test_a_dag_of_more_than_sixteen_acdcs_is_refused():
    star = {"root": "R", "edges": [{"near": "R", "path": f"e.x{i}", "n": f"F{i}"}
                                   for i in range(MAX_DAG_ACDCS - 1)]}
    assert case_problem(acdc_case("ACDC-0001", ALL_ACDC_CHECKS, dag=star)) is None
    star["edges"].append({"near": "R", "path": "e.extra", "n": "Fextra"})
    problem = case_problem(acdc_case("ACDC-0001", ALL_ACDC_CHECKS, dag=star))
    assert "17 ACDCs" in problem


def test_a_diamond_counts_its_shared_far_node_once():
    diamond = {"root": "A", "edges": [{"near": "A", "path": "e.l", "n": "B"},
                                      {"near": "A", "path": "e.r", "n": "C"},
                                      {"near": "B", "path": "e.d", "n": "D"},
                                      {"near": "C", "path": "e.d", "n": "D"}]}
    assert case_problem(acdc_case("ACDC-0001", ALL_ACDC_CHECKS, dag=diamond)) is None


@pytest.mark.parametrize("edges", [
    [{"near": "A", "path": "e.self", "n": "A"}],
    [{"near": "A", "path": "e.x", "n": "B"}, {"near": "B", "path": "e.y", "n": "A"}],
    # A cycle away from the root is still not a DAG.
    [{"near": "A", "path": "e.x", "n": "B"}, {"near": "C", "path": "e.y", "n": "D"},
     {"near": "D", "path": "e.z", "n": "C"}],
])
def test_a_cycle_is_refused(edges):
    problem = case_problem(acdc_case("ACDC-0001", ALL_ACDC_CHECKS,
                                     dag={"root": "A", "edges": edges}))
    assert "cycle" in problem


def test_an_edge_listed_twice_is_refused():
    edges = [{"near": "A", "path": "e.x", "n": "B"}, {"near": "A", "path": "e.x", "n": "C"}]
    problem = case_problem(acdc_case("ACDC-0001", ALL_ACDC_CHECKS,
                                     dag={"root": "A", "edges": edges}))
    assert "twice" in problem and "e.x" in problem


@pytest.mark.parametrize("path", ["le", "e", "e.", "e..le", "a.le", ".e.le"])
def test_an_edge_path_starts_at_the_top_level_e_field(path):
    case = acdc_case("ACDC-0001", [assertion("edge_reported", near="EAcd", path=path)])
    assert not CASE_SCHEMA.is_valid(case)
    assert "path" in case_problem(case)
    dag = {"root": "A", "edges": [{"near": "A", "path": path, "n": "B"}]}
    case = acdc_case("ACDC-0001", ALL_ACDC_CHECKS, dag=dag)
    assert not CASE_SCHEMA.is_valid(case)
    assert case_problem(case) is not None


def test_an_exn_assertion_names_a_delivered_message():
    case = exn_case("KERI-0101", [assertion("exn_verdict", message=2, expected="rejected")])
    assert CASE_SCHEMA.is_valid(case)
    assert "message 2" in case_problem(case)


@pytest.mark.parametrize("expected", ["valid", "not-valid"])
def test_a_verdict_is_graded_as_valid_or_not_valid(expected):
    case = acdc_case("ACDC-0001", [assertion("verdict", expected=expected)])
    assert case_problem(case) is None
    for wrong in ("invalid", "incomplete", "revoked"):
        case["assertions"][0]["expected"] = wrong
        assert not CASE_SCHEMA.is_valid(case)
        assert case_problem(case) is not None


@pytest.mark.parametrize(("operation", "check"), [
    ("acdc.verify", "exn_verdict"), ("exn.verify", "verdict"), ("keri.process", "edge_valid"),
])
def test_the_new_checks_fit_only_their_operation(operation, check):
    sample = {a["check"]: a for c in GOOD_CASES for a in c["assertions"]}[check]
    case = copy.deepcopy(GOOD_CASES[0] if operation == "acdc.verify" else GOOD_CASES[2])
    if operation == "keri.process":
        case = make_case("KERI-0001", "keri.process",
                         {"perspective": {"role": "validator"},
                          "messages": [{"stream": "7b7d", "source": "c"}]}, [sample])
    case["assertions"] = [sample]
    assert not CASE_SCHEMA.is_valid(case)
    assert "operation" in case_problem(case)


def test_acdc_cases_load_from_disk(cases_dir):
    loaded = load_cases(cases_dir(*GOOD_CASES))
    assert [c["id"] for c in loaded] == ["ACDC-0001", "ACDC-0002", "KERI-0101"]


# --- adapter results -----------------------------------------------------------------------------

ACDC_RESULT = {"verdict": "valid", "reason": "sealed in issuer ixn 1", "registry": REGISTRY,
               "edges": [{"near": "EAcd", "path": "e.le", "n": "EFar", "valid": True}]}
EXN_RESULT = {"verdicts": [{"on_delivery": "rejected", "verdict": "rejected", "reason": "sig"},
                           {"on_delivery": "accepted", "verdict": "accepted"}]}


@pytest.mark.parametrize(("op", "result"), [
    ("acdc.verify", ACDC_RESULT),
    ("acdc.verify", {"verdict": "incomplete", "registry": None, "edges": []}),
    ("acdc.verify", {"verdict": "invalid", "edges": [],
                     "registry": {**REGISTRY, "td": None, "ts": None}}),
    ("exn.verify", EXN_RESULT),
])
def test_well_formed_results_are_read(op, result):
    assert check_result_shape(op, result) is None
    assert list(RESPONSE.iter_errors({"id": 5, "result": result})) == []


@pytest.mark.parametrize(("op", "result", "names"), [
    ("acdc.verify", {**ACDC_RESULT, "verdict": "revoked"}, "verdict"),
    ("acdc.verify", {k: v for k, v in ACDC_RESULT.items() if k != "registry"}, "registry"),
    ("acdc.verify", {k: v for k, v in ACDC_RESULT.items() if k != "edges"}, "edges"),
    ("acdc.verify", {**ACDC_RESULT, "registry": {**REGISTRY, "n": "1"}}, "n"),
    ("acdc.verify", {**ACDC_RESULT, "registry": {**REGISTRY, "extra": 1}}, "extra"),
    ("acdc.verify", {**ACDC_RESULT, "edges": [{"near": "EAcd", "path": "e.le", "n": "EFar"}]},
     "valid"),
    ("acdc.verify", {**ACDC_RESULT, "edges": [{"near": "EAcd", "path": "le", "n": "EFar",
                                               "valid": True}]}, "path"),
    ("acdc.verify", {**ACDC_RESULT, "edges": [{"near": "", "path": "e.le", "n": "EFar",
                                               "valid": True}]}, "near"),
    ("exn.verify", {"verdicts": [{"verdict": "accepted"}]}, "on_delivery"),
    ("exn.verify", {"verdicts": [{"on_delivery": "seen", "verdict": "accepted"}]},
     "on_delivery"),
    ("exn.verify", {"verdicts": [{"on_delivery": "accepted", "verdict": "accepted", "x": 1}]},
     "x"),
])
def test_off_shape_results_are_malformed(op, result, names):
    problem = check_result_shape(op, result)
    assert problem is not None and names in problem
    assert list(RESPONSE.iter_errors({"id": 5, "result": result}))


@pytest.mark.parametrize("request_", [
    {"id": 5, "op": "acdc.verify", **BUNDLE},
    {"id": 5, "op": "acdc.verify", **BUNDLE, "expect_schema": "ESch"},
    {"id": 6, "op": "exn.verify", **GOOD_CASES[2]["input"]},
])
def test_the_requests_the_runner_sends_validate(request_):
    assert list(REQUEST.iter_errors(request_)) == []


def test_requests_are_refused_without_their_bundle():
    assert list(REQUEST.iter_errors({"id": 5, "op": "acdc.verify", "kels": []}))
    assert list(REQUEST.iter_errors({"id": 6, "op": "exn.verify", "kels": []}))


# --- evaluation ----------------------------------------------------------------------------------


def outcome(check, result, **fields):
    return evaluate(assertion(check, **fields), result)


@pytest.mark.parametrize(("expected", "verdict", "result"), [
    ("valid", "valid", "pass"), ("valid", "invalid", "fail"), ("valid", "incomplete", "fail"),
    ("not-valid", "invalid", "pass"), ("not-valid", "incomplete", "pass"),
    ("not-valid", "valid", "fail"),
])
def test_a_verdict_is_valid_or_not_valid(expected, verdict, result):
    evaluation = outcome("verdict", {**ACDC_RESULT, "verdict": verdict}, expected=expected)
    assert evaluation.outcome == result
    assert evaluation.actual == verdict


@pytest.mark.parametrize(("expected", "registry", "result"), [
    (True, REGISTRY, "pass"), (True, None, "fail"), (False, None, "pass"),
    (False, REGISTRY, "fail"),
])
def test_whether_a_registry_is_reported(expected, registry, result):
    evaluation = outcome("registry_reported", {**ACDC_RESULT, "registry": registry},
                         expected=expected)
    assert evaluation.outcome == result


def test_a_registry_state_matching_the_head_passes():
    evaluation = outcome("registry_state", ACDC_RESULT, expected=REGISTRY)
    assert evaluation.outcome == "pass"
    assert evaluation.actual == REGISTRY


def test_a_registry_state_differing_names_the_fields():
    evaluation = outcome("registry_state", {**ACDC_RESULT, "registry": {**REGISTRY, "n": 2,
                                                                        "ts": None}},
                         expected=REGISTRY)
    assert evaluation.outcome == "fail"
    assert "n, ts" in evaluation.detail


def test_an_unknown_blinded_state_compares_as_null():
    unknown = {**REGISTRY, "td": None, "ts": None}
    assert outcome("registry_state", {**ACDC_RESULT, "registry": unknown},
                   expected=unknown).outcome == "pass"
    assert outcome("registry_state", ACDC_RESULT, expected=unknown).outcome == "fail"


@pytest.mark.parametrize("verdict", ["invalid", "incomplete"])
def test_an_unreported_registry_makes_registry_state_not_applicable_unless_valid(verdict):
    evaluation = outcome("registry_state", {**ACDC_RESULT, "verdict": verdict, "registry": None},
                         expected=REGISTRY)
    assert evaluation.outcome == "not-applicable"


@pytest.mark.parametrize("level", ["MUST", "SHOULD"])
def test_a_valid_verdict_with_no_registry_fails_registry_state(level):
    # A valid verdict commits the adapter to the registry it relied on (design.md, Registry state).
    evaluation = outcome("registry_state", {**ACDC_RESULT, "registry": None}, level=level,
                         expected=REGISTRY)
    assert evaluation.outcome == "fail"
    assert "valid" in evaluation.detail


def test_an_edge_is_reported_or_not():
    assert outcome("edge_reported", ACDC_RESULT, near="EAcd", path="e.le").outcome == "pass"
    for near, path in (("EFar", "e.le"), ("EAcd", "e.qvi")):
        evaluation = outcome("edge_reported", ACDC_RESULT, near=near, path=path)
        assert evaluation.outcome == "fail"
        assert path in evaluation.detail


@pytest.mark.parametrize(("expected", "reported", "result"), [
    (True, True, "pass"), (True, False, "fail"), (False, False, "pass"), (False, True, "fail"),
])
def test_a_reported_edge_is_graded_on_its_validity(expected, reported, result):
    edges = [{"near": "EAcd", "path": "e.le", "n": "EFar", "valid": reported}]
    for verdict in ("valid", "invalid"):
        evaluation = outcome("edge_valid", {**ACDC_RESULT, "verdict": verdict, "edges": edges},
                             near="EAcd", path="e.le", expected=expected)
        assert evaluation.outcome == result
        assert evaluation.actual is reported


@pytest.mark.parametrize("verdict", ["valid", "invalid", "incomplete"])
def test_an_unreported_edge_expected_valid_is_not_applicable(verdict):
    evaluation = outcome("edge_valid", {**ACDC_RESULT, "verdict": verdict, "edges": []},
                         level="SHOULD", near="EAcd", path="e.le", expected=True)
    assert evaluation.outcome == "not-applicable"


@pytest.mark.parametrize(("verdict", "result"), [
    ("valid", "fail"), ("invalid", "pass"), ("incomplete", "pass"),
])
def test_a_failing_must_edge_commits_a_valid_verdict_to_reporting_it(verdict, result):
    # design.md, Edges: a valid verdict that does not report the failing edge as not valid fails.
    evaluation = outcome("edge_valid", {**ACDC_RESULT, "verdict": verdict, "edges": []},
                         near="EAcd", path="e.le", expected=False)
    assert evaluation.outcome == result


def test_the_edge_commitment_binds_only_a_must_assertion():
    evaluation = outcome("edge_valid", {**ACDC_RESULT, "edges": []}, level="SHOULD",
                         near="EAcd", path="e.le", expected=False)
    assert evaluation.outcome == "not-applicable"


def test_an_edge_is_found_by_near_node_and_path_together():
    edges = [{"near": "EOther", "path": "e.le", "n": "EFar", "valid": False},
             {"near": "EAcd", "path": "e.qvi", "n": "EFar", "valid": False},
             {"near": "EAcd", "path": "e.le", "n": "EFar", "valid": True}]
    evaluation = outcome("edge_valid", {**ACDC_RESULT, "edges": edges}, near="EAcd",
                         path="e.le", expected=True)
    assert evaluation.outcome == "pass"


@pytest.mark.parametrize(("expected", "on_delivery", "final", "result"), [
    ("rejected", "rejected", "rejected", "pass"),
    ("rejected", "accepted", "rejected", "fail"),  # accepted on arrival, retracted later
    ("rejected", "rejected", "accepted", "fail"),
    ("rejected", "accepted", "accepted", "fail"),
    ("accepted", "accepted", "accepted", "pass"),
    ("accepted", "rejected", "accepted", "pass"),
    ("accepted", "accepted", "rejected", "fail"),
])
def test_an_exchange_message_is_read_on_delivery_and_at_the_end(expected, on_delivery, final,
                                                                 result):
    entry = {"on_delivery": on_delivery, "verdict": final}
    evaluation = outcome("exn_verdict", {"verdicts": [EXN_RESULT["verdicts"][0], entry]},
                         message=1, expected=expected)
    assert evaluation.outcome == result
    assert evaluation.actual == entry
    if result == "fail":
        assert "message 1" in evaluation.detail.lower()


def test_an_unanswered_exchange_message_fails():
    evaluation = outcome("exn_verdict", {"verdicts": []}, message=0, expected="accepted")
    assert evaluation.outcome == "fail"
    assert evaluation.actual is None


# --- the session ---------------------------------------------------------------------------------


def run(table, cases, tmp_path, write_json, operations=("acdc.verify", "exn.verify")):
    hello = {"protocol": 1, "adapter": {"name": "fake", "version": "1"},
             "implementation": {"name": "fake-impl", "version": "1", "commit": "c"},
             "operations": list(operations),
             "features": ["acdc.version-2.x", "acdc.edges", "acdc.registry.bup"]}
    adapter = good("--hello", write_json("hello.json", hello),
                   "--table", write_json("table.json", table))
    report = tmp_path / "report.json"
    code = cli.main(["run", "--adapter", shlex.join(adapter), "--suite", str(ROOT),
                     "--cases", str(cases), "--report", str(report)])
    return code, json.loads(report.read_text())


def outcomes(report):
    return {c["id"]: [a["outcome"] for a in c["assertions"]] for c in report["cases"]}


def test_an_edge_reported_twice_is_malformed(cases_dir, tmp_path, write_json):
    edge = ACDC_RESULT["edges"][0]
    table = [{"match": {"op": "acdc.verify"}, "result": {**ACDC_RESULT, "edges": [edge, edge]}}]
    _code, report = run(table, cases_dir(GOOD_CASES[0]), tmp_path, write_json)
    case = report["cases"][0]
    assert case["failure"]["kind"] == "malformed"
    assert "e.le" in case["failure"]["detail"] and "twice" in case["failure"]["detail"]
    assert set(outcomes(report)["ACDC-0001"]) == {"fail"}


def test_too_few_exchange_verdicts_are_malformed(cases_dir, tmp_path, write_json):
    table = [{"match": {"op": "exn.verify"},
              "result": {"verdicts": EXN_RESULT["verdicts"][:1]}}]
    _code, report = run(table, cases_dir(GOOD_CASES[2]), tmp_path, write_json)
    case = report["cases"][0]
    assert case["failure"]["kind"] == "malformed"
    assert "1 verdict for 2 messages" in case["failure"]["detail"]


def test_an_adapter_without_the_operations_is_not_sent_the_cases(cases_dir, tmp_path,
                                                                 write_json):
    _code, report = run([], cases_dir(*GOOD_CASES), tmp_path, write_json,
                        operations=("cesr.parse",))
    assert {c["outcome"] for c in report["cases"]} == {"not-supported"}


# --- end to end ----------------------------------------------------------------------------------


def test_kcs_run_grades_every_new_check_end_to_end(cases_dir, tmp_path, write_json):
    valid_answer = ACDC_RESULT
    refusal_answer = {"verdict": "invalid", "registry": None, "edges": []}
    wrong_answer = {"verdict": "valid", "registry": {**REGISTRY, "n": 0},
                    "edges": [{"near": "EAcd", "path": "e.le", "n": "EFar", "valid": False}]}
    dodging_answer = {"verdict": "valid", "registry": None, "edges": []}
    table = [
        {"match": {"op": "acdc.verify", "presented": {"stream": GENUS + "7b00"}},
         "result": valid_answer},
        {"match": {"op": "acdc.verify", "presented": {"stream": GENUS + "7b01"}},
         "result": refusal_answer},
        {"match": {"op": "acdc.verify", "presented": {"stream": GENUS + "7b02"}},
         "result": wrong_answer},
        {"match": {"op": "acdc.verify", "presented": {"stream": GENUS + "7b03"}},
         "result": dodging_answer},
        {"match": {"op": "exn.verify"}, "result": {"verdicts": [
            {"on_delivery": "rejected", "verdict": "rejected"},
            {"on_delivery": "accepted", "verdict": "rejected"},
            {"on_delivery": "accepted", "verdict": "accepted"}]}},
    ]
    must_refuse = [assertion("verdict", expected="not-valid"),
                   assertion("registry_reported", name="a2", level="SHOULD", expected=False),
                   assertion("registry_state", name="a3", expected=REGISTRY),
                   assertion("edge_valid", name="a4", near="EAcd", path="e.le", expected=False),
                   assertion("edge_reported", name="a5", level="SHOULD", near="EAcd",
                             path="e.le")]
    cases = cases_dir(
        acdc_case("ACDC-0001", ALL_ACDC_CHECKS),
        acdc_case("ACDC-0002", must_refuse, presented="7b01"),
        acdc_case("ACDC-0003", [assertion("verdict", expected="not-valid"),
                                assertion("registry_state", name="a2", expected=REGISTRY),
                                assertion("edge_valid", name="a3", level="SHOULD", near="EAcd",
                                          path="e.le", expected=True)],
                  presented="7b02"),
        acdc_case("ACDC-0004", [assertion("registry_state", expected=REGISTRY),
                                assertion("edge_valid", name="a2", near="EAcd", path="e.le",
                                          expected=False)],
                  presented="7b03"),
        exn_case("KERI-0101", [assertion("exn_verdict", message=0, expected="rejected"),
                               assertion("exn_verdict", name="a2", message=1,
                                         expected="rejected"),
                               assertion("exn_verdict", name="a3", level="SHOULD", message=2,
                                         expected="accepted")],
                 messages=3),
    )
    code, report = run(table, cases, tmp_path, write_json)
    assert outcomes(report) == {
        "ACDC-0001": ["pass", "pass", "pass", "pass", "pass"],
        # Refused, with nothing reported: the conditional registry and edge assertions do not
        # apply, the failing edge holds through the not-valid verdict, and the unreported edge
        # fails its SHOULD.
        "ACDC-0002": ["pass", "pass", "not-applicable", "pass", "fail"],
        "ACDC-0003": ["fail", "fail", "fail"],
        # A valid verdict that reports neither the registry nor the failing edge dodges nothing.
        "ACDC-0004": ["fail", "fail"],
        "KERI-0101": ["pass", "fail", "pass"],
    }
    assert code == errors.EXIT_FAILED
    assert report["verdict"] == "not-conformant"
    first = {a["id"]: a for a in report["cases"][0]["assertions"]}
    assert first["a3"]["actual"] == REGISTRY
    assert first["a5"]["expected"] is True


def test_the_registry_state_definition_is_identical_in_both_schemas():
    case = json.loads((ROOT / "schema" / "case.schema.json").read_text(encoding="utf-8"))
    assert case["$defs"]["registry_state"] == PROTOCOL["$defs"]["registry_state"]
