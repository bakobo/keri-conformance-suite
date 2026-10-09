"""The ACDC case builder: scenario composition, the checks it makes before writing a case, and
the grading calculus of docs/design.md ("How levels are derived")."""

import copy
import json
import os
import pathlib
import shutil
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from generators.spec_tables import acdc_cases as ac
from generators.spec_tables import acdc_model as am
from generators.spec_tables import regenerate, spec_source, tables
from generators.spec_tables.errors import ScenarioError

try:
    TEXTS = {"acdc": spec_source.load_spec(pin=spec_source.ACDC), "cesr": spec_source.load_spec()}
except spec_source.SpecUnavailable as e:
    if os.environ.get("KCS_REQUIRE_SPEC") == "1":
        raise
    pytest.skip(f"a pinned specification text is unavailable: {e}", allow_module_level=True)

T = tables.load(TEXTS["cesr"])
REGISTRY = json.loads((ROOT / "scenarios" / "acdc" / "clauses.json").read_text())
CLAUSES, INFERENCES, CONFLICTS = ac.resolve_registry(REGISTRY, TEXTS)


def scenario(name):
    return json.loads((ROOT / "scenarios" / "acdc" / f"{name}.json").read_text())


STRUCTURE, REG, EDGES = scenario("structure"), scenario("registry"), scenario("edges")


def one(scen, key):
    return copy.deepcopy(next(c for c in scen["cases"] if c["key"] == key))


def grade(scen, key, pairs=None, **over):
    c = {**one(scen, key), **over}
    ev = ac.build(T, scen["fixtures"], c)
    return ac.build_acdc_case("scenarios/acdc/t.json", c, ev, pairs or {"KS-01": ("ACDC-0001",
                              False), "KS-27": ("ACDC-0025", False), "KS-39": ("ACDC-0043",
                              False), "KS-31p": ("ACDC-0032", False)}, CLAUSES, INFERENCES,
                              CONFLICTS)


# -- composition --------------------------------------------------------------------------------

FIX = {"f": {"events": [{"name": "e1", "x": 1}], "kels": [{"event": "e1"}, {"event": "e2"}]}}


def test_compose_patches_removes_appends_and_replaces():
    frag = ac.compose(FIX, {"base": "f", "patch": {"events": {"e1": {"x": None, "y": 2}}},
                            "remove": {"kels": ["e2"]}, "append": {"acdcs": [{"name": "A"}]},
                            "replace": {"presented": "A"}})
    assert frag == {"events": [{"name": "e1", "y": 2}], "kels": [{"event": "e1"}],
                    "acdcs": [{"name": "A"}], "presented": "A"}
    assert FIX["f"]["events"] == [{"name": "e1", "x": 1}]  # the fixture is not changed


@pytest.mark.parametrize("case,words", [
    ({"base": "g"}, "fixture"),
    ({"base": "f", "patch": {"events": {"zz": {"x": 1}}}}, "zz"),
    ({"base": "f", "remove": {"events": ["zz"]}}, "zz"),
])
def test_compose_refusals(case, words):
    with pytest.raises(ScenarioError, match=words):
        ac.compose(FIX, {"key": "K", **case})


# -- the registry -------------------------------------------------------------------------------

def test_a_clause_from_another_spec_is_refused():
    reg = copy.deepcopy(REGISTRY)
    reg["clauses"]["said-verify"]["spec"] = "keri"
    with pytest.raises(ScenarioError, match="keri"):
        ac.resolve_registry(reg, TEXTS)


def test_an_inference_with_a_cesr_clause_is_refused():
    out = ac._Assertions(CLAUSES, INFERENCES, CONFLICTS)
    with pytest.raises(ScenarioError, match="cesr"):
        out.add("verdict", "said-verify", "liveness", note="n", expected="not-valid")


# -- the checks before a case is written ------------------------------------------------------

def test_a_scenario_whose_expectation_differs_from_the_procedure_is_refused():
    with pytest.raises(ScenarioError, match="decision procedure fails"):
        grade(STRUCTURE, "KS-03", expect=[])


def test_a_refusal_must_name_a_positive_pair():
    with pytest.raises(ScenarioError, match="positive pair"):
        grade(STRUCTURE, "KS-03", pair="KS-99")
    with pytest.raises(ScenarioError, match="not a positive pair"):
        grade(STRUCTURE, "KS-03", pairs={"KS-02": ("ACDC-0002", True)})
    with pytest.raises(ScenarioError, match="names no pair"):
        grade(STRUCTURE, "KS-01", pair="KS-02")


def test_a_refusal_carries_its_pair_and_derivations():
    [case] = grade(STRUCTURE, "KS-07", pairs={"KS-01": ("ACDC-0001", False)})
    assert case["description"].endswith("Its positive pair is KS-01 (ACDC-0001), which differs "
                                        "from it only in the defect.")
    [a] = case["assertions"]
    assert a["level"] == "MUST" and a["clause"]["quote"] == CLAUSES["schema-enforced"][1]["quote"]
    assert "step 1 required-field: SHOULD" in a["note"] and "step 2 schema-absent: MUST" in \
        a["note"]


def _with_others(monkeypatch, change):
    """Make the alternative readings see a changed result."""
    real = ac.Evaluation.__init__

    def init(self, t, bundle):
        real(self, t, bundle)
        self.others = [(name, change(copy.deepcopy(self.result))) for name, _ in self.others]
    monkeypatch.setattr(ac.Evaluation, "__init__", init)


def test_a_must_refusal_that_another_reading_accepts_is_refused(monkeypatch):
    def accept(r):
        r.presented.failures = []
        return r
    _with_others(monkeypatch, accept)
    with pytest.raises(ScenarioError, match="reading"):
        grade(STRUCTURE, "KS-03", pairs={"KS-02": ("ACDC-0002", False)})


def test_a_registry_head_that_depends_on_the_reading_is_refused(monkeypatch):
    def move(r):
        r.registry.n += 1
        return r
    _with_others(monkeypatch, move)
    with pytest.raises(ScenarioError, match="registry"):
        grade(REG, "KS-27")


def test_a_failing_edge_that_another_reading_passes_is_refused(monkeypatch):
    def pass_edges(r):
        for e in r.edges:
            e.failure = None
        return r
    _with_others(monkeypatch, pass_edges)
    with pytest.raises(ScenarioError, match="edge"):
        grade(EDGES, "KS-40")


def test_a_case_with_no_assertion_is_refused(monkeypatch):
    monkeypatch.setattr(ac, "_verdict", lambda *a: None)
    with pytest.raises(ScenarioError, match="no assertion"):
        grade(STRUCTURE, "KS-01")


def test_a_companion_must_be_named_when_needed_and_only_then():
    c = one(EDGES, "KS-40")
    del c["companion"]
    with pytest.raises(ScenarioError, match="companion"):
        ac.build_acdc_case("t", c, ac.build(T, EDGES["fixtures"], c),
                           {"KS-39": ("x", False)}, CLAUSES, INFERENCES, CONFLICTS)
    with pytest.raises(ScenarioError, match="nothing to split"):
        grade(STRUCTURE, "KS-01", companion={"id": "ACDC-9999", "key": "x", "title": "t",
                                             "description": "d"})


def test_a_split_case_puts_every_must_and_refusal_in_the_ungated_companion():
    main, comp = grade(EDGES, "KS-40")
    assert "acdc.edges" in main["targets"]["features"]
    assert "acdc.edges" not in comp["targets"]["features"]
    assert [a["check"] for a in main["assertions"]] == ["edge_reported"]
    assert [(a["check"], a["level"], a["expected"]) for a in comp["assertions"]] == [
        ("edge_valid", "MUST", False)]
    assert "Its positive pair is KS-39" in comp["description"]


def test_a_registry_whose_inception_fails_is_graded_by_the_failing_clause():
    [case] = grade(REG, "KS-35")
    reported = next(a for a in case["assertions"] if a["check"] == "registry_reported")
    assert reported["expected"] is False
    assert reported["clause"]["quote"] == CLAUSES["registry-issuer"][1]["quote"]


def test_a_direct_should_acceptance_needs_no_inference():
    [case] = grade(scenario("schema"), "KS-19")
    [a] = case["assertions"]
    assert a["level"] == "SHOULD" and "inferred_from" not in a


def test_an_acceptance_that_depends_on_a_reading_names_it():
    [case] = grade(scenario("disclosure"), "KS-48")
    assert case["assertions"][0]["inferred_from"] == INFERENCES["reading-aggregate"]


def test_an_expanded_acdc_is_accepted_as_liveness_alone():
    # Line 134 leaves one reading of the compact form's size field (A-B1), so accepting an
    # expanded ACDC depends on no open reading.
    [case] = grade(STRUCTURE, "KS-02")
    assert case["assertions"][0]["inferred_from"] == INFERENCES["liveness"]


def test_both_and_A_sentences_are_recorded_against_each_other():
    [case] = grade(STRUCTURE, "KS-06")
    [a] = case["assertions"]
    assert [c["quote"] for c in a["spec_conflicts"]] == [CONFLICTS["a-and-A-presence"]["quote"]]


def test_the_edge_schema_refusal_cites_the_validator_sentence():
    _, comp = grade(EDGES, "KS-42", pairs={"KS-42p": ("ACDC-0048", False)})
    [a] = comp["assertions"]
    assert a["clause"]["quote"].startswith("To clarify, the Validator")
    assert a["level"] == "MUST"


def test_an_unframeable_presented_acdc_grades_no_registry():
    c = one(REG, "KS-27")
    c["patch"] = {"acdcs": {"A1": {"protocol": "KERI"}}}
    c["expect"], c["pair"] = ["presented 1/protocol"], "KS-27"
    [case] = grade(REG, "KS-27", **{k: c[k] for k in ("patch", "expect", "pair")})
    assert [a["check"] for a in case["assertions"]] == ["verdict"]


def _ipex_lines():
    """The line span of the ACDC text's IPEX section, which declares itself non-normative."""
    heads = spec_source.headings(TEXTS["acdc"])
    start = next(h for h in heads if h.text.startswith("Issuance and Presentation Exchange"))
    end = next((h.line for h in heads if h.line > start.line and h.level <= start.level),
               len(TEXTS["acdc"].splitlines()) + 1)
    return range(start.line, end)


def test_no_clause_inference_or_conflict_quotes_the_non_normative_ipex_section():
    span = _ipex_lines()
    for kind in ("clauses", "inferences", "conflicts"):
        for key, record in REGISTRY[kind].items():
            if record.get("spec", "acdc") != "acdc":
                continue
            line = spec_source.find_quote(TEXTS["acdc"], record["quote"])
            assert line not in span, f"{kind} {key} quotes line {line}, in the IPEX section"


def test_a_direct_commitment_refusal_rests_on_key_state_by_inference():
    [case] = grade(scenario("commitment"), "KS-20")
    [a] = case["assertions"]
    assert (a["level"], a["expected"]) == ("SHOULD", "not-valid")
    assert a["clause"]["quote"] == CLAUSES["key-state"][1]["quote"]
    assert a["inferred_from"] == INFERENCES["commitment"]


def test_a_registry_commitment_refusal_rests_on_anchored_updates_by_inference():
    [case] = grade(REG, "KS-32")
    verdict = next(a for a in case["assertions"] if a["check"] == "verdict")
    assert verdict["clause"]["quote"] == CLAUSES["update-anchored"][1]["quote"]
    assert verdict["inferred_from"] == INFERENCES["commitment-registry"]
    assert "step 5 no-registry-commitment" in verdict["note"]


def test_another_protocol_is_a_producer_rule_and_a_misdeclared_size_a_parser_one():
    [protocol] = grade(STRUCTURE, "KS-10")[0]["assertions"]
    assert protocol["clause"]["quote"] == CLAUSES["version-protocol"][1]["quote"]
    assert "inferred_from" in protocol and "step 1 (protocol)" in protocol["note"]
    [size] = grade(STRUCTURE, "KS-09", pairs={"KS-02": ("ACDC-0002", False)})[0]["assertions"]
    assert (size["level"], size["expected"]) == ("SHOULD", "not-valid")
    assert size["clause"]["quote"] == CLAUSES["version-size"][1]["quote"]
    assert "inferred_from" not in size and "step 1 (unframeable)" in size["note"]


def test_a_refusal_only_recovery_can_make_requires_it_and_is_not_split():
    commitment = scenario("commitment")
    [case] = grade(commitment, "KS-25", pairs={"KS-25p": ("ACDC-0065", False)})
    assert "kel.recovery" in case["targets"]["features"]
    [a] = case["assertions"]
    assert (a["check"], a["level"], a["expected"]) == ("verdict", "SHOULD", "not-valid")
    [positive] = grade(commitment, "KS-25p")
    assert "kel.recovery" in positive["targets"]["features"]


def test_a_required_feature_never_gates_a_must():
    with pytest.raises(ScenarioError, match="requires"):
        grade(STRUCTURE, "KS-03", pairs={"KS-02": ("ACDC-0002", False)},
              requires=["kel.recovery"])


def test_only_a_known_feature_may_be_required():
    with pytest.raises(ScenarioError, match="requires"):
        grade(STRUCTURE, "KS-01", requires=["acdc.teleport"])


def test_found_names_an_unnamed_presented_acdc_by_its_role():
    result = am.Result(am.Node({"d": "Ex"}, [am.Failure(1, "said")]), {}, [])
    assert ac.found(result, {}) == ["presented 1/said"]


# -- regeneration -------------------------------------------------------------------------------


@pytest.fixture
def atree(tmp_path):
    (tmp_path / "scenarios" / "cesr").mkdir(parents=True)
    shutil.copy(ROOT / "scenarios" / "cesr" / "clauses.json", tmp_path / "scenarios" / "cesr")
    (tmp_path / "scenarios" / "acdc").mkdir()
    shutil.copy(ROOT / "scenarios" / "acdc" / "clauses.json", tmp_path / "scenarios" / "acdc")
    return tmp_path


def _write(tree, cases, profile="acdc-1.0", **extra):
    (tree / "scenarios" / "acdc" / "t.json").write_text(json.dumps(
        {"profile": profile, "fixtures": STRUCTURE["fixtures"], "cases": cases, **extra}))


def _ks(key, n):
    return {**one(STRUCTURE, key), "id": f"ACDC-{n:04d}"}


def test_generate_writes_acdc_cases_and_their_profile(atree):
    _write(atree, [_ks("KS-01", 2), {**_ks("KS-03", 3), "pair": "KS-01"}],
           id_gaps=[{"number": 1, "reason": "test"}])
    (atree / "scenarios" / "acdc" / "triage.json").write_text('{"about": "x", "entries": {}}')
    files = regenerate.generate(atree)
    assert json.loads(files["profiles/acdc-1.0.json"])["cases"] == ["ACDC-0002", "ACDC-0003"]


@pytest.mark.parametrize("cases,match", [
    ([{**_ks("KS-01", 1), "id": "ACDC-1"}], "not a case id"),
    ([_ks("KS-01", 1), {**_ks("KS-02", 2), "key": "KS-01"}], "used twice"),
    ([_ks("KS-01", 1), _ks("KS-02", 1)], "used twice"),
    ([_ks("KS-01", 2)], "undocumented gaps"),
    ([{**_ks("KS-01", 1), "patch": {"acdcs": {"A1": {"issuer": None}}}}], "KeyError"),
    ([{k: v for k, v in _ks("KS-01", 1).items() if k != "description"}], "KeyError"),
    ([{**_ks("KS-03", 1), "pair": "KS-99"}], "positive pair"),
])
def test_generate_refuses_a_bad_acdc_scenario(atree, cases, match):
    _write(atree, cases)
    with pytest.raises(ScenarioError, match=match):
        regenerate.generate(atree)


def test_generate_refuses_a_companion_id_that_is_not_an_acdc_id(atree):
    c = {**one(EDGES, "KS-40"), "id": "ACDC-0002"}
    c["companion"]["id"] = "KERI-0003"
    (atree / "scenarios" / "acdc" / "t.json").write_text(json.dumps(
        {"profile": "acdc-1.0", "fixtures": EDGES["fixtures"],
         "cases": [{**one(EDGES, "KS-39"), "id": "ACDC-0001"}, c]}))
    with pytest.raises(ScenarioError, match="not a case id"):
        regenerate.generate(atree)


def test_generate_refuses_another_profile_for_an_acdc_scenario(atree):
    _write(atree, [_ks("KS-01", 1)], profile="keri-1.0")
    with pytest.raises(ScenarioError, match="unknown ACDC profile"):
        regenerate.generate(atree)


def test_generate_refuses_an_acdc_clause_registry_that_misquotes(atree):
    path = atree / "scenarios" / "acdc" / "clauses.json"
    reg = json.loads(path.read_text())
    reg["clauses"]["field-order"]["quote"] = "There MUST be no such sentence."
    path.write_text(json.dumps(reg))
    _write(atree, [_ks("KS-01", 1)])
    with pytest.raises(ScenarioError, match="scenarios/acdc/clauses.json"):
        regenerate.generate(atree)
