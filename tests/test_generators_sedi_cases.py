"""sedi-1's verifier cases: scenarios graded by the sedi-1 model, never by a hand-written
expectation, each resting on the choices it names and checked against what the model finds."""

import json
import os
import pathlib
import shutil

import pytest
from sedi_world import cred, single, world

from generators.spec_tables import regenerate, sedi_cases, spec_source, tables
from generators.spec_tables.errors import ScenarioError
from keri_conformance import cases

ROOT = pathlib.Path(__file__).resolve().parent.parent

try:
    CESR_TEXT = spec_source.load_spec()
except spec_source.SpecUnavailable as e:
    if os.environ.get("KCS_REQUIRE_SPEC") == "1":
        raise
    pytest.skip(f"a pinned specification text is unavailable: {e}", allow_module_level=True)

T = tables.load(CESR_TEXT)
READINGS = {c["id"]: c["reading"] for c in
            json.loads((ROOT / "scenarios/sedi/profile.json").read_text())["choices"]}


def scenario():
    revoked = world({"A": cred("I", states=("issued", "revoked"))}, "A")
    return {
        "profile": "sedi-1",
        "fixtures": {"issued": world({"A": cred("I")}, "A"), "revoked": revoked,
                     "chain": world(single(), "N")},
        "cases": [
            {"id": "ACDC-0901", "key": "SV-01", "title": "Issued", "base": "issued",
             "description": "An issued credential.", "choices": ["valid-is-interop"],
             "triage": "None: an acceptance.", "expect": []},
            {"id": "ACDC-0902", "key": "SV-02", "title": "Revoked", "base": "revoked",
             "description": "A revoked credential.", "choices": ["revoked"],
             "triage": "Accepting it accepts a revoked credential.", "pair": "SV-01",
             "expect": ["A invalid/revoked"]},
            {"id": "ACDC-0903", "key": "SV-03", "title": "Unknown operator", "base": "chain",
             "description": "An unknown operator.", "choices": ["unknown-operator"],
             "triage": "None.", "pair": "SV-04",
             "patch": {"acdcs": {"N": {"e": {"d": "", "le": {"d": "", "n": {"acdc": "F"},
                                                              "o": "XYZ"}}}}},
             "expect": ["N:e.le incomplete/operator-unknown"]},
            {"id": "ACDC-0904", "key": "SV-04", "title": "Chain", "base": "chain",
             "description": "A chain.", "choices": ["operator-list"], "triage": "None.",
             "expect": []},
        ],
    }


@pytest.fixture
def tree(tmp_path):
    shutil.copytree(ROOT / "scenarios", tmp_path / "scenarios")
    # Only the test's own scenario: the committed sedi cases would share its keys and ids.
    for path in (tmp_path / "scenarios/sedi").glob("*.json"):
        if path.name != "profile.json":
            path.unlink()
    (tmp_path / "profiles").mkdir()
    shutil.copy(ROOT / "profiles" / "features.json", tmp_path / "profiles")
    shutil.copy(ROOT / "pyproject.toml", tmp_path)
    return tmp_path


def write(tree, data):
    (tree / "scenarios/sedi/verify-test.json").write_text(json.dumps(data))


def test_cases_are_graded_by_the_model_and_fill_the_choice_matrix(tree):
    write(tree, scenario())
    files = regenerate.generate(tree)
    made = {p: json.loads(d) for p, d in files.items() if p.startswith("cases/sedi/")}
    assert sorted(made) == [f"cases/sedi/ACDC-090{n}.json" for n in range(1, 5)]
    for case in made.values():
        assert cases.case_problem(case) is None, case["id"]
    verdicts = {c["id"]: c["assertions"][0]["expected"] for c in made.values()}
    assert verdicts == {"ACDC-0901": "valid", "ACDC-0902": "invalid", "ACDC-0903": "incomplete",
                        "ACDC-0904": "valid"}
    revoked = made["cases/sedi/ACDC-0902.json"]
    a = revoked["assertions"][0]
    assert a["level"] == "INTEROP" and a["choices"] == ["revoked"]
    assert a["basis"] == f"sedi-1 revoked: {READINGS['revoked']}"
    assert "invalid (revoked)" in a["note"] and "SV-01 (ACDC-0901)" in revoked["description"]
    assert "acdc.registry.bup" in revoked["targets"]["features"]
    assert "acdc.edges" in made["cases/sedi/ACDC-0904.json"]["targets"]["features"]
    assert "nothing" in made["cases/sedi/ACDC-0901.json"]["assertions"][0]["note"]
    profile = json.loads(files["profiles/sedi-1.json"])
    exercised = {c["id"]: c["cases"] for c in profile["choices"]}
    assert exercised["revoked"]["negative"] == ["ACDC-0902"]
    assert exercised["valid-is-interop"]["positive"] == ["ACDC-0901"]
    assert "ACDC-0903" in profile["cases"]
    regenerate.write(tree, files)
    assert "cases/sedi/ACDC-0902.json" in regenerate.committed(tree)


def mutate(change):
    data = scenario()
    change(data)
    return data


@pytest.mark.parametrize("change,words", [
    (lambda d: d["cases"][1].update(expect=[]), "sedi-1 model finds"),
    (lambda d: d["cases"][1].pop("pair"), "positive pair"),
    (lambda d: d["cases"][1].update(pair="SV-03"), "not a positive pair"),
    (lambda d: d["cases"][0].update(pair="SV-04"), "names no pair"),
    (lambda d: d["cases"][0].update(choices=["no-such"]), "does not choose"),
    (lambda d: d["cases"][0].pop("triage"), "needs 'triage'"),
    (lambda d: d["cases"][0].update(extra=1), "unknown fields"),
    (lambda d: d["cases"][0].update(id="X-1"), "ACDC-NNNN"),
    (lambda d: d["cases"][1].update(key="SV-01"), "used twice"),
    (lambda d: d["cases"][1].update(id="ACDC-0001"), "used twice"),
    (lambda d: d.update(profile="sedi-9"), "unknown sedi profile"),
    (lambda d: d["cases"][0].update(base="nope"), "fixture"),
    (lambda d: d["cases"][0].update(choices=[{"x": 1}]), "TypeError"),
    (lambda d: d["cases"][0].update(expect=7), "ACDC-0901: TypeError"),
])
def test_a_malformed_scenario_is_refused(tree, change, words):
    write(tree, mutate(change))
    with pytest.raises(ScenarioError, match=words):
        regenerate._generate_sedi(tree, {"cases/acdc/ACDC-0001.json": b""}, T)


def test_without_a_profile_source_there_are_no_sedi_cases(tree):
    write(tree, scenario())
    (tree / "scenarios/sedi/profile.json").unlink()
    files = {}
    regenerate._generate_sedi(tree, files, T)
    assert files == {}


def test_found_names_nodes_and_edge_paths():
    result = sedi_cases.sm.Result("invalid", [sedi_cases.sm.Finding("invalid", "E1.e.x", "r"),
                                              sedi_cases.sm.Finding("invalid", "E2", "s")])
    assert sedi_cases.found(result, {"E1": "N"}) == ["E2 invalid/s", "N:e.x invalid/r"]
