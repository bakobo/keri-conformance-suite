"""The layered sedi-1 profile file: its source, its choices and the cases that exercise them, and
the freeze on a released version (generators/spec_tables/sedi_profile.py; docs/design.md, Targets
and profiles; this.i 47yreej2)."""

import copy
import json
import shutil

import pytest
from conftest import ROOT

from generators.spec_tables import regenerate, sedi_profile
from generators.spec_tables.errors import ScenarioError

SOURCE = json.loads((ROOT / "scenarios" / "sedi" / "profile.json").read_text(encoding="utf-8"))
OPERATIONS = {"cesr.parse", "keri.process", "exn.verify", "acdc.verify", "acdc.issue",
              "acdc.present"}
FEATURES = set(json.loads((ROOT / "profiles" / "features.json").read_text())["features"])
PROFILES = {"cesr-1.0", "keri-1.0", "acdc-1.0"}
ACDC = "4a543c549fd9811c23bf97b0daaf48400f4005c2"
PINS = {"suite": "0.0.1", "specs": {"acdc": {"repository": "r", "tag": "v1.0", "commit": ACDC}}}
SMALL = {**SOURCE, "choices": [c for c in SOURCE["choices"]
                               if c["id"] in ("tel-sequence", "revoked")]}


def build(source=SMALL, cases=(), pins=PINS):
    return sedi_profile.build_profile(source, list(cases), operations=OPERATIONS,
                                      features=FEATURES, profiles=PROFILES, pins=pins)


def verdict_case(case_id, expected, choices, **extra):
    return {"id": case_id, "profile": "sedi-1", "assertions": [
        {"id": "a1", "check": "verdict", "level": "INTEROP", "basis": "b",
         "expected": expected, "choices": list(choices), **extra}]}


FILLED = [verdict_case("ACDC-0901", "valid", ["tel-sequence", "revoked"]),
          verdict_case("ACDC-0902", "not-valid", ["tel-sequence"]),
          verdict_case("ACDC-0903", "not-valid", ["revoked"])]


def test_the_committed_source_builds_and_lists_every_unexercised_choice():
    doc, unfilled = build(SOURCE)
    assert doc["name"] == "sedi-1" and doc["status"] == "draft" and doc["normative"] is False
    assert doc["prerequisites"] == ["cesr-1.0", "keri-1.0", "acdc-1.0"]
    assert len(unfilled) == 2 * len(SOURCE["choices"])
    assert doc["pins"]["drafts"] == SOURCE["drafts"]
    assert all(c["cases"] == {"positive": [], "negative": []} for c in doc["choices"])


def test_cases_fill_the_choice_matrix_by_polarity():
    doc, unfilled = build(cases=FILLED)
    assert unfilled == []
    matrix = {c["id"]: c["cases"] for c in doc["choices"]}
    assert matrix["tel-sequence"] == {"positive": ["ACDC-0901"], "negative": ["ACDC-0902"]}
    assert matrix["revoked"] == {"positive": ["ACDC-0901"], "negative": ["ACDC-0903"]}
    assert doc["cases"] == ["ACDC-0901", "ACDC-0902", "ACDC-0903"]


def test_a_case_counts_once_per_side_however_many_assertions_name_the_choice():
    case = verdict_case("ACDC-0901", "valid", ["revoked"])
    case["assertions"].append({**case["assertions"][0], "id": "a2"})
    doc, _ = build(cases=[case])
    assert next(c for c in doc["choices"] if c["id"] == "revoked")["cases"]["positive"] == \
        ["ACDC-0901"]


def test_a_draft_may_leave_a_choice_unexercised_but_an_active_version_may_not():
    _doc, unfilled = build(cases=FILLED[:2])
    assert unfilled == ["revoked has no negative case"]
    with pytest.raises(ScenarioError, match="cannot be active.*revoked has no negative case"):
        build({**SMALL, "status": "active"}, FILLED[:2])
    doc, _ = build({**SMALL, "status": "active"}, FILLED)
    assert doc["status"] == "active"


@pytest.mark.parametrize(("assertion", "words"), [
    ({"level": "SHOULD", "clause": {}}, "rests on no choice"),
    ({"choices": []}, "rests on no choice"),
    ({"choices": ["no-such-choice"]}, "does not choose"),
    ({"check": "rejected"}, "has no polarity"),
    ({"basis": {"spec": "acdc", "commit": "1234567"}}, "does not pin"),
])
def test_every_assertion_rests_on_a_choice_the_profile_makes(assertion, words):
    case = verdict_case("ACDC-0901", "valid", ["revoked"])
    case["assertions"][0].update(assertion)
    with pytest.raises(ScenarioError, match=words):
        build(cases=[case])


@pytest.mark.parametrize("commit", [ACDC, ACDC[:7], SOURCE["drafts"]["acdc-main"]["commit"]])
def test_a_quoted_basis_must_be_at_a_pinned_commit(commit):
    case = verdict_case("ACDC-0901", "valid", ["revoked"],
                        basis={"text": "t", "spec": "acdc", "commit": commit})
    build(cases=[case])


def _mutated(path, value):
    source = copy.deepcopy(SMALL)
    target = source
    for key in path[:-1]:
        target = target[key]
    if value is KeyError:
        del target[path[-1]]
    else:
        target[path[-1]] = value
    return source


@pytest.mark.parametrize(("path", "value", "words"), [
    (("name",), "Sedi 1", "not a profile name"),
    (("version",), "", "version and basis"),
    (("basis",), " ", "version and basis"),
    (("status",), "released", "status must be"),
    (("prerequisites",), [], "prerequisites"),
    (("prerequisites",), ["acdc-9"], "prerequisites"),
    (("requires",), {"operations": []}, "requires must list"),
    (("requires", "features"), "x", "requires must list"),
    (("requires", "operations"), ["acdc.revoke"], "acdc.revoke"),
    (("requires", "features"), ["acdc.everything"], "acdc.everything"),
    (("drafts", "acdc-main", "commit"), "9d80942", "drafts"),
    (("drafts", "acdc-main", "why"), "", "drafts"),
    (("drafts",), [], "drafts"),
    (("maxima",), {"registry_events": 0}, "maxima"),
    (("maxima",), {"registry_events": True}, "maxima"),
    (("maxima",), [], "maxima"),
    (("choices",), [], "at least one choice"),
    (("choices", 0), "x", "not an object"),
    (("choices", 0, "id"), "Tel", "not lowercase"),
    (("choices", 1, "id"), "tel-sequence", "defined twice"),
    (("choices", 0, "colour"), "red", "unknown fields"),
    (("choices", 0, "reading"), "", "non-empty reading"),
    (("choices", 0, "overturn"), KeyError, "non-empty overturn"),
    (("choices", 0, "tick"), "57UD", "not a tick id"),
    (("choices", 0, "decided"), "x", "this.i decision"),
    (("choices", 0, "security"), False, "security only as true"),
    (("surplus",), 1, "exactly the fields"),
])
def test_a_malformed_source_is_refused(path, value, words):
    with pytest.raises(ScenarioError, match=words):
        build(_mutated(path, value))


def test_a_source_that_is_not_an_object_is_refused():
    with pytest.raises(ScenarioError, match="not an object"):
        build([])


# --- the freeze on a released version -----------------------------------------------------------

def test_the_frozen_digest_ignores_what_a_release_may_grow():
    doc, _ = build(cases=FILLED)
    bare, _ = build()
    assert sedi_profile.frozen_digest(doc) == sedi_profile.frozen_digest(bare)
    assert sedi_profile.frozen_digest({**doc, "about": "new prose"}) == \
        sedi_profile.frozen_digest(doc)
    changed = copy.deepcopy(doc)
    changed["choices"][0]["reading"] = "Another reading."
    assert sedi_profile.frozen_digest(changed) != sedi_profile.frozen_digest(doc)


def test_a_released_version_must_be_active_and_unchanged():
    doc, _ = build({**SMALL, "status": "active"}, FILLED)
    record = {"sedi-1": {"suite": "0.0.1", "digest": sedi_profile.frozen_digest(doc)}}
    sedi_profile.check_release(doc, record)
    sedi_profile.check_release(doc, {})
    sedi_profile.check_release(doc, [])
    with pytest.raises(ScenarioError, match="status must be active"):
        sedi_profile.check_release({**doc, "status": "draft"}, record)
    changed = copy.deepcopy(doc)
    changed["requires"]["features"].append("kel.delegation")
    with pytest.raises(ScenarioError, match="make a new version"):
        sedi_profile.check_release(changed, record)


# --- in the generator ------------------------------------------------------------------------------

@pytest.fixture
def tree(tmp_path):
    shutil.copytree(ROOT / "scenarios", tmp_path / "scenarios")
    (tmp_path / "profiles").mkdir()
    shutil.copy(ROOT / "profiles" / "features.json", tmp_path / "profiles")
    shutil.copy(ROOT / "pyproject.toml", tmp_path)
    return tmp_path


def test_the_generator_writes_the_profile_and_owns_its_file():
    files = regenerate.generate(ROOT)
    doc = json.loads(files["profiles/sedi-1.json"])
    assert doc["pins"]["suite"] == regenerate._suite_version(ROOT)
    assert {"cesr", "keri", "acdc"} == set(doc["pins"]["specs"])
    assert "profiles/sedi-1.json" in regenerate.committed(ROOT)
    assert "profiles/features.json" not in regenerate.committed(ROOT)


def test_without_a_source_there_is_no_layered_profile(tree):
    (tree / "scenarios" / "sedi" / "profile.json").unlink()
    assert regenerate.sedi(tree, {}) is None
    assert not any(p.startswith("profiles/sedi") for p in regenerate.generate(tree))


def test_a_released_version_keeps_the_suite_version_it_was_released_with(tree):
    sedi = tree / "scenarios" / "sedi"
    (sedi / "profile.json").write_text(json.dumps({**SMALL, "status": "active"}))
    files = {f"cases/acdc/{c['id']}.json": json.dumps(c).encode() for c in FILLED}
    doc, _ = regenerate.sedi(tree, files)
    assert doc["pins"]["suite"] == regenerate._suite_version(tree)
    released = {**doc, "pins": {**doc["pins"], "suite": "0.0.0"}}
    record = {"suite": "0.0.0", "digest": sedi_profile.frozen_digest(released)}
    (sedi / "released.json").write_text(json.dumps({"sedi-1": record}))
    doc, _ = regenerate.sedi(tree, files)
    assert doc["pins"]["suite"] == "0.0.0"
    (sedi / "released.json").write_text(json.dumps({"sedi-1": {**record, "digest": "0" * 64}}))
    with pytest.raises(ScenarioError, match="make a new version"):
        regenerate.sedi(tree, files)


def test_the_generator_hands_the_profile_only_its_own_cases(tree):
    case = verdict_case("ACDC-0901", "valid", ["revoked"])
    other = {**verdict_case("ACDC-0902", "valid", ["revoked"]), "profile": "acdc-1.0"}
    files = {"cases/acdc/ACDC-0901.json": json.dumps(case).encode(),
             "cases/acdc/ACDC-0902.json": json.dumps(other).encode(),
             "profiles/acdc-1.0.json": b"{}"}
    doc, _ = regenerate.sedi(tree, files)
    assert doc["cases"] == ["ACDC-0901"]


def test_the_script_lists_the_unexercised_choices(capsys):
    from generators.spec_tables import cli as script
    assert script.main(["--check"]) == 0
    out = capsys.readouterr().out
    assert "sedi-1 (draft):" in out and "revoked has no negative case" in out


def test_the_script_says_nothing_when_every_choice_is_exercised(monkeypatch, capsys):
    from generators.spec_tables import cli as script
    real = script.regenerate.sedi
    monkeypatch.setattr(script.regenerate, "sedi", lambda root, files: (real(root, files)[0], []))
    assert script.main(["--check"]) == 0
    assert "not yet exercised" not in capsys.readouterr().out
