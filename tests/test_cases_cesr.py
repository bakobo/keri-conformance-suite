"""The committed CESR cases are well-formed, cite the pinned specification verbatim, and are
exactly what their scenarios generate.

These tests read committed files and the pinned specification text from its cache. Tests that need
the text fetch it into the cache if it is missing, and skip with the reason when they cannot,
unless KCS_REQUIRE_SPEC=1 is set, when they fail instead.
"""

import json
import os
import pathlib
import re
import subprocess
import sys

import pytest
from jsonschema import Draft202012Validator

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from generators.spec_tables import spec_source

SCHEMA = json.loads((ROOT / "schema" / "case.schema.json").read_text(encoding="utf-8"))
VALIDATOR = Draft202012Validator(SCHEMA)
FEATURES = json.loads((ROOT / "profiles" / "features.json").read_text(encoding="utf-8"))["features"]
CASE_DIR = ROOT / "cases" / "cesr"
CASE_FILES = sorted(CASE_DIR.glob("*.json"))
CASES = {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in CASE_FILES}
HEX = re.compile(r"^([0-9a-f]{2})*$")
NORMATIVE = "cesr-1.0"
INTEROP = "keripy-1x-interop"
STRICT = "cesr-strict"


@pytest.fixture(scope="module")
def spec():
    try:
        return spec_source.load_spec()
    except spec_source.SpecUnavailable as e:
        if os.environ.get("KCS_REQUIRE_SPEC") == "1":
            raise
        return pytest.skip(f"the pinned CESR specification text is unavailable: {e}")


def _scenario_gaps() -> set[int]:
    gaps = set()
    for path in (ROOT / "scenarios" / "cesr").glob("*.json"):
        gaps.update(g["number"] for g in json.loads(path.read_text(encoding="utf-8")).get("id_gaps", []))
    return gaps


def _assertions():
    for cid, case in sorted(CASES.items()):
        for a in case["assertions"]:
            yield pytest.param(cid, a, id=f"{cid}-{a['id']}")


def test_there_are_cases():
    assert len(CASES) >= 30


@pytest.mark.parametrize("cid", sorted(CASES))
def test_case_validates_against_the_case_schema(cid):
    errors = sorted(VALIDATOR.iter_errors(CASES[cid]), key=lambda e: list(e.path))
    assert not errors, [f"{list(e.path)}: {e.message}" for e in errors]


@pytest.mark.parametrize("cid", sorted(CASES))
def test_case_id_matches_its_file_name(cid):
    assert CASES[cid]["id"] == cid


def test_case_ids_are_contiguous_apart_from_documented_gaps():
    numbers = sorted(int(cid.split("-")[1]) for cid in CASES)
    assert numbers[0] == 1
    missing = set(range(1, numbers[-1] + 1)) - set(numbers)
    assert missing <= _scenario_gaps()


@pytest.mark.parametrize(("cid", "a"), list(_assertions()))
def test_normative_assertion_quotes_the_pinned_spec_verbatim(cid, a, spec):
    if a["level"] == "INTEROP":
        assert "clause" not in a and a["basis"]
        return
    clause = a["clause"]
    assert clause["spec"] == "cesr"
    assert clause["commit"] == spec_source.SPEC_COMMIT
    line = spec_source.find_quote(spec, clause["quote"])
    heading = spec_source.section_of_line(spec, line)
    assert clause["section"] == heading.text
    assert clause["url"] == spec_source.file_url(heading.anchor)
    if "inferred_from" in a:
        # A consumer obligation inferred from a producer-side MUST is graded SHOULD.
        assert a["level"] == "SHOULD" and "MUST" in clause["quote"]
        assert a["inferred_from"]["quote"] == clause["quote"]
    else:
        assert a["level"] in clause["quote"]
    records = [*a.get("spec_conflicts", [])]
    if "inferred_from" in a:
        records.append(a["inferred_from"])
    for record in records:
        line = spec_source.find_quote(spec, record["quote"])
        assert record["line"] == line
        assert record["section"] == spec_source.section_of_line(spec, line).text


def test_the_cached_spec_is_the_pinned_text(spec):
    assert spec_source.sha256(spec) == spec_source.SPEC_SHA256


@pytest.mark.parametrize("cid", sorted(CASES))
def test_case_profile_level_and_provenance_agree(cid):
    case = CASES[cid]
    levels = {a["level"] for a in case["assertions"]}
    if case["profile"] == NORMATIVE:
        assert levels <= {"MUST", "SHOULD", "MAY"}
        assert case["provenance"]["reference"] is None
    elif case["profile"] == STRICT:
        assert levels == {"INTEROP"}
        assert case["provenance"]["reference"] is None
    else:
        assert case["profile"] == INTEROP
        assert levels == {"INTEROP"}
        assert case["provenance"]["reference"]["implementation"] == "keripy"
    assert case["provenance"]["generator"]["name"] == "kcs-gen-spec-tables"


@pytest.mark.parametrize("cid", sorted(CASES))
def test_case_features_are_in_the_vocabulary(cid):
    for feature in CASES[cid]["targets"]["features"]:
        assert feature in FEATURES, feature


@pytest.mark.parametrize("cid", sorted(CASES))
def test_encoded_expectations_are_hex(cid):
    for a in CASES[cid]["assertions"]:
        if a["check"] == "encoded":
            assert HEX.match(a["expected"]) and a["expected"]


@pytest.mark.parametrize("cid", sorted(CASES))
def test_disputed_cases_carry_a_dispute(cid):
    case = CASES[cid]
    assert (case["status"] == "disputed") == ("dispute" in case)


@pytest.mark.parametrize("name", [NORMATIVE, INTEROP, STRICT])
def test_profile_lists_exactly_its_cases(name):
    profile = json.loads((ROOT / "profiles" / f"{name}.json").read_text(encoding="utf-8"))
    assert profile["name"] == name and profile["about"]
    assert profile["cases"] == sorted(cid for cid, c in CASES.items() if c["profile"] == name)


def test_normative_profile_cites_the_pinned_spec():
    profile = json.loads((ROOT / "profiles" / f"{NORMATIVE}.json").read_text(encoding="utf-8"))
    assert profile["normative"] is True
    assert profile["spec"]["tag"] == "v1.0"
    assert profile["spec"]["commit"] == spec_source.SPEC_COMMIT


@pytest.mark.parametrize("name", [INTEROP, STRICT])
def test_non_normative_profiles_say_so(name):
    profile = json.loads((ROOT / "profiles" / f"{name}.json").read_text(encoding="utf-8"))
    assert profile["normative"] is False


def test_founding_case_counts_quadlets_not_items():
    """The case the suite exists for: a signature group whose size in quadlets differs from its
    number of signatures, followed by another group an item-counting parser would misframe."""
    case = CASES["CESR-0025"]
    items = case["assertions"][0]["expected"]
    k = next(n for n, it in enumerate(items) if it.get("code") == "-K")
    group = items[k]
    inside = [it for it in items[k + 1:] if it["end"] <= group["group_end"]]
    assert group["size"] == 66 and len(inside) == 3
    assert group["group_end"] == group["end"] + 4 * group["size"]
    assert items[k + 4]["code"] == "-L" and items[k + 4]["start"] == group["group_end"]
    assert items[-1]["end"] == len(bytes.fromhex(case["input"]["stream"]))


@pytest.mark.parametrize("cid", sorted(CASES))
def test_decoded_cases_carry_valid_keri_bodies_first(cid):
    """Positive streams are what a parser must accept: a genus code or a message first, never a
    bare group."""
    for a in CASES[cid]["assertions"]:
        if a["check"] == "decoded":
            assert a["expected"][0]["kind"] in ("genus", "message")
            assert any(it["kind"] == "message" for it in a["expected"])


def test_every_genus_item_has_a_two_digit_minor():
    for case in CASES.values():
        for a in case["assertions"]:
            for it in a.get("expected", []) if a["check"] == "decoded" else []:
                if it["kind"] == "genus":
                    assert re.match(r"^\d+\.\d{2,}$", it["version"]) and "size" not in it


def test_regenerate_check_passes(spec):
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "regenerate"), "--check"],
        capture_output=True, text=True, cwd=ROOT, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


PROTOCOL = json.loads((ROOT / "schema" / "adapter-protocol.schema.json").read_text(encoding="utf-8"))


DECODED = Draft202012Validator({"$defs": PROTOCOL["$defs"], "$ref": "#/$defs/result_decoded"})


@pytest.mark.parametrize("cid", sorted(CASES))
def test_decoded_expectations_are_valid_adapter_results(cid):
    """An expected item list must be something a conforming adapter could return."""
    for a in CASES[cid]["assertions"]:
        if a["check"] == "decoded":
            errors = list(DECODED.iter_errors({"items": a["expected"]}))
            assert not errors, [e.message for e in errors]


@pytest.mark.parametrize("cid", sorted(CASES))
def test_case_loads_through_the_runner(cid):
    """The runner's own hand-written case checks accept every committed case, as the JSON schema
    does; a case the runner refused would be a runner fault, never a scored case."""
    from keri_conformance.cases import case_problem

    assert case_problem(CASES[cid]) is None


def test_the_runner_loads_the_whole_cases_directory():
    from keri_conformance.cases import load_cases

    assert [c["id"] for c in load_cases(ROOT / "cases")] == sorted(CASES)


@pytest.mark.parametrize("cid", sorted(CASES))
def test_every_expected_counter_states_where_its_group_ends(cid):
    for a in CASES[cid]["assertions"]:
        for item in a.get("expected", []) if a["check"] == "decoded" else []:
            if item["kind"] == "counter":
                assert item["group_end"] >= item["end"] > item["start"]
            if item["kind"] == "genus":
                assert "group_end" not in item


def test_policy_only_keripy_disagreements_are_disputed():
    """Spec-internal conflicts do not make a case disputed (they are recorded in spec_conflicts);
    only a contradiction between keripy and a cited clause does."""
    disputed = sorted(cid for cid, c in CASES.items() if c["status"] == "disputed")
    assert disputed == ["CESR-0022", "CESR-0031"]


@pytest.mark.parametrize(("cid", "a"), list(_assertions()))
def test_no_temporary_policy_notes_remain(cid, a):
    note = a.get("note", "")
    assert not note.startswith(("spec-conflict", "inferred consumer obligation"))


def test_case_schema_accepts_and_checks_the_policy_fields():
    case = json.loads((CASE_DIR / "CESR-0038.json").read_text(encoding="utf-8"))
    assert not list(VALIDATOR.iter_errors(case))
    must = json.loads(json.dumps(case))
    must["assertions"][0]["level"] = "MUST"
    assert list(VALIDATOR.iter_errors(must)), "inferred_from requires SHOULD"
    bad = json.loads(json.dumps(case))
    del bad["assertions"][0]["inferred_from"]["line"]
    assert list(VALIDATOR.iter_errors(bad))
    conflict = json.loads((CASE_DIR / "CESR-0025.json").read_text(encoding="utf-8"))
    conflict["assertions"][0]["spec_conflicts"][0]["extra"] = 1
    assert list(VALIDATOR.iter_errors(conflict))
