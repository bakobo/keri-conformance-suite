"""The committed KERI cases are well-formed, cite the pinned KERI specification verbatim, follow the
design's grading rules, and are what their scenarios generate (test_cases_cesr runs
``scripts/regenerate --check`` over every layer).

The pinned specification text is read from its cache and fetched there if it is missing; without
it these tests skip, unless KCS_REQUIRE_SPEC=1 is set, when they fail instead.
"""

import json
import os
import pathlib
import sys

import pytest
from jsonschema import Draft202012Validator

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from generators.spec_tables import keri_events, keri_model, spec_source, tables

SCHEMA = Draft202012Validator(
    json.loads((ROOT / "schema" / "case.schema.json").read_text(encoding="utf-8")))
PROTOCOL = json.loads((ROOT / "schema" / "adapter-protocol.schema.json").read_text(encoding="utf-8"))
FEATURES = json.loads((ROOT / "profiles" / "features.json").read_text(encoding="utf-8"))["features"]
CASE_DIR = ROOT / "cases" / "keri"
CASES = {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in sorted(CASE_DIR.glob("*.json"))}
NORMATIVE, ESCROW = "keri-1.0", "keri-escrow"
GATED = {"keri.escrow", "kel.recovery"}


@pytest.fixture(scope="module")
def spec():
    try:
        return spec_source.load_spec(pin=spec_source.KERI)
    except spec_source.SpecUnavailable as e:
        if os.environ.get("KCS_REQUIRE_SPEC") == "1":
            raise
        return pytest.skip(f"the pinned KERI specification text is unavailable: {e}")


def _assertions():
    for cid, case in sorted(CASES.items()):
        for a in case["assertions"]:
            yield pytest.param(cid, a, id=f"{cid}-{a['id']}")


def _scenario_gaps() -> set[int]:
    gaps = set()
    for path in (ROOT / "scenarios" / "keri").glob("*.json"):
        gaps.update(g["number"] for g in json.loads(path.read_text(encoding="utf-8")).get("id_gaps", []))
    return gaps


def test_there_is_a_first_batch():
    assert len(CASES) >= 35


@pytest.mark.parametrize("cid", sorted(CASES))
def test_case_validates_against_the_case_schema_and_loads_through_the_runner(cid):
    from keri_conformance.cases import case_problem

    errors = sorted(SCHEMA.iter_errors(CASES[cid]), key=lambda e: list(e.path))
    assert not errors, [f"{list(e.path)}: {e.message}" for e in errors]
    assert case_problem(CASES[cid]) is None
    assert CASES[cid]["id"] == cid and CASES[cid]["operation"] == "keri.process"


def test_case_ids_are_contiguous_apart_from_documented_gaps():
    numbers = sorted(int(cid.split("-")[1]) for cid in CASES)
    assert numbers[0] == 1
    missing = set(range(1, numbers[-1] + 1)) - set(numbers)
    assert missing <= _scenario_gaps()


@pytest.mark.parametrize(("cid", "a"), list(_assertions()))
def test_assertion_quotes_the_pinned_keri_spec_verbatim(cid, a, spec):
    if a["level"] == "INTEROP":
        assert "clause" not in a and a["basis"]
        return
    clause = a["clause"]
    assert clause["spec"] == "keri" and clause["commit"] == spec_source.KERI.commit
    line = spec_source.find_quote(spec, clause["quote"])
    heading = spec_source.section_of_line(spec, line)
    assert clause["section"] == heading.text
    assert clause["url"] == spec_source.file_url(heading.anchor, spec_source.KERI)
    if "inferred_from" in a:
        assert a["level"] == "SHOULD" and "MUST" in clause["quote"]
    else:
        assert a["level"] in clause["quote"]
    for record in [*a.get("spec_conflicts", []), *([a["inferred_from"]] if "inferred_from" in a
                                                   else [])]:
        line = spec_source.find_quote(spec, record["quote"])
        assert record["line"] == line
        assert record["section"] == spec_source.section_of_line(spec, line).text


@pytest.mark.parametrize("cid", sorted(CASES))
def test_profile_levels_features_and_provenance_agree(cid):
    case = CASES[cid]
    levels = {a["level"] for a in case["assertions"]}
    features = set(case["targets"]["features"])
    assert features <= set(FEATURES)
    assert {"kel.basic", "keri.version-2.x", "crypto.ed25519"} <= features
    assert case["targets"]["wire"] == ["CESR-2.00", keri_events.WIRE]
    assert case["provenance"]["generator"]["name"] == "kcs-gen-keri"
    assert case["provenance"]["reference"] is None
    assert case["provenance"]["scenario"].startswith("scenarios/keri/")
    if case["profile"] == ESCROW:
        assert levels == {"INTEROP"} and "keri.escrow" in features
    else:
        assert case["profile"] == NORMATIVE and levels <= {"MUST", "SHOULD"}


@pytest.mark.parametrize("cid", sorted(CASES))
def test_no_must_disposition_hides_behind_a_feature_an_adapter_can_decline(cid):
    case = CASES[cid]
    if GATED & set(case["targets"]["features"]):
        assert not [a for a in case["assertions"]
                    if a["level"] == "MUST" and a["check"] in ("disposition", "trunk")]


@pytest.mark.parametrize("cid", sorted(CASES))
def test_assertions_name_delivered_messages_and_grade_by_the_design(cid):
    case = CASES[cid]
    count = len(case["input"]["messages"])
    for a in case["assertions"]:
        index = a.get("message", a.get("if_seen"))
        assert 0 <= index < count
        if a["check"] == "disposition" and a["level"] != "INTEROP":
            # Rejected only where a clause says drop, and only at the initial reading; pending
            # only for a threshold shortfall, at SHOULD; seen only at SHOULD (liveness).
            if a["expected"] == "rejected":
                assert a["phase"] == "initial" and a["level"] == "MUST"
                assert "drop" in a["clause"]["quote"] or "discarded" in a["clause"]["quote"]
            if a["expected"] == "pending":
                assert a["level"] == "SHOULD" and "SHOULD escrow" in a["clause"]["quote"]
            if a["expected"] == "seen":
                assert a["level"] == "SHOULD"
        if a["check"] == "trunk" and a["level"] != "INTEROP":
            assert a["level"] == "SHOULD"


@pytest.mark.parametrize("cid", sorted(CASES))
def test_key_state_assertions_match_the_adapter_protocol(cid):
    state = Draft202012Validator({"$defs": PROTOCOL["$defs"], "$ref": "#/$defs/key_state"})
    for a in CASES[cid]["assertions"]:
        if a["check"] == "key_state":
            assert not list(state.iter_errors(a["expected"]))


@pytest.mark.parametrize("cid", sorted(CASES))
def test_the_model_reads_the_committed_bytes_as_the_case_says(cid):
    """Re-run the model validator over the committed streams: what the case asserts must be what
    the escrowing model reads, so a case cannot drift from its own derivation."""
    case = CASES[cid]
    t = tables.load()
    streams = [bytes.fromhex(m["stream"]) for m in case["input"]["messages"]]
    model = keri_model.run(t, streams, "all")
    for a in case["assertions"]:
        if a["check"] == "disposition":
            got = (model.initial if a["phase"] == "initial" else model.outcome)[a["message"]]
            want = a["expected"]
            if want == "seen":
                assert got.state == "seen"
            elif want == "pending":
                assert got.state == "kept"
            else:
                assert got.state != "seen"
        elif a["check"] == "trunk":
            assert model.on_trunk(a["message"]) is a["expected"]
        elif a["check"] == "key_state":
            assert model.key_state(a["aid"]) == a["expected"]


@pytest.mark.parametrize("name", [NORMATIVE, ESCROW])
def test_profile_lists_exactly_its_cases(name):
    profile = json.loads((ROOT / "profiles" / f"{name}.json").read_text(encoding="utf-8"))
    assert profile["name"] == name and profile["about"]
    assert profile["cases"] == sorted(cid for cid, c in CASES.items() if c["profile"] == name)
    assert profile["normative"] is (name == NORMATIVE)
    if name == NORMATIVE:
        assert profile["spec"]["tag"] == "v1.0.1"
        assert profile["spec"]["commit"] == spec_source.KERI.commit


def test_every_escrow_case_has_its_safety_half_in_the_normative_profile():
    keys = {c["provenance"]["scenario"].split("#")[1]: c for c in CASES.values()}
    for key, case in keys.items():
        if case["profile"] == ESCROW:
            assert key.endswith("L") and key[:-1] in keys
            assert keys[key[:-1]]["input"] == case["input"]


def test_the_cached_keri_spec_is_the_pinned_text(spec):
    assert spec_source.sha256(spec) == spec_source.KERI.sha256
