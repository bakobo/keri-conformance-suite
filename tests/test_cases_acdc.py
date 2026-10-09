"""The committed ACDC cases are well-formed, cite the pinned specification texts verbatim, follow
the design's grading rules, and are what the model validator reads in their bytes
(test_cases_cesr runs ``scripts/regenerate --check`` over every layer).

The pinned specification texts are read from their cache and fetched there if missing; without
them these tests skip, unless KCS_REQUIRE_SPEC=1 is set, when they fail instead.
"""

import json
import os
import pathlib
import sys

import pytest
from jsonschema import Draft202012Validator

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from generators.spec_tables import acdc_cases, acdc_model, spec_source, tables

SCHEMA = Draft202012Validator(
    json.loads((ROOT / "schema" / "case.schema.json").read_text(encoding="utf-8")))
PROTOCOL = json.loads((ROOT / "schema" / "adapter-protocol.schema.json").read_text(encoding="utf-8"))
FEATURES = json.loads((ROOT / "profiles" / "features.json").read_text(encoding="utf-8"))["features"]
CASES = {p.stem: json.loads(p.read_text(encoding="utf-8"))
         for p in sorted((ROOT / "cases" / "acdc").glob("*.json"))}
GATED = {"acdc.edges", "acdc.registry.bup"}
PINS = {"acdc": spec_source.ACDC, "cesr": spec_source.cesr_pin()}


@pytest.fixture(scope="module")
def texts():
    try:
        return {label: spec_source.load_spec(pin=pin) for label, pin in PINS.items()}
    except spec_source.SpecUnavailable as e:
        if os.environ.get("KCS_REQUIRE_SPEC") == "1":
            raise
        return pytest.skip(f"a pinned specification text is unavailable: {e}")


def _assertions():
    for cid, case in sorted(CASES.items()):
        for a in case["assertions"]:
            yield pytest.param(cid, a, id=f"{cid}-{a['id']}")


def test_there_is_a_first_batch():
    assert len(CASES) >= 60


def test_case_ids_are_contiguous():
    numbers = sorted(int(cid.split("-")[1]) for cid in CASES)
    assert numbers == list(range(1, len(numbers) + 1))


@pytest.mark.parametrize("cid", sorted(CASES))
def test_case_validates_against_the_case_schema_and_loads_through_the_runner(cid):
    from keri_conformance.cases import case_problem

    errors = sorted(SCHEMA.iter_errors(CASES[cid]), key=lambda e: list(e.path))
    assert not errors, [f"{list(e.path)}: {e.message}" for e in errors]
    assert case_problem(CASES[cid]) is None
    assert CASES[cid]["id"] == cid and CASES[cid]["operation"] == "acdc.verify"


@pytest.mark.parametrize("cid", sorted(CASES))
def test_the_request_matches_the_adapter_protocol(cid):
    request = {"$defs": PROTOCOL["$defs"], "$ref": "#/$defs/request"}
    validator = Draft202012Validator(request)
    msg = {"id": 1, "op": "acdc.verify", **CASES[cid]["input"]}
    assert not list(validator.iter_errors(msg))


@pytest.mark.parametrize(("cid", "a"), list(_assertions()))
def test_assertion_quotes_the_pinned_spec_verbatim(cid, a, texts):
    clause = a["clause"]
    pin = PINS[clause["spec"]]
    text = texts[clause["spec"]]
    assert clause["commit"] == pin.commit
    line = spec_source.find_quote(text, clause["quote"])
    heading = spec_source.section_of_line(text, line)
    assert clause["section"] == heading.text
    assert clause["url"] == spec_source.file_url(heading.anchor, pin)
    if "inferred_from" in a:
        assert a["level"] == "SHOULD" and clause["spec"] == "acdc"
        assert "MUST" in clause["quote"]
    else:
        assert a["level"] in clause["quote"]
    for record in [*a.get("spec_conflicts", []), *([a["inferred_from"]] if "inferred_from" in a
                                                   else [])]:
        line = spec_source.find_quote(texts["acdc"], record["quote"])
        assert record["line"] == line
        assert record["section"] == spec_source.section_of_line(texts["acdc"], line).text


@pytest.mark.parametrize("cid", sorted(CASES))
def test_profile_features_wire_and_provenance(cid):
    case = CASES[cid]
    features = set(case["targets"]["features"])
    assert features <= set(FEATURES)
    assert set(acdc_cases.BASE_FEATURES) <= features
    assert case["targets"]["wire"][0] == "CESR-2.00" and case["targets"]["wire"][-1] == \
        acdc_cases.WIRE
    assert case["profile"] == "acdc-1.0" and case["status"] == "active"
    assert {a["level"] for a in case["assertions"]} <= {"MUST", "SHOULD"}
    assert case["provenance"]["generator"]["name"] == acdc_cases.GENERATOR_NAME
    assert case["provenance"]["reference"] is None
    assert case["provenance"]["scenario"].startswith("scenarios/acdc/")


@pytest.mark.parametrize("cid", sorted(CASES))
def test_no_must_and_no_refusal_hides_behind_a_feature_an_adapter_can_decline(cid):
    case = CASES[cid]
    if GATED & set(case["targets"]["features"]):
        for a in case["assertions"]:
            assert a["level"] != "MUST"
            assert a.get("expected") not in ("not-valid", False)


@pytest.mark.parametrize("cid", sorted(CASES))
def test_every_assertion_records_its_derivation(cid):
    for a in CASES[cid]["assertions"]:
        assert a["note"].startswith(("Decided at step", "Decision procedure step"))


@pytest.mark.parametrize("cid", sorted(CASES))
def test_valid_is_never_a_must_and_a_refusal_names_its_pair(cid):
    case = CASES[cid]
    for a in case["assertions"]:
        if a.get("expected") in ("valid", True) or a["check"] == "edge_reported":
            assert a["level"] == "SHOULD"
    refusal = any(a.get("expected") in ("not-valid", False) for a in case["assertions"]) or \
        any(a["check"] == "registry_state" and a["level"] == "MUST" for a in case["assertions"])
    if refusal:
        assert "Its positive pair is" in case["description"]


@pytest.mark.parametrize("cid", sorted(CASES))
def test_registry_state_matches_the_adapter_protocol(cid):
    state = Draft202012Validator({"$defs": PROTOCOL["$defs"], "$ref": "#/$defs/registry_state"})
    for a in CASES[cid]["assertions"]:
        if a["check"] == "registry_state":
            assert not list(state.iter_errors(a["expected"]))


@pytest.mark.parametrize("cid", sorted(CASES))
def test_the_model_reads_the_committed_bytes_as_the_case_says(cid, texts):
    """Re-run the model validator over the committed bundle: every assertion must be what the
    model reads, so a case cannot drift from its own derivation."""
    case = CASES[cid]
    result = acdc_model.evaluate(tables.load(texts["cesr"]), case["input"])
    edges = {(e.near, e.path): e for e in result.edges}
    for a in case["assertions"]:
        if a["check"] == "verdict":
            assert bool(result.presented.failures) is (a["expected"] == "not-valid")
            if a["expected"] == "valid":
                assert not result.failing()
        elif a["check"] == "registry_reported":
            assert (result.registry is not None) is a["expected"]
        elif a["check"] == "registry_state":
            assert result.registry.facts() == a["expected"]
        elif a["check"] == "edge_reported":
            assert (a["near"], a["path"]) in edges
        else:
            assert (edges[(a["near"], a["path"])].failure is None) is a["expected"]
    assert case["dag"]["root"] == result.presented.said or result.presented.said is None


def test_profile_lists_exactly_the_cases():
    profile = json.loads((ROOT / "profiles" / "acdc-1.0.json").read_text(encoding="utf-8"))
    assert profile["name"] == "acdc-1.0" and profile["about"] and profile["normative"] is True
    assert profile["cases"] == sorted(CASES)
    assert profile["spec"]["tag"] == "v1.0" and profile["spec"]["commit"] == \
        spec_source.ACDC.commit


def test_the_cached_acdc_spec_is_the_pinned_text(texts):
    assert spec_source.sha256(texts["acdc"]) == spec_source.ACDC.sha256
