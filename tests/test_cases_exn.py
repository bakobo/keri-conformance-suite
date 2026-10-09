"""The committed exchange-message cases (KERI cases run through ``exn.verify``) are well-formed,
cite the pinned KERI specification verbatim, grade by the exchange-message decision procedure of
docs/design.md (IPEX), and say what the model validator reads from their committed bytes
(test_cases_cesr runs ``scripts/regenerate --check`` over every layer).

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

from generators.spec_tables import exn_build, keri_events, keri_model, spec_source, tables

SCHEMA = Draft202012Validator(
    json.loads((ROOT / "schema" / "case.schema.json").read_text(encoding="utf-8")))
FEATURES = json.loads((ROOT / "profiles" / "features.json").read_text(encoding="utf-8"))["features"]
CASES = {cid: c for cid, c in
         ((p.stem, json.loads(p.read_text(encoding="utf-8")))
          for p in sorted((ROOT / "cases" / "keri").glob("*.json")))
         if c["operation"] == "exn.verify"}
# Refusals a clause that binds a validator says drop or forbids: graded MUST (design, IPEX,
# steps 1 and 2). Everything else is an inferred SHOULD.
MUST_CLAUSES = {"drop-unsigned", "nonkey-threshold", "act-as-verifier", "exn-fields",
                "xip-fields"}
REGISTRY = json.loads((ROOT / "scenarios" / "keri" / "clauses.json").read_text())["clauses"]
KEY_OF = {c["quote"]: k for k, c in REGISTRY.items()}


@pytest.fixture(scope="module")
def spec():
    try:
        return spec_source.load_spec(pin=spec_source.KERI)
    except spec_source.SpecUnavailable as e:
        if os.environ.get("KCS_REQUIRE_SPEC") == "1":
            raise
        return pytest.skip(f"the pinned KERI specification text is unavailable: {e}")


def test_there_is_an_exchange_message_batch():
    assert len(CASES) >= 10


@pytest.mark.parametrize("cid", sorted(CASES))
def test_case_validates_against_the_case_schema_and_loads_through_the_runner(cid):
    from keri_conformance.cases import case_problem

    errors = sorted(SCHEMA.iter_errors(CASES[cid]), key=lambda e: list(e.path))
    assert not errors, [f"{list(e.path)}: {e.message}" for e in errors]
    assert case_problem(CASES[cid]) is None


@pytest.mark.parametrize("cid", sorted(CASES))
def test_profile_features_and_provenance(cid):
    case = CASES[cid]
    assert case["profile"] == "keri-1.0"
    assert set(case["targets"]["features"]) <= set(FEATURES)
    assert set(exn_build.FEATURES_BASE) <= set(case["targets"]["features"])
    assert case["targets"]["wire"] == ["CESR-2.00", keri_events.WIRE]
    assert case["provenance"]["scenario"].startswith("scenarios/keri/exchange.json#")
    assert case["provenance"]["reference"] is None
    for stream in [*case["input"]["kels"], *case["input"]["messages"]]:
        assert stream["stream"].startswith(keri_events.GENUS_CODE.encode().hex())


@pytest.mark.parametrize("cid", sorted(CASES))
def test_assertions_grade_by_the_design(cid, spec):
    case = CASES[cid]
    graded = sorted(a["message"] for a in case["assertions"])
    assert graded == list(range(len(case["input"]["messages"])))
    for a in case["assertions"]:
        assert a["check"] == "exn_verdict"
        clause = a["clause"]
        assert clause["spec"] == "keri" and clause["commit"] == spec_source.KERI.commit
        line = spec_source.find_quote(spec, clause["quote"])
        assert clause["section"] == spec_source.section_of_line(spec, line).text
        assert clause["url"] == spec_source.file_url(
            spec_source.section_of_line(spec, line).anchor, spec_source.KERI)
        key = KEY_OF[clause["quote"]]
        if a["expected"] == "accepted" or key not in MUST_CLAUSES:
            assert a["level"] == "SHOULD" and "MUST" in clause["quote"]
            record = a["inferred_from"]
            line = spec_source.find_quote(spec, record["quote"])
            assert record["line"] == line
            assert record["section"] == spec_source.section_of_line(spec, line).text
        else:
            assert a["level"] == "MUST" and a["expected"] == "rejected"
            assert "MUST" in clause["quote"] and "inferred_from" not in a


@pytest.mark.parametrize("cid", sorted(CASES))
def test_the_model_reads_the_committed_bytes_as_the_case_says(cid):
    case = CASES[cid]
    model = exn_build.run(tables.load(),
                          [bytes.fromhex(k["stream"]) for k in case["input"]["kels"]],
                          [bytes.fromhex(m["stream"]) for m in case["input"]["messages"]])
    for a in case["assertions"]:
        i = a["message"]
        assert model.initial[i].state == model.outcome[i].state == a["expected"]


@pytest.mark.parametrize("cid", sorted(CASES))
def test_a_disputed_case_names_a_keri_clause_and_where_it_was_raised(cid):
    case = CASES[cid]
    assert (case["status"] == "disputed") is ("dispute" in case)
    if "dispute" in case:
        assert case["dispute"]["clauses"] and case["dispute"]["raised_at"]
        assert all(c["spec"] == "keri" for c in case["dispute"]["clauses"])


def test_every_must_refusal_has_an_active_positive_pair():
    """A validator that accepts nothing passes every MUST, so the batch carries an active case in
    which a signed message should be accepted, and a SHOULD failure there exposes it."""
    active_accepts = [cid for cid, c in CASES.items() if c["status"] == "active"
                      and any(a["expected"] == "accepted" for a in c["assertions"])]
    assert active_accepts


def _readings(case):
    """The model's run over a case's bytes, and for each message whether at least one sender
    signature verifies, and the sender's signing threshold."""
    model = exn_build.run(tables.load(),
                          [bytes.fromhex(k["stream"]) for k in case["input"]["kels"]],
                          [bytes.fromhex(m["stream"]) for m in case["input"]["messages"]])
    out = []
    for p in model.parsed:
        kel = model.kel.kels[p.body["i"]]
        valid, kt = 0, None
        for g in p.groups:
            if g.pre != p.body["i"]:
                continue
            est = kel.seen[g.said].body
            kt = est["kt"]
            valid += len({s.index for s in g.sigs if s.index < len(est["k"]) and keri_model.verify(
                keri_model.qb64_raw(est["k"][s.index]), p.raw, s.raw)})
        out.append((valid, kt))
    return model, out


def test_exchange_cases_use_a_route_and_payload_no_ipex_handler_polices():
    """The clauses these cases cite are KERI's, about any exchange message, so their messages use
    a route that no implementation registers a handler for and carry no ACDC; a deployment that
    polices IPEX routes would otherwise refuse the positive pairs for IPEX reasons (review
    SKP-F1, docs/design.md, IPEX)."""
    for cid, case in CASES.items():
        model, _ = _readings(case)
        for p in model.parsed:
            assert not p.body["r"].startswith("/ipex/"), cid
            assert "acdc" not in p.body["a"], cid
