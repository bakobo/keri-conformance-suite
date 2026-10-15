"""The KERI generator's 1.x wire, for the keripy-1x-interop profile: KERI 1.0 bodies with keripy
1.x's field sets and version string, bare CESR 1.00 attachment groups and no genus/version code,
read by the same model validator and graded INTEROP by the same decision procedure (docs/design.md,
KERI; this.i "KERI 1.x KELs are graded for interoperability, by the decision procedure")."""

import copy
import json
import os
import pathlib
import shutil
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from generators.spec_tables import (
    build,
    decoding,
    keri_build,
    keri_events,
    keri_model,
    keripy1x,
    regenerate,
    spec_source,
    tables,
)
from generators.spec_tables.errors import ScenarioError

try:
    CESR_TEXT = spec_source.load_spec()
    KERI_TEXT = spec_source.load_spec(pin=spec_source.KERI)
except spec_source.SpecUnavailable as e:
    if os.environ.get("KCS_REQUIRE_SPEC") == "1":
        raise
    pytest.skip(f"a pinned specification text is unavailable: {e}", allow_module_level=True)

T = tables.load(CESR_TEXT)
REGISTRY = json.loads((ROOT / "scenarios" / "keri" / "clauses.json").read_text())
CLAUSES = build.resolve_clauses(REGISTRY["clauses"], KERI_TEXT, spec_source.KERI)
INFERENCES = build.resolve_records(REGISTRY["inferences"], KERI_TEXT, "inference")
CONFLICTS = build.resolve_records(REGISTRY["conflicts"], KERI_TEXT, "why")
V1 = keri_events.V1
A = "6/accepted"
ICP = {"name": "icp", "aid": "A", "t": "icp", "keys": ["a0"], "next": ["a1"]}
PROFILE = "keripy-1x-interop"


def ev(name, t, aid="A", **kw):
    return {"name": name, "aid": aid, "t": t, **kw}


def msg(event, sigs, expect=None, **kw):
    return {"event": event, "sigs": sigs, "expect": expect, **kw}


def case(events, messages, **kw):
    return {"id": "KERI-9999", "key": "K1X-test", "title": "t", "description": "d",
            "profile": PROFILE, "events": events, "messages": messages, **kw}


def make_all(c):
    return keri_build.build_keri_case(T, "scenarios/keri/test.json", c, CLAUSES, INFERENCES,
                                      CONFLICTS, False, keripy_1x=True)


def make(c):
    return make_all(c)[0]


def streams(events, deliveries):
    eb = keri_events.EventBuilder(T, events, wire=V1)
    return [eb.message(d).stream for d in deliveries]


def tags(events, deliveries, policy="all"):
    m = keri_model.run(T, streams(events, deliveries), policy)
    return [[a.tag, b.tag] for a, b in zip(m.initial, m.outcome, strict=True)]


DELEGATION = [ev("Dicp", "icp", aid="D", keys=["d0"], next=["d1"]),
              ev("Dixn1", "ixn", aid="D", a=[{"event": "Edip"}]),
              ev("Edip", "dip", aid="E", delegator="D", keys=["e0"], next=["e1"]),
              ev("Dixn2", "ixn", aid="D", a=[{"event": "Edrt1"}]),
              ev("Edrt1", "drt", aid="E", keys=["e1"], next=["e2"])]


# --- The builder -----------------------------------------------------------------------------


def test_bodies_have_keripy_1x_field_sets_and_version_string():
    eb = keri_events.EventBuilder(T, [ICP, ev("ixn1", "ixn"),
                                      ev("rot1", "rot", keys=["a1"], next=["a2"]),
                                      *DELEGATION], wire=V1)
    for name in ("icp", "ixn1", "rot1", "Edip", "Edrt1"):
        e = eb.event(name)
        assert tuple(e.body) == V1.fields[e.ilk]
        assert e.raw.startswith(b'{"v":"KERI10JSON') and e.body["v"].endswith("_")
        assert int(e.body["v"][10:16], 16) == len(e.raw)
    # keripy 1.x's rotations carry no configuration traits, where 2.00's do.
    assert "c" not in eb.event("rot1").body and "c" not in eb.event("Edrt1").body
    assert "c" in keri_events.FIELDS["rot"]
    assert eb.event("icp").said == eb.event("icp").pre


def test_streams_carry_bare_cesr_100_groups_counted_in_items_and_no_genus_code():
    events = [{**ICP, "wits": ["w1", "w2"], "bt": "1"}, *DELEGATION]
    one, rct, dip = streams(events, [
        msg("icp", ["a0"], wigs=["w1", "w2"]),
        {"receipt": "icp", "couples": ["x1"]},
        msg("Edip", ["e0"], source_seal="Dixn1")])
    assert one.startswith(b'{"v":"KERI10JSON')
    items = decoding.Parser(T, keripy1x.TABLE).parse(one)
    counters = [(it["code"], it["size"]) for it in items if it["kind"] == "counter"]
    assert counters == [("-A", 1), ("-B", 2)]
    items = decoding.Parser(T, keripy1x.TABLE).parse(rct)
    assert [(it["code"], it["size"]) for it in items if it["kind"] == "counter"] == [("-C", 1)]
    items = decoding.Parser(T, keripy1x.TABLE).parse(dip)
    assert [(it["code"], it["size"]) for it in items if it["kind"] == "counter"] == [
        ("-A", 1), ("-G", 1)]


def test_a_rotation_built_on_the_1x_wire_cannot_carry_configuration_traits():
    with pytest.raises(ScenarioError, match="no c field"):
        streams([ICP, ev("rot1", "rot", keys=["a1"], next=["a2"], c=["EO"])],
                [msg("rot1", ["a1"])])


# --- The model -------------------------------------------------------------------------------


def test_the_model_reads_a_1x_kel_as_it_reads_a_2x_one():
    events = [ICP, ev("ixn1", "ixn"), ev("rot1", "rot", keys=["a1"], next=["a2"]),
              ev("ixn2", "ixn")]
    got = tags(events, [msg("icp", ["a0"]), msg("ixn1", ["a0"]), msg("rot1", ["a1"]),
                        msg("ixn2", ["a1"])])
    assert got == [[A, A]] * 4


def test_the_model_reads_witness_receipts_and_delegation_on_the_1x_wire():
    events = [{**ICP, "wits": ["w1"], "bt": "1"}, *DELEGATION]
    got = tags(events, [msg("icp", ["a0"]), {"receipt": "icp", "wigs": ["w1"]},
                        msg("Dicp", ["d0"]), msg("Dixn1", ["d0"]),
                        msg("Edip", ["e0"], source_seal="Dixn1")])
    assert got[0] == ["4/witness-threshold", A]
    assert got[1] == ["6/receipt", "6/receipt"]
    assert got[4] == [A, A]


def test_a_2x_field_set_under_a_1x_version_string_is_an_intrinsic_failure():
    events = [ICP, ev("rot1", "rot", keys=["a1"], next=["a2"],
                      tamper={"fields": {"add": {"c": []}}})]
    assert tags(events, [msg("icp", ["a0"]), msg("rot1", ["a1"])])[1] == ["1/fields"] * 2


def test_a_1x_body_without_a_genus_code_is_not_read_as_2x():
    one = streams([ICP], [msg("icp", ["a0"])])[0]
    assert keri_model.parse(T, one).error is None
    two = keri_events.EventBuilder(T, [ICP]).message(msg("icp", ["a0"])).stream
    assert keri_model.parse(T, two.removeprefix(keri_events.GENUS_CODE.encode())).error


# --- Grading ---------------------------------------------------------------------------------


def test_every_assertion_is_interop_with_a_basis_quoting_the_step_s_sentence():
    built = make(case([ICP, ev("rot1", "rot", keys=["x1"], next=["a2"])],
                      [msg("icp", ["a0"], [A, A]),
                       msg("rot1", ["x1"], ["4/pre-rotation", "4/pre-rotation"])]))
    assert built["profile"] == PROFILE
    assert built["targets"]["wire"] == ["CESR-1.00", "KERI10JSON"]
    features = set(built["targets"]["features"])
    assert {"cesr.genus-1.00", "keri.version-1.x", "kel.basic", "crypto.ed25519"} <= features
    assert not {"cesr.genus-2.00", "keri.version-2.x"} & features
    assert {a["level"] for a in built["assertions"]} == {"INTEROP"}
    for a in built["assertions"]:
        assert "clause" not in a and "inferred_from" not in a
        assert a["basis"]["spec"] == "keri" and "keripy 1.x" in a["basis"]["text"]
        spec_source.find_quote(KERI_TEXT, a["basis"]["quote"])
    refused = [a for a in built["assertions"] if a.get("message") == 1]
    assert {a["expected"] for a in refused} == {"not-seen"}
    assert "would grade the same reading MUST" in refused[0]["basis"]["text"]
    seen = next(a for a in built["assertions"] if a.get("expected") == "seen")
    assert "would grade the same reading SHOULD, inferred" in seen["basis"]["text"]


LATE = [ICP, ev("ixn1", "ixn"), ev("ixn2", "ixn")]
LATE_MSGS = [msg("icp", ["a0"], [A, A]), msg("ixn2", ["a0"], ["4/out-of-order", A]),
             msg("ixn1", ["a0"], [A, A])]
COMPANION = {"id": "KERI-9998", "key": "K1X-test-s", "title": "s", "description": "s"}


def test_escrow_readings_are_graded_and_gated_with_the_safety_half_in_a_companion():
    with pytest.raises(ScenarioError, match="must name a companion"):
        make(case(LATE, copy.deepcopy(LATE_MSGS)))
    gated, companion = make_all(case(LATE, copy.deepcopy(LATE_MSGS), companion=COMPANION))
    assert "keri.escrow" in gated["targets"]["features"]
    graded = {(a.get("message"), a.get("phase"), a.get("expected")) for a in gated["assertions"]
              if a["check"] == "disposition"}
    assert (1, "initial", "pending") in graded and (1, "final", "seen") in graded
    escrow = [a for a in gated["assertions"] if a.get("message") == 1]
    assert all(isinstance(a["basis"], str) and "keripy 1.x" in a["basis"] for a in escrow)
    assert companion["profile"] == PROFILE and companion["input"] == gated["input"]
    assert "keri.escrow" not in companion["targets"]["features"]
    assert {a["level"] for a in companion["assertions"]} == {"INTEROP"}
    assert (1, "initial", "not-seen") in {(a["message"], a["phase"], a["expected"])
                                          for a in companion["assertions"]
                                          if a["check"] == "disposition"}



# --- Regeneration ----------------------------------------------------------------------------


@pytest.fixture
def ktree(tmp_path):
    for layer in ("cesr", "keri"):
        (tmp_path / "scenarios" / layer).mkdir(parents=True)
        shutil.copy(ROOT / "scenarios" / layer / "clauses.json", tmp_path / "scenarios" / layer)
    return tmp_path


def _kscenario(tree, cases, **extra):
    (tree / "scenarios" / "keri" / "t.json").write_text(
        json.dumps({"profile": PROFILE, "cases": cases, **extra}))


def _one():
    c = case([ICP], [msg("icp", ["a0"], [A, A])])
    c.pop("profile")
    c["id"] = "KERI-0001"
    return c


def test_generate_builds_keri_scenarios_of_the_profile_on_the_1x_wire(ktree):
    _kscenario(ktree, [_one()])
    files = regenerate.generate(ktree)
    built = json.loads(files["cases/keri/KERI-0001.json"])
    assert built["targets"]["wire"] == ["CESR-1.00", "KERI10JSON"]
    assert json.loads(files["profiles/keripy-1x-interop.json"])["cases"] == ["KERI-0001"]


def test_generate_refuses_an_exchange_scenario_in_the_profile(ktree):
    _kscenario(ktree, [_one()], operation="exn.verify")
    with pytest.raises(ScenarioError, match="only keri.process cases"):
        regenerate.generate(ktree)
