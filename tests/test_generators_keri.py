"""The KERI generator: the event builder, the model validator that applies the decision procedure,
the grading that turns the model's readings into assertions, and the regeneration of KERI cases.

The committed cases exercise the paths a real scenario takes; these tests pin each refusal and each
guard, because a generator that quietly accepts a scenario it cannot grade soundly would publish a
wrong expectation."""

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
    b64,
    build,
    keri_build,
    keri_events,
    keri_model,
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
A = "6/accepted"
ICP = {"name": "icp", "aid": "A", "t": "icp", "keys": ["a0"], "next": ["a1"]}


def ev(name, t, aid="A", **kw):
    return {"name": name, "aid": aid, "t": t, **kw}


def msg(event, sigs, expect=None, **kw):
    return {"event": event, "sigs": sigs, "expect": expect, **kw}


def case(events, messages, **kw):
    return {"id": "KERI-9999", "key": "KS-test", "title": "t", "description": "d",
            "profile": kw.pop("profile", "keri-1.0"), "events": events, "messages": messages,
            **kw}


def make(c, normative=True):
    return keri_build.build_keri_case(T, "scenarios/keri/test.json", c, CLAUSES, INFERENCES,
                                      CONFLICTS, normative)


def streams(events, deliveries):
    eb = keri_events.EventBuilder(T, events)
    return [eb.message(d).stream for d in deliveries]


def tags(events, deliveries, policy="all"):
    m = keri_model.run(T, streams(events, deliveries), policy)
    return [[a.tag, b.tag] for a, b in zip(m.initial, m.outcome, strict=True)]


# --- The event builder ----------------------------------------------------------------------


@pytest.mark.parametrize("events,deliveries,match", [
    ([ICP, ICP], [msg("icp", ["a0"])], "defined twice"),
    ([ev("icpB", "icp", aid="B", keys=["b0"]), ev("ixn1", "ixn", prior="icpB")],
     [msg("ixn1", ["a0"])], "has no inception event"),
    ([ev("ixn1", "ixn"), ICP], [msg("ixn1", ["a0"])], "has no prior event"),
    ([ICP], [msg("nope", ["a0"])], "No event is named"),
    ([ICP, ev("ixn1", "ixn", a=[{"event": "ixn1"}])], [msg("ixn1", ["a0"])], "depends on itself"),
    ([ev("icp", "xyz")], [msg("icp", ["a0"])], "unknown type"),
    ([{**ICP, "kt": 1}], [msg("icp", ["a0"])], "must be a string or a list"),
    ([ICP], [msg("icp", ["b0"])], "not one of its signing keys"),
    ([ICP], [msg("icp", ["a0"], wigs=["w1"])], "not one of its witnesses"),
])
def test_the_builder_refuses_a_scenario_it_cannot_build(events, deliveries, match):
    with pytest.raises(ScenarioError, match=match):
        streams(events, deliveries)


def test_explicit_signature_and_witness_indexes_are_used_as_given():
    events = [{**ICP, "wits": ["w1"], "bt": "1"}]
    s = streams(events, [msg("icp", [{"key": "a0", "index": 0}],
                             wigs=[{"key": "w1", "index": 0}])])
    assert tags(events, [msg("icp", [{"key": "a0", "index": 0}],
                             wigs=[{"key": "w1", "index": 0}])]) == [[A, A]]
    assert s[0].startswith(keri_events.GENUS_CODE.encode())


def test_a_signature_index_beyond_the_keys_does_not_verify():
    events = [ICP]
    deliveries = [msg("icp", [{"key": "a0", "index": 3}])]
    assert tags(events, deliveries) == [["2/unverified", "2/unverified"]]


def test_bodies_follow_the_specification_field_order_and_are_self_addressing():
    eb = keri_events.EventBuilder(T, [ICP, ev("rot1", "rot", keys=["a1"], next=["a2"])])
    icp, rot = eb.event("icp"), eb.event("rot1")
    assert tuple(icp.body) == keri_events.FIELDS["icp"]
    assert tuple(rot.body) == keri_events.FIELDS["rot"]
    assert icp.said == icp.pre and icp.raw.startswith(b'{"v":"KERICAACAAJSON')
    assert b64.b64_to_int(icp.body["v"][14:18]) == len(icp.raw)
    assert rot.body["p"] == icp.said and rot.body["n"] == [keri_events.next_digest(T, "a2")]


# --- The model validator --------------------------------------------------------------------


def test_the_model_refuses_an_unknown_keep_policy():
    with pytest.raises(ScenarioError, match="Unknown keep policy"):
        keri_model.Model(T, "some")


@pytest.mark.parametrize("threshold,size,match", [
    ("0", 1, "not modelled"),
    (["1/2", "1/2"], 3, "weights over 3 keys"),
])
def test_thresholds_the_model_does_not_grade_are_refused(threshold, size, match):
    with pytest.raises(ScenarioError, match=match):
        keri_model.satisfies(threshold, {0}, size)


def test_weighted_clauses_must_each_reach_one():
    assert keri_model.satisfies([["1/2", "1/2"], ["1"]], {0, 1, 2}, 3)
    assert not keri_model.satisfies([["1/2", "1/2"], ["1"]], {0, 2}, 3)
    assert keri_model.satisfies("2", {0, 2, 7}, 3) and not keri_model.satisfies("2", {0, 7}, 3)


def test_an_unparseable_stream_is_an_intrinsic_failure():
    m = keri_model.run(T, [b"not a stream"], "all")
    assert m.outcome[0].tag == "1/unparseable" and m.outcome[0].state == "dropped"


def test_a_stream_of_two_messages_is_refused():
    one, two = streams([ICP, ev("ixn1", "ixn")], [msg("icp", ["a0"]), msg("ixn1", ["a0"])])
    m = keri_model.run(T, [one + two[len(keri_events.GENUS_CODE):]], "all")
    assert m.outcome[0].tag == "1/unparseable"


def test_fields_out_of_order_are_an_intrinsic_failure():
    body = {"v": "", "t": "icp", "i": "x", "d": "y", "s": "0"}
    raw = keri_events.sized(body)
    m = keri_model.run(T, [keri_events.GENUS_CODE.encode() + raw], "all")
    assert m.outcome[0].tag == "1/fields"


def test_sequence_numbers_are_checked_in_the_body():
    assert tags([{**ICP, "s": 1}], [msg("icp", ["a0"])]) == [["1/inception-sn"] * 2]
    events = [ICP, ev("ixn1", "ixn", s=0)]
    assert tags(events, [msg("icp", ["a0"]), msg("ixn1", ["a0"])])[1] == ["1/sn"] * 2


def test_a_rotation_must_meet_its_own_signing_threshold_as_well_as_the_prior_next():
    events = [{**ICP, "next": ["a1", "b1"], "nt": "1"},
              ev("rot1", "rot", keys=["a1", "b1"], kt="2", next=["a2", "b2"], nt="1")]
    got = tags(events, [msg("icp", ["a0"]), msg("rot1", ["a1"])])
    assert got[1] == ["4/signing-threshold"] * 2


def test_a_receipt_couple_from_a_witness_is_not_modelled():
    events = [{**ICP, "wits": ["w1"], "bt": "1"}]
    with pytest.raises(ScenarioError, match="G21"):
        tags(events, [msg("icp", ["a0"]), {"receipt": "icp", "couples": ["w1"]}])


def test_witness_signatures_that_move_with_a_witness_rotation_are_not_modelled():
    events = [{**ICP, "wits": ["w1", "w2"], "bt": "1"},
              ev("rot1", "rot", keys=["a1"], next=["a2"], br=["w1"], ba=["w3"], bt="1")]
    with pytest.raises(ScenarioError, match="G12"):
        tags(events, [msg("icp", ["a0"], wigs=["w1"]), msg("rot1", ["a1"], wigs=["w2"])])


def test_superseding_a_delegated_rotation_is_not_modelled():
    events = [ev("Dicp", "icp", aid="D", keys=["d0"], next=["d1"]),
              ev("Dixn1", "ixn", aid="D", a=[{"event": "Edip"}, {"event": "Edrt1"},
                                            {"event": "Edrt1b"}]),
              ev("Edip", "dip", aid="E", delegator="D", keys=["e0"], next=["e1"]),
              ev("Edrt1", "drt", aid="E", keys=["e1"], next=["e2"]),
              ev("Edrt1b", "drt", aid="E", prior="Edip", keys=["e1"], next=["x2"])]
    with pytest.raises(ScenarioError, match="rules B, C"):
        tags(events, [msg("Dicp", ["d0"]), msg("Dixn1", ["d0"]), msg("Edip", ["e0"]),
                      msg("Edrt1", ["e1"]), msg("Edrt1b", ["e1"])])


def test_a_rotation_may_not_supersede_a_rotation():
    events = [ICP, ev("rot1", "rot", keys=["a1"], next=["a2"]),
              ev("rot1b", "rot", prior="icp", keys=["a1"], next=["x2"])]
    got = tags(events, [msg("icp", ["a0"]), msg("rot1", ["a1"]), msg("rot1b", ["a1"])])
    assert got[2] == ["5/supersede-refused"] * 2


def test_a_receipt_before_its_event_is_dropped_or_refused_by_policy():
    events = [{**ICP, "wits": ["w1"], "bt": "1"}]
    deliveries = [{"receipt": "icp", "wigs": ["w1"]}, msg("icp", ["a0"])]
    with pytest.raises(ScenarioError, match="G4"):
        tags(events, deliveries, "all")
    assert tags(events, deliveries, "none")[0] == ["4/receipt"] * 2


# --- Grading ---------------------------------------------------------------------------------


def test_a_refusal_with_no_clause_is_refused():
    with pytest.raises(ScenarioError, match="No clause grades"):
        keri_build._not_seen_clause("mystery", "icp")


def test_a_scenario_whose_expectation_differs_from_the_procedure_is_refused():
    with pytest.raises(ScenarioError, match="the decision procedure gives"):
        make(case([ICP], [msg("icp", ["a0"], ["4/signing-threshold", A])]))


def test_a_liveness_case_must_declare_itself_when_it_needs_a_declinable_feature():
    m3 = {**ICP, "keys": ["a0", "b0", "c0"], "kt": "2", "next": ["a1", "b1", "c1"], "nt": "2"}
    deliveries = [msg("icp", ["a0"], ["4/signing-threshold", "6/already-seen"]),
                  msg("icp", ["c0"], [A, A])]
    with pytest.raises(ScenarioError, match="liveness_only"):
        make(case([m3], deliveries))
    built = make(case([m3], deliveries, liveness_only=True))
    assert "keri.escrow" in built["targets"]["features"]
    assert all(a["level"] != "MUST" or a["check"] == "key_state" for a in built["assertions"])
    assert [a["id"] for a in built["assertions"]] == [
        f"a{n}" for n in range(1, len(built["assertions"]) + 1)]


def test_an_escrow_case_with_nothing_escrow_dependent_is_refused():
    with pytest.raises(ScenarioError, match="no assertion survives"):
        make(case([ICP], [msg("icp", ["a0"], [A, A])], profile="keri-escrow",
                  key_state={"A": False}), normative=False)


def test_a_disputed_case_carries_its_dispute():
    built = make(case([ICP], [msg("icp", ["a0"], [A, A])], status="disputed",
                      dispute={"clauses": ["act-as-verifier"], "summary": "s", "raised_at": "r"}))
    assert built["status"] == "disputed"
    assert built["dispute"]["clauses"][0]["spec"] == "keri"


LATE = [ICP, ev("ixn1", "ixn"), ev("ixn2", "ixn"), ev("ixn3", "ixn")]
LATE_MSGS = [msg("icp", ["a0"], [A, A]), msg("ixn2", ["a0"], ["4/out-of-order", A]),
             msg("ixn1", ["a0"], [A, A]), msg("ixn3", ["a0"], [A, A])]


def test_a_reading_that_needs_unspecified_escrow_is_not_graded_in_a_normative_case():
    built = make(case(LATE, copy.deepcopy(LATE_MSGS)))
    about = {(a.get("message"), a.get("phase"), a["check"]) for a in built["assertions"]}
    assert (3, "initial", "disposition") not in about  # ixn3 is seen only if ixn2 was kept
    assert (1, "initial", "disposition") in about


def test_the_escrow_profile_grades_what_depends_on_escrow():
    built = make(case(LATE, copy.deepcopy(LATE_MSGS), profile="keri-escrow"), normative=False)
    graded = {(a.get("message"), a.get("phase"), a["expected"] if a["check"] != "key_state"
               else "ks") for a in built["assertions"]}
    assert (1, "initial", "pending") in graded and (3, "final", "seen") in graded
    assert (3, "initial", "pending") not in graded  # ixn3 was never held: it was seen on arrival
    assert all(a["level"] == "INTEROP" for a in built["assertions"])
    gap = make(case([ICP, ev("ixn1", "ixn"), ev("ixn2", "ixn")],
                    [msg("icp", ["a0"], [A, A]),
                     msg("ixn2", ["a0"], ["4/out-of-order", "4/out-of-order"])],
                    profile="keri-escrow"), normative=False)
    assert [(a.get("message"), a.get("expected")) for a in gap["assertions"]
            if a["check"] == "disposition"] == [(1, "pending")]


def test_key_state_can_be_left_out_for_an_identifier():
    built = make(case([ICP], [msg("icp", ["a0"], [A, A])], key_state={"A": False}))
    assert not any(a["check"] == "key_state" for a in built["assertions"])


def _patched(monkeypatch, policy, mutate):
    real = keri_model.run

    def run(t, s, p):
        m = real(t, s, p)
        if p == policy:
            mutate(m)
        return m

    monkeypatch.setattr(keri_model, "run", run)


SEEN = keri_model.Outcome("seen", 6, "accepted")
KEPT = keri_model.Outcome("kept", 4, "signing-threshold")


@pytest.mark.parametrize("phase,match", [("initial", "initial refusal"),
                                         ("final", "final refusal")])
def test_a_refusal_that_another_keep_policy_would_not_make_is_refused(monkeypatch, phase, match):
    def mutate(m):
        (m.initial if phase == "initial" else m.outcome)[0] = SEEN

    _patched(monkeypatch, "none", mutate)
    with pytest.raises(ScenarioError, match=match):
        make(case([ICP], [msg("icp", [], ["2/unsigned", "2/unsigned"])]))


def test_a_drop_that_another_keep_policy_would_not_make_is_refused(monkeypatch):
    _patched(monkeypatch, "thresholds", lambda m: m.initial.__setitem__(0, KEPT))
    with pytest.raises(ScenarioError, match="dropped under every policy"):
        make(case([ICP], [msg("icp", [], ["2/unsigned", "2/unsigned"])]))


def test_a_key_state_that_depends_on_the_keep_policy_is_refused(monkeypatch):
    def mutate(m):
        m.key_state = lambda pre: {"sn": 99}

    _patched(monkeypatch, "none", mutate)
    with pytest.raises(ScenarioError, match="key state depends"):
        make(case([ICP], [msg("icp", ["a0"], [A, A])]))


# --- Regeneration of KERI cases --------------------------------------------------------------


@pytest.fixture
def ktree(tmp_path):
    (tmp_path / "scenarios" / "cesr").mkdir(parents=True)
    shutil.copy(ROOT / "scenarios" / "cesr" / "clauses.json", tmp_path / "scenarios" / "cesr")
    (tmp_path / "scenarios" / "keri").mkdir()
    shutil.copy(ROOT / "scenarios" / "keri" / "clauses.json", tmp_path / "scenarios" / "keri")
    return tmp_path


def _kscenario(tree, cases, profile="keri-1.0", **extra):
    for c in cases:
        c.pop("profile", None)
    (tree / "scenarios" / "keri" / "t.json").write_text(
        json.dumps({"profile": profile, "cases": cases, **extra}))


def _one(n=1, **kw):
    c = case([ICP], [msg("icp", ["a0"], [A, A])], **kw)
    c["id"] = f"KERI-{n:04d}"
    return c


def test_generate_writes_keri_cases_and_their_profile(ktree):
    _kscenario(ktree, [_one(2)], id_gaps=[{"number": 1, "reason": "test"}])
    files = regenerate.generate(ktree)
    assert "cases/keri/KERI-0002.json" in files
    assert json.loads(files["profiles/keri-1.0.json"])["cases"] == ["KERI-0002"]


@pytest.mark.parametrize("cases,match", [
    ([{**_one(), "id": "KERI-1"}], "not a case id"),
    ([_one(), _one()], "used twice"),
    ([{k: v for k, v in _one().items() if k != "events"}], "KeyError"),
    ([_one(3)], "undocumented gaps"),
])
def test_generate_refuses_a_bad_keri_scenario(ktree, cases, match):
    _kscenario(ktree, cases)
    with pytest.raises(ScenarioError, match=match):
        regenerate.generate(ktree)


def test_generate_refuses_a_non_keri_profile_for_a_keri_scenario(ktree):
    _kscenario(ktree, [_one()], profile="cesr-1.0")
    with pytest.raises(ScenarioError, match="unknown KERI profile"):
        regenerate.generate(ktree)


def test_generate_refuses_a_keri_clause_registry_that_misquotes(ktree):
    path = ktree / "scenarios" / "keri" / "clauses.json"
    registry = json.loads(path.read_text())
    registry["clauses"]["one-kel"]["quote"] = "There MUST be no such sentence."
    path.write_text(json.dumps(registry))
    with pytest.raises(ScenarioError, match="scenarios/keri/clauses.json"):
        regenerate.generate(ktree)
