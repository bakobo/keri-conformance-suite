"""The exchange-message generator: the builder of `xip` and `exn` messages and their signature
groups, the model validator that applies the exchange-message decision procedure of
docs/design.md (IPEX), the grading that turns its readings into `exn_verdict` assertions, and the
regeneration of exchange-message cases as KERI cases.

The committed cases exercise the paths a real scenario takes; these tests pin each refusal and
each guard, because a generator that quietly grades a scenario it does not model would publish a
wrong expectation."""

import ast
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
    encoding,
    exn_build,
    keri_events,
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
OK = "4/accepted"

EVENTS = [
    {"name": "I-icp", "aid": "I", "t": "icp", "keys": ["i0"], "next": ["i1"]},
    {"name": "H-icp", "aid": "H", "t": "icp", "keys": ["h0"], "next": ["h1"]},
    {"name": "X-icp", "aid": "X", "t": "icp", "keys": ["x0"], "next": ["x1"]},
]
KELS = [{"event": "I-icp", "sigs": ["i0"], "source": "issuer"},
        {"event": "H-icp", "sigs": ["h0"], "source": "holder"},
        {"event": "X-icp", "sigs": ["x0"], "source": "other"}]
XIP = {"name": "xip", "t": "xip", "sender": "I", "receiver": "H", "nonce": "offer",
       "r": "/ipex/offer", "q": {}, "a": {}}
GRANT = {"name": "grant", "t": "exn", "sender": "I", "receiver": "H", "x": {"said": "xip"},
         "p": {"said": "xip"}, "r": "/ipex/grant", "q": {}, "a": {"acdc": {"nothing": "A1"}}}
LONE = {**GRANT, "name": "lone", "x": "", "p": ""}
BY_I = [{"aid": "I", "keys": ["i0"]}]


def deliver(name, expect, sigs=BY_I, **kw):
    return {"exchange": name, "sigs": sigs, "expect": [expect, expect], **kw}


def case(exchanges, messages, events=EVENTS, kels=KELS, **kw):
    return {"id": "KERI-9999", "key": "XS-test", "title": "t", "description": "d",
            "profile": kw.pop("profile", "keri-1.0"), "events": events, "kels": kels,
            "exchanges": exchanges, "messages": messages, **kw}


def make(c, normative=True):
    return exn_build.build_exn_case(T, "scenarios/keri/test.json", c, CLAUSES, INFERENCES,
                                    CONFLICTS, normative)


def built(c):
    """The case's KEL streams and message streams, as the builder makes them."""
    xb = exn_build.ExchangeBuilder(T, c["events"], c["exchanges"])
    return ([xb.kel_message(k).stream for k in c["kels"]],
            [xb.message(m).stream for m in c["messages"]])


def tags(c):
    kels, streams = built(c)
    m = exn_build.run(T, kels, streams)
    return [[a.tag, b.tag] for a, b in zip(m.initial, m.outcome, strict=True)]


def body(stream: bytes) -> dict:
    """The JSON body of a stream: the version string's size field gives its length."""
    data = stream.removeprefix(keri_events.GENUS_CODE.encode())
    return json.loads(data[:b64.b64_to_int(data[20:24].decode())])


# --- The builder ------------------------------------------------------------------------------


def test_bodies_follow_the_specification_field_order_and_are_self_addressing():
    _, streams = built(case([XIP, GRANT], [deliver("xip", OK), deliver("grant", OK)]))
    xip, grant = body(streams[0]), body(streams[1])
    assert tuple(xip) == exn_build.FIELDS["xip"] == ("v", "t", "d", "u", "i", "ri", "dt", "r",
                                                     "q", "a")
    assert tuple(grant) == exn_build.FIELDS["exn"] == ("v", "t", "d", "i", "ri", "x", "p", "dt",
                                                       "r", "q", "a")
    assert grant["x"] == grant["p"] == xip["d"]
    assert xip["u"].startswith("0A") and len(xip["u"]) == 24
    assert grant["a"]["acdc"] == keri_events.label_digest(T, "A1")
    assert grant["i"] != grant["ri"]


def test_a_signature_group_names_the_signers_latest_establishment_event():
    kels, streams = built(case([LONE], [deliver("lone", OK)]))
    parsed = exn_build.parse(T, streams[0])
    (group,) = parsed.groups
    icp = body(kels[0])
    assert (group.pre, group.sn, group.said) == (icp["i"], 0, icp["d"])
    assert [s.index for s in group.sigs] == [0]


@pytest.mark.parametrize("exchanges,messages,match", [
    ([LONE, LONE], [deliver("lone", OK)], "defined twice"),
    ([{**GRANT, "x": {"said": "later"}}], [deliver("grant", OK)], "names no earlier exchange"),
    ([{**LONE, "t": "qry"}], [deliver("lone", OK)], "not an exchange message type"),
    ([LONE], [deliver("nope", OK)], "No exchange is named"),
    ([LONE], [deliver("lone", OK, sigs=[{"aid": "I", "keys": ["x0"]}])],
     "not one of the signing keys"),
    ([LONE], [deliver("lone", OK, sigs=[{"aid": "Z", "keys": ["z0"]}])], "no establishment event"),
    ([{**LONE, "a": {"aid": "Q"}}], [deliver("lone", OK)], "has no inception event"),
])
def test_the_builder_refuses_a_scenario_it_cannot_build(exchanges, messages, match):
    with pytest.raises(ScenarioError, match=match):
        built(case(exchanges, messages))


def test_references_resolve_inside_q_and_a_and_lists():
    ex = {**LONE, "q": {"to": {"aid": "H"}}, "a": {"list": [{"said": "xip"}, 3, "s"]}}
    _, streams = built(case([XIP, ex], [deliver("lone", OK)]))
    b = body(streams[0])
    assert b["q"]["to"] == b["ri"] and b["a"]["list"][1:] == [3, "s"]
    assert b["a"]["list"][0].startswith("E")


def test_an_extra_field_is_saidified_and_signed_and_a_tamper_is_applied_after_the_said():
    extra = {**LONE, "extra": {"e": {}}}
    tampered = {**LONE, "name": "t", "tamper": {"dt": "2025-07-04T17:50:00.000001+00:00"}}
    _, streams = built(case([extra, tampered], [deliver("lone", "1/fields"),
                                                deliver("t", "1/said")]))
    assert list(body(streams[0]))[-1] == "e"
    assert body(streams[1])["dt"].endswith("01+00:00")
    assert tags(case([extra, tampered], [deliver("lone", "1/fields"),
                                         deliver("t", "1/said")])) == [
        ["1/fields", "1/fields"], ["1/said", "1/said"]]


def test_explicit_and_forged_signatures():
    msgs = [deliver("lone", "2/unverified", sigs=[{"aid": "I", "keys": [{"key": "x0",
                                                                           "index": 0}]}]),
            deliver("lone", "2/unverified", sigs=[{"aid": "I", "keys": [{"key": "i0",
                                                                           "forged": True}]}])]
    assert tags(case([LONE], msgs)) == [["2/unverified"] * 2] * 2


# --- The model --------------------------------------------------------------------------------


def test_a_well_formed_transaction_and_a_lone_message_are_accepted():
    c = case([XIP, GRANT, LONE], [deliver("xip", OK), deliver("grant", OK), deliver("lone", OK)])
    assert tags(c) == [[OK, OK]] * 3


@pytest.mark.parametrize("sigs,want", [
    ([], "2/unsigned"),
    ([{"aid": "X", "keys": ["x0"]}], "2/not-sender"),
])
def test_a_message_without_the_senders_signature_is_dropped(sigs, want):
    assert tags(case([LONE], [deliver("lone", want, sigs=sigs)])) == [[want, want]]


def test_a_threshold_shortfall_is_unverified():
    events = [{**EVENTS[0], "keys": ["i0", "j0"], "kt": "2", "next": ["i1", "j1"], "nt": "2"},
              *EVENTS[1:]]
    kels = [{"event": "I-icp", "sigs": ["i0", "j0"]}, *KELS[1:]]
    c = case([LONE], [deliver("lone", "2/unverified")], events=events, kels=kels)
    assert tags(c) == [["2/unverified"] * 2]


THRESHOLD = [{**EVENTS[0], "keys": ["i0", "j0", "k0"], "kt": "2", "next": ["i1", "j1", "k1"],
              "nt": "2"}, *EVENTS[1:]]
WEIGHTED = [{**EVENTS[0], "keys": ["i0", "j0", "k0", "l0"], "kt": ["1/2", "1/2", "1/4", "1/4"],
             "next": ["i1", "j1", "k1", "l1"], "nt": "2"}, *EVENTS[1:]]
THRESHOLD_KELS = [{"event": "I-icp", "sigs": ["i0", "j0", "k0"]}, *KELS[1:]]
WEIGHTED_KELS = [{"event": "I-icp", "sigs": ["i0", "j0", "k0", "l0"]}, *KELS[1:]]


@pytest.mark.parametrize("events,kels,keys,want", [
    (THRESHOLD, THRESHOLD_KELS, ["j0"], "2/unverified"),
    (THRESHOLD, THRESHOLD_KELS, ["i0", "k0"], OK),
    (THRESHOLD, THRESHOLD_KELS, ["j0", "j0"], "2/unverified"),
    (THRESHOLD, THRESHOLD_KELS, ["i0", {"key": "k0", "forged": True}], "2/unverified"),
    (WEIGHTED, WEIGHTED_KELS, ["k0", "l0"], "2/unverified"),
    (WEIGHTED, WEIGHTED_KELS, ["i0", "j0"], OK),
    (WEIGHTED, WEIGHTED_KELS, ["i0", "k0", "l0"], OK),
])
def test_a_multi_key_sender_is_accepted_only_when_its_threshold_is_met(events, kels, keys, want):
    """One valid sender signature passes the line-1266 floor; only the line-1260 threshold
    refuses it, counted over distinct verified signers and, when weighted, by weight."""
    sigs = [{"aid": "I", "keys": keys}]
    c = case([LONE], [deliver("lone", want, sigs=sigs)], events=events, kels=kels)
    assert tags(c) == [[want, want]]


@pytest.mark.parametrize("grant,want", [
    ({**GRANT, "p": {"nothing": "elsewhere"}}, "3/prior"),
    ({**GRANT, "x": {"nothing": "no-such-xip"}}, "3/no-xip"),
    ({**GRANT, "x": {"nothing": "no-such-xip"}, "p": ""}, "3/no-xip"),
])
def test_broken_transaction_links_are_refused(grant, want):
    c = case([XIP, grant], [deliver("xip", OK), deliver("grant", want)])
    assert tags(c)[1] == [want, want]


def test_membership_is_by_x_so_a_prior_from_another_transaction_is_a_prior_failure():
    """Line 979 says x "universally uniquely associates" a message with its transaction, so a
    message whose x names one held xip belongs to that transaction, and a p naming a message of
    another transaction breaks line 975, not line 979."""
    xip2 = {**XIP, "name": "xip2", "nonce": "other"}
    grant = {**GRANT, "x": {"said": "xip2"}, "p": {"said": "xip"}}
    c = case([XIP, xip2, grant], [deliver("xip", OK), deliver("xip2", OK),
                                  deliver("grant", "3/prior")])
    assert tags(c)[2] == ["3/prior"] * 2


def test_an_exchange_id_naming_a_held_message_that_is_not_an_inception_is_refused():
    """An x naming an accepted exn is not the SAID of any transaction's first message, under
    either reading of which transaction the message continues."""
    second = {**GRANT, "name": "second", "x": {"said": "grant"}, "p": {"said": "grant"}}
    c = case([XIP, GRANT, second], [deliver("xip", OK), deliver("grant", OK),
                                    deliver("second", "3/exchange-id")])
    assert tags(c)[2] == ["3/exchange-id"] * 2


def test_the_second_message_of_a_transaction_follows_the_first():
    admit = {**GRANT, "name": "admit", "sender": "H", "receiver": "I", "p": {"said": "grant"},
             "r": "/ipex/admit"}
    c = case([XIP, GRANT, admit], [deliver("xip", OK), deliver("grant", OK),
                                   deliver("admit", OK, sigs=[{"aid": "H", "keys": ["h0"]}])])
    assert tags(c) == [[OK, OK]] * 3


@pytest.mark.parametrize("stream,want", [
    (keri_events.GENUS_CODE.encode() + b"{", "1/unparseable"),
])
def test_an_unparseable_stream_is_an_intrinsic_failure(stream, want):
    kels, _ = built(case([LONE], [deliver("lone", OK)]))
    m = exn_build.run(T, kels, [stream])
    assert m.initial[0].tag == want


def test_two_messages_in_one_stream_are_unparseable():
    kels, streams = built(case([LONE], [deliver("lone", OK)]))
    m = exn_build.run(T, kels, [streams[0] + streams[0]])
    assert m.initial[0].tag == "1/unparseable"


@pytest.mark.parametrize("mutate,match", [
    (lambda c: c["messages"].__setitem__(0, deliver("lone", OK, sigs=[
        {"aid": "I", "keys": ["i0"]}, {"aid": "X", "keys": ["x0"]}])), "another AID"),
    (lambda c: c.__setitem__("kels", KELS[1:]), "sender's KEL"),
    (lambda c: c["messages"].append(deliver("lone", OK)), "second delivery"),
    (lambda c: c["exchanges"].__setitem__(0, {**LONE, "x": "", "p": {"nothing": "q"}}),
     "outside a transaction"),
])
def test_shapes_the_model_does_not_grade_are_refused(mutate, match):
    c = case([LONE], [deliver("lone", OK)])
    mutate(c)
    with pytest.raises(ScenarioError, match=match):
        tags(c)


def test_a_signature_naming_an_event_the_validator_does_not_hold_is_not_graded():
    rot = {"name": "I-rot", "aid": "I", "t": "rot", "keys": ["i1"], "next": ["i2"]}
    c = case([LONE], [deliver("lone", OK, sigs=[{"aid": "I", "keys": ["i1"]}])],
             events=[*EVENTS, rot])
    with pytest.raises(ScenarioError, match="does not hold"):
        tags(c)


def test_a_sender_whose_kel_has_rotated_is_not_modelled():
    rot = {"name": "I-rot", "aid": "I", "t": "rot", "keys": ["i1"], "next": ["i2"]}
    c = case([LONE], [deliver("lone", OK, sigs=[{"aid": "I", "keys": ["i1"]}])],
             events=[*EVENTS, rot], kels=[*KELS, {"event": "I-rot", "sigs": ["i1"]}])
    with pytest.raises(ScenarioError, match="has rotated"):
        tags(c)


def test_attachments_the_model_does_not_grade_are_refused():
    """A seal source couple can authenticate an exchange message in place of signatures; the
    model grades signatures only."""
    kels, streams = built(case([LONE], [deliver("lone", OK, sigs=[])]))
    src = keri_events.EventBuilder(T, EVENTS)
    icp = src.event("I-icp")
    couple = encoding.primitive(T, "0A", (0).to_bytes(16, "big")) + icp.said
    group = src._group("-C", [src._group("-S", [couple])])
    with pytest.raises(ScenarioError, match="not modelled"):
        exn_build.run(T, kels, [streams[0] + group.encode()])


def test_an_xip_delivered_after_a_message_that_named_it_is_not_graded():
    c = case([XIP, GRANT], [deliver("grant", "3/no-xip"), deliver("xip", OK)])
    with pytest.raises(ScenarioError, match="later delivery"):
        tags(c)


def test_a_prior_delivered_after_the_message_that_named_it_is_not_graded():
    admit = {**GRANT, "name": "admit", "p": {"said": "grant"}}
    c = case([XIP, GRANT, admit], [deliver("xip", OK), deliver("admit", "3/prior"),
                                   deliver("grant", OK)])
    with pytest.raises(ScenarioError, match="later delivery"):
        tags(c)


def test_a_kel_the_validator_does_not_accept_is_refused():
    c = case([LONE], [deliver("lone", OK)], kels=[{"event": "I-icp", "sigs": []}])
    with pytest.raises(ScenarioError, match="KEL message"):
        tags(c)


def test_a_non_canonical_body_is_not_graded():
    kels, streams = built(case([LONE], [deliver("lone", OK, sigs=[])]))
    raw = streams[0].removeprefix(keri_events.GENUS_CODE.encode())
    spaced = raw.replace(b'"t":"exn"', b'"t": "exn"').replace(b'"r":"/ipex/grant"',
                                                              b'"r":"/ipex/gran"')
    with pytest.raises(ScenarioError, match="compact JSON"):
        exn_build.run(T, kels, [keri_events.GENUS_CODE.encode() + spaced])


def _spec_examples():
    lines = KERI_TEXT.splitlines()
    out, i = [], 0
    while i < len(lines):
        if lines[i].startswith("(b'{\"v\":\"KERI"):
            j = i
            while not lines[j].rstrip().endswith(")"):
                j += 1
            raw = ast.literal_eval(" ".join(lines[i:j + 1]))
            if json.loads(raw)["t"] in exn_build.FIELDS:
                out.append(pytest.param(i + 1, raw, id=f"L{i + 1}"))
            i = j
        i += 1
    return out


def test_the_specification_has_an_xip_and_an_exn_example():
    assert sorted(json.loads(p.values[1])["t"] for p in _spec_examples()) == ["exn", "xip"]


@pytest.mark.parametrize("line,raw", _spec_examples())
def test_the_specifications_own_exchange_examples_pass_the_models_structure_checks(line, raw):
    """Every xip and exn example in the pinned text carries a SAID and field order the model
    accepts, so the bytes the generator builds follow the specification's own examples."""
    parsed = exn_build.Parsed(body=json.loads(raw), raw=raw)
    assert exn_build.intrinsic(T, parsed) is None


# --- The grading ------------------------------------------------------------------------------


def _by_message(c):
    (out,) = make(c)
    return {a["message"]: a for a in out["assertions"]}, out


def test_an_accepted_message_is_graded_should_as_liveness():
    a, out = _by_message(case([XIP, GRANT], [deliver("xip", OK), deliver("grant", OK)]))
    assert out["operation"] == "exn.verify" and out["id"] == "KERI-9999"
    assert [(x["expected"], x["level"]) for x in a.values()] == [("accepted", "SHOULD")] * 2
    assert a[0]["inferred_from"] == INFERENCES["exn-liveness"]
    assert a[0]["clause"] == CLAUSES["nonkey-threshold"][1]
    assert out["targets"]["features"] == sorted(exn_build.FEATURES_BASE)
    assert out["input"]["perspective"] == {"role": "validator"}
    assert [k["source"] for k in out["input"]["kels"]] == ["issuer", "holder", "other"]
    assert out["provenance"]["scenario"] == "scenarios/keri/test.json#XS-test"


@pytest.mark.parametrize("exchanges,sigs,clause,level", [
    ([LONE], [], "drop-unsigned", "MUST"),
    ([LONE], [{"aid": "X", "keys": ["x0"]}], "drop-unsigned", "MUST"),
    ([LONE], [{"aid": "I", "keys": [{"key": "x0", "index": 0}]}], "nonkey-threshold", "MUST"),
    ([{**LONE, "extra": {"e": {}}}], BY_I, "exn-fields", "MUST"),
    ([{**LONE, "tamper": {"dt": "2025-07-04T17:50:00.000001+00:00"}}], BY_I, "act-as-verifier",
     "MUST"),
])
def test_refusals_at_steps_1_and_2_are_must_rejections(exchanges, sigs, clause, level):
    want = tags(case(exchanges, [deliver("lone", OK, sigs=sigs)]))[0][0]
    a, _ = _by_message(case(exchanges, [deliver("lone", want, sigs=sigs)]))
    assert a[0]["expected"] == "rejected" and a[0]["level"] == level
    assert a[0]["clause"] == CLAUSES[clause][1] and "inferred_from" not in a[0]
    assert a[0]["note"].startswith(f"Decision procedure step {want[0]}")


def test_an_xip_with_an_extra_field_cites_the_xip_field_order():
    a, _ = _by_message(case([{**XIP, "extra": {"e": {}}}], [deliver("xip", "1/fields")]))
    assert a[0]["clause"] == CLAUSES["xip-fields"][1]


@pytest.mark.parametrize("exchanges,messages,clause,inference", [
    ([XIP, {**GRANT, "p": {"nothing": "elsewhere"}}],
     [deliver("xip", OK), deliver("grant", "3/prior")], "exn-prior", "exn-prior-link"),
    ([XIP, {**XIP, "name": "xip2", "nonce": "other"},
      {**GRANT, "x": {"said": "xip2"}}],
     [deliver("xip", OK), deliver("xip2", OK), deliver("grant", "3/prior")],
     "exn-prior", "exn-prior-link"),
    ([XIP, GRANT, {**GRANT, "name": "second", "x": {"said": "grant"}, "p": {"said": "grant"}}],
     [deliver("xip", OK), deliver("grant", OK), deliver("second", "3/exchange-id")],
     "exn-x", "exn-x-link"),
    ([{**LONE, "x": {"nothing": "no-such-xip"}}], [deliver("lone", "3/no-xip")],
     "exn-x-empty", "exn-lone"),
])
def test_broken_links_are_should_rejections_inferred_from_the_sender_rule(exchanges, messages,
                                                                           clause, inference):
    (out,) = make(case(exchanges, messages))
    last = out["assertions"][-1]
    assert last["expected"] == "rejected" and last["level"] == "SHOULD"
    assert last["clause"] == CLAUSES[clause][1]
    assert last["inferred_from"] == INFERENCES[inference]


def test_a_scenario_whose_expectation_differs_from_the_procedure_is_refused():
    with pytest.raises(ScenarioError, match="the decision procedure gives"):
        make(case([LONE], [deliver("lone", "2/unsigned")]))


def test_a_disputed_case_carries_its_dispute():
    dispute = {"clauses": ["exn-xip-first"], "summary": "s", "raised_at": "r"}
    (out,) = make(case([LONE], [deliver("lone", OK)], status="disputed", dispute=dispute))
    assert out["status"] == "disputed"
    assert out["dispute"] == {"clauses": [CLAUSES["exn-xip-first"][1]], "summary": "s",
                              "raised_at": "r"}


def test_an_exchange_case_is_normative_only():
    with pytest.raises(ScenarioError, match="normative"):
        make(case([LONE], [deliver("lone", OK)]), normative=False)


def test_a_reason_with_no_clause_is_refused(monkeypatch):
    monkeypatch.setattr(exn_build, "REASON_CLAUSES", {})
    with pytest.raises(ScenarioError, match="No clause grades"):
        make(case([LONE], [deliver("lone", "2/unsigned", sigs=[])]))


def test_features_follow_the_kels():
    events = [{**EVENTS[0], "keys": ["i0", "j0"], "kt": "2", "next": ["i1", "j1"], "nt": "2"},
              *EVENTS[1:]]
    kels = [{"event": "I-icp", "sigs": ["i0", "j0"]}, *KELS[1:]]
    sigs = [{"aid": "I", "keys": ["i0", "j0"]}]
    (out,) = make(case([LONE], [deliver("lone", OK, sigs=sigs)], events=events, kels=kels))
    assert "kel.multisig.numeric" in out["targets"]["features"]


# --- Regeneration -----------------------------------------------------------------------------


@pytest.fixture
def ktree(tmp_path):
    (tmp_path / "scenarios" / "cesr").mkdir(parents=True)
    shutil.copy(ROOT / "scenarios" / "cesr" / "clauses.json", tmp_path / "scenarios" / "cesr")
    (tmp_path / "scenarios" / "keri").mkdir()
    shutil.copy(ROOT / "scenarios" / "keri" / "clauses.json", tmp_path / "scenarios" / "keri")
    return tmp_path


def test_generate_writes_exchange_cases_into_the_keri_layer_and_profile(ktree):
    c = case([LONE], [deliver("lone", OK)])
    c["id"] = "KERI-0001"
    c.pop("profile")
    (ktree / "scenarios" / "keri" / "x.json").write_text(json.dumps(
        {"profile": "keri-1.0", "operation": "exn.verify", "cases": [copy.deepcopy(c)]}))
    files = regenerate.generate(ktree)
    assert json.loads(files["cases/keri/KERI-0001.json"])["operation"] == "exn.verify"
    assert json.loads(files["profiles/keri-1.0.json"])["cases"] == ["KERI-0001"]


def test_a_key_event_delivered_as_an_exchange_message_is_refused():
    kels, _ = built(case([LONE], [deliver("lone", OK)]))
    with pytest.raises(ScenarioError, match="not an exchange message"):
        exn_build.run(T, kels, [kels[1]])
