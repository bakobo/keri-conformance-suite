"""Turn KERI scenarios into case files.

A KERI scenario names its events and deliveries without their bytes (see keri_events), and states,
for each delivered message, the decision-procedure step and reason it expects at its initial and
final readings, as ``"<step>/<reason>"``. The builder:

1. builds every stream from the scenario (keri_events);
2. runs the model validator over the streams under each keep policy (keri_model), and refuses the
   case unless the escrowing model reaches exactly the steps the scenario states;
3. derives the assertions from the model by the grading rules of docs/design.md ("What is graded
   at which level"), never from a hand-written expectation, and checks each one against all three
   keep policies, so that no graded assertion depends on behaviour the specification leaves to the
   validator.

The grading, per key-event message (receipts are graded only through their event):

- Not seen: graded at the level of the clause behind the step that refused it. A refusal under
  a sentence that says drop (lines 1266, 377, 379, 1823) is graded as ``rejected``, at the initial
  reading only. Every not-seen assertion must hold under every keep policy.
- Pending: for a signing or witness threshold shortfall only, SHOULD (line 1266).
- Seen and on the trunk: SHOULD, inferred (liveness). If seeing it needs the validator to have
  kept a threshold shortfall, it rests on line 1266 instead and needs ``keri.escrow``. If it needs
  any other kind of keeping, it is not graded in a normative case; the ``keri-escrow`` profile
  grades it at INTEROP.
- Superseded (seen, off the trunk) and the superseding rotation: SHOULD, inferred from rule A0,
  needing ``kel.recovery``.
- Key state: conditional on the message that delivered the last event on the identifier's trunk,
  at a level computed from what fixes the state: MUST under line 1737 (or a MUST clause the
  scenario names), unless the trunk was reached by a supersession (SHOULD, inferred from rule
  A0) or rests on a refusal graded only SHOULD (SHOULD, inferred from first-seen).

A normative case that needs ``keri.escrow`` or ``kel.recovery`` carries no MUST assertion of any
kind, because a MUST is never behind a feature an adapter can decline. If its grading produces
MUST assertions, the scenario names a ``companion``, and the builder emits them there: an ungated
case with the same messages and only those assertions. Its conditional key states report
not-applicable for a validator that never sees the message they are conditioned on.

"Every keep policy" above means every combination of keep policy, quiescence order (delivery
order, its reverse, and every order of the kept messages when there are at most
``MAX_PERMUTED``) and recovery choice (a validator that declines an A0 supersession, which only a
SHOULD asks it to accept). A refusal that holds only for a validator that performs recovery is
graded SHOULD, inferred from rule A0, and needs ``kel.recovery``.
"""

import itertools

from . import keri_model
from .errors import ScenarioError
from .keri_events import DELEGATED, ESTABLISHMENT, INCEPTIONS, ROTATIONS, WIRE, EventBuilder

GENERATOR_NAME = "kcs-gen-keri"
GENERATOR_VERSION = "0.1.0"
SCHEMA_VERSION = 1
BASE_FEATURES = ("cesr.genus-2.00", "cesr.serialization.json", "crypto.ed25519", "kel.basic",
                 "keri.version-2.x")
GATED = ("keri.escrow", "kel.recovery")
REJECT_REASONS = {
    "unsigned": "drop-unsigned",
    "unverified": "drop-unsigned",
    "establishment-only": "eo-drop",
    "do-not-delegate": "dnd-drop",
    "supersede-refused": "supersede-discard",
}
NOT_SEEN_CLAUSES = {
    "unparseable": "act-as-verifier",
    "fields": "act-as-verifier",
    "said": "act-as-verifier",
    "sn": "act-as-verifier",
    "inception-sn": "act-as-verifier",
    "d-i": "inception-d-i",
    "nontransferable": "no-events-nontransferable",
    "abandoned": "no-events-abandoned",
    "out-of-order": "controlling-keys",
    "prior-digest": "act-as-verifier",
    "pre-rotation": "prerotation",
    "witness-threshold": "wit-threshold",
    "delegation": "delegation-seal",
    **REJECT_REASONS,
}
ESCROW_BASIS = (
    "Inference from the KERI specification v1.0.1 (tag v1.0.1, commit "
    "71cb54ebb445dd9d8cb33cd29a5f50894fafc569): an event that cannot be accepted yet because an "
    "earlier event of its KEL, or its delegating seal, has not been seen becomes acceptable when "
    "that arrives, so a validator that keeps it accepts a KEL delivered out of order. No clause "
    "states this; the specification's only escrow obligation is for threshold shortfalls (line "
    "1266). keripy keeps such events in its escrows."
)


class _Assertions:
    def __init__(self, case_id, clauses, inferences, conflicts):
        self.case_id = case_id
        self.clauses, self.inferences, self.conflicts = clauses, inferences, conflicts
        self.items: list[dict] = []

    def add(self, check, clause=None, inferred=None, basis=None, conflicts=(), note=None,
            **fields):
        out = {"check": check}
        if basis is not None:
            out["level"], out["basis"] = "INTEROP", basis
        else:
            level, text = self.clauses[clause]
            if inferred:
                level = "SHOULD"
                out["inferred_from"] = self.inferences[inferred]
            out["level"], out["clause"] = level, text
        if conflicts:
            out["spec_conflicts"] = [self.conflicts[k] for k in conflicts]
        if note:
            out["note"] = note
        out.update(fields)
        self.items.append(out)

    def numbered(self) -> list[dict]:
        return [{"id": f"a{n}", **a} for n, a in enumerate(self.items, start=1)]


def _not_seen_clause(reason: str, ilk: str) -> tuple[str, str | None]:
    """The clause behind a refusal, and the inference if the refusal is only inferred."""
    if reason == "signing-threshold":
        return ("sig-threshold-rot" if ilk in ROTATIONS else "sig-threshold-icp-ixn"), None
    if reason == "conflict":
        return "one-kel", "first-seen"
    if reason not in NOT_SEEN_CLAUSES:
        raise ScenarioError(f"No clause grades a refusal for {reason!r}.")
    return NOT_SEEN_CLAUSES[reason], None


def _note(outcome) -> str:
    return f"Decision procedure step {outcome.step} ({outcome.reason})."


def _features(ideal, messages, graded: set[str]) -> list[str]:
    features = set(BASE_FEATURES) | graded
    for i, p in enumerate(ideal.parsed):
        ilk, body = p.ilk, p.body
        if ilk == "rct":
            features.update({"kel.witness", "keri.routing"})
            continue
        if ilk in ESTABLISHMENT:
            for th, keys in ((body["kt"], body["k"]), (body["nt"], body["n"])):
                if isinstance(th, list):
                    features.add("kel.multisig.weighted")
                elif len(keys) > 1:
                    features.add("kel.multisig.numeric")
            if body["b"] if ilk in INCEPTIONS else (body["br"] or body["ba"]):
                features.add("kel.witness")
        if ilk in INCEPTIONS and not body["n"]:
            features.add("kel.nontransferable")
        if ilk in DELEGATED:
            features.add("kel.delegation")
        if p.wigs or p.couples:
            features.add("kel.witness")
        if ilk in ROTATIONS:
            if any(s.code != "A" for s in p.sigs):
                features.add("kel.partial-rotation")
            kel = ideal.kels.get(p.pre)
            if ideal.outcome[i].state == "seen" and kel:
                prior_n = set(kel.est_before(p.sn).body["n"])
                if {ideal._digest(k) for k in body["k"]} != prior_n:
                    features.add("kel.partial-rotation")
    return sorted(features)


MAX_PERMUTED = 4  # every order of up to this many kept messages; beyond, forward and reverse


def _orders(ideal, n: int) -> dict[str, tuple[int, ...]]:
    """Quiescence orders to check: delivery order, its reverse, and every order of the messages
    the escrowing model ever kept, when there are few enough of them."""
    kept = [i for i in range(n) if ideal.initial[i].state == "kept"
            or ideal.outcome[i].state == "kept" or ideal.initial[i].state != ideal.outcome[i].state]
    orders = {"forward": tuple(range(n)), "reverse": tuple(reversed(range(n)))}
    if len(kept) <= MAX_PERMUTED:
        for perm in itertools.permutations(kept):
            orders["/".join(map(str, perm))] = perm
    return orders


class _Models:
    """The model validator under every keep policy, quiescence order and recovery choice. The
    expected readings are the escrowing model's (keep all, delivery order, recovery on); the
    others are what the grading must hold for."""

    def __init__(self, t, streams):
        n = len(streams)
        ideal = keri_model.run(t, streams, "all")
        self.ideal = ideal
        self.orders = _orders(ideal, n)
        self.runs = {}
        for policy in keri_model.POLICIES:
            for name, order in self.orders.items():
                for recovery in (True, False):
                    if recovery is False and name not in ("forward", "reverse"):
                        continue
                    self.runs[(policy, name, recovery)] = keri_model.run(
                        t, streams, policy, order, recovery)

    def select(self, policies=keri_model.POLICIES, recovery=(True, False)):
        return [m for (pol, _, rec), m in self.runs.items() if pol in policies and rec in recovery]

    @staticmethod
    def reading(m, i, phase):
        return (m.initial[i] if phase == "initial" else m.outcome[i]).state


def _companion_case(case, cid_key):
    comp = case.get("companion")
    if not isinstance(comp, dict) or not all(k in comp for k in ("id", "key", "title",
                                                                    "description")):
        raise ScenarioError(f"{case['id']}: it needs {cid_key} but carries MUST assertions, so "
                            "it must name a companion (id, key, title, description) to carry "
                            "them ungated.")
    return comp


def build_keri_case(t, scenario_path: str, case: dict, clauses: dict, inferences: dict,
                    conflicts: dict, normative: bool) -> list[dict]:
    """The case a scenario describes, and its ungated companion when it has one."""
    cid = case["id"]
    eb = EventBuilder(t, case["events"])
    deliveries = case["messages"]
    messages = [eb.message(d) for d in deliveries]
    streams = [m.stream for m in messages]
    models = _Models(t, streams)
    ideal = models.ideal

    for i, d in enumerate(deliveries):
        got = [ideal.initial[i].tag, ideal.outcome[i].tag]
        if d.get("expect") != got:
            raise ScenarioError(f"{cid}: message {i} is expected to reach {d.get('expect')}, but "
                                f"the decision procedure gives {got}.")

    receipted = {ideal.parsed[i].said for i, m in enumerate(messages) if m.receipt}
    out = _Assertions(cid, clauses, inferences, conflicts)
    graded: set[str] = set()
    read = _Models.reading

    def all_seen(i, phase, policies):
        return all(read(m, i, phase) == "seen" for m in models.select(policies, (True,)))

    def seen_grade(i, phase):
        """How a seen reading is graded, (clause, inference, features), or None when it would
        depend on keeping more than threshold shortfalls, or on the order of re-evaluation."""
        supersedes = "supersedes" in (ideal.outcome[i].reason, ideal.initial[i].reason)
        extra = {"kel.recovery"} if supersedes else set()
        if all_seen(i, phase, keri_model.POLICIES):
            return "accept-precondition", ("recovery" if supersedes else "liveness"), extra, \
                keri_model.POLICIES
        if all_seen(i, phase, ("thresholds", "all")):
            return "escrow-thresholds", None, extra | {"keri.escrow"}, ("thresholds", "all")
        return None

    def refusal(i, phase, ini_or_fin):
        """The level of a refusal: graded as the procedure says when every model refuses; as
        SHOULD, inferred from rule A0, when only validators that perform recovery refuse; and
        refused outright when a model that recovers would accept it."""
        if any(read(m, i, phase) == "seen" for m in models.select(recovery=(True,))):
            raise ScenarioError(f"{cid}: message {i}'s {phase} refusal depends on what the "
                                f"validator keeps or the order it re-evaluates in.")
        clause, inferred = _not_seen_clause(ini_or_fin.reason, ideal.parsed[i].ilk or "")
        if any(read(m, i, phase) == "seen" for m in models.select(recovery=(False,))):
            graded.add("kel.recovery")
            return clause, "recovery", False
        return clause, inferred, True

    for i, m in enumerate(messages):
        if m.receipt:
            continue
        p = ideal.parsed[i]
        ini, fin = ideal.initial[i], ideal.outcome[i]
        conflicts_here = ("receipt-drop",) if p.said in receipted else ()
        if not normative:
            _escrow_assertions(out, models, i)
            continue
        # The initial reading.
        if ini.state == "seen":
            grade = seen_grade(i, "initial")
            if grade:
                clause, inferred, extra, _ = grade
                graded |= extra
                out.add("disposition", clause, inferred, conflicts=conflicts_here, note=_note(ini),
                        message=i, phase="initial", expected="seen")
        else:
            clause, inferred, everywhere = refusal(i, "initial", ini)
            extra_conflicts = ("unsigned-may",) if ini.reason in ("unsigned", "unverified") else ()
            expected = "not-seen"
            if ini.reason in REJECT_REASONS and everywhere:
                if any(read(m, i, "initial") != "dropped" for m in models.select()):
                    raise ScenarioError(f"{cid}: message {i} must be dropped under every policy "
                                        f"and order.")
                expected = "rejected"
            out.add("disposition", clause, inferred, conflicts=conflicts_here + extra_conflicts,
                    note=_note(ini), message=i, phase="initial", expected=expected)
            if ini.reason in keri_model.THRESHOLD_REASONS and all(
                    read(m, i, "initial") == "kept"
                    for m in models.select(("thresholds", "all"), (True,))):
                out.add("disposition", "escrow-thresholds", conflicts=conflicts_here,
                        note=_note(ini), message=i, phase="initial", expected="pending")
        # The final reading and the trunk.
        if fin.state == "seen":
            grade = seen_grade(i, "final")
            if grade and ini.state != "seen":
                clause, inferred, extra, _ = grade
                graded |= extra
                out.add("disposition", clause, inferred, conflicts=conflicts_here, note=_note(fin),
                        message=i, phase="final", expected="seen")
            on = ideal.on_trunk(i)
            if grade and all(x.on_trunk(i) == on for x in models.select(grade[3], (True,))):
                clause, inferred, extra, _ = grade
                if not on:
                    clause, inferred, extra = "accept-precondition", "recovery", {"kel.recovery"}
                graded |= extra
                out.add("trunk", clause, inferred, conflicts=conflicts_here, note=_note(fin),
                        message=i, expected=on)
        else:
            clause, inferred, _ = refusal(i, "final", fin)
            extra_conflicts = ("unsigned-may",) if fin.reason in ("unsigned", "unverified") else ()
            out.add("disposition", clause, inferred, conflicts=conflicts_here + extra_conflicts,
                    note=_note(fin), message=i, phase="final", expected="not-seen")

    _key_states(out, case, eb, models, messages, normative, receipted)
    features = _features(ideal, messages, graded | ({"keri.escrow"} if not normative else set()))
    assertions = out.numbered()
    companion = None
    gated = sorted(set(features) & set(GATED))
    if normative and gated:
        musts = [a for a in assertions if a["level"] == "MUST"]
        if musts:
            comp = _companion_case(case, gated)
            companion = _case(comp["id"], comp["title"], comp["description"], case,
                              _features(ideal, messages, set()), musts, messages, scenario_path,
                              comp["key"], clauses)
        elif "companion" in case:
            raise ScenarioError(f"{cid}: names a companion but has no MUST assertion to put in it.")
        assertions = [a for a in assertions if a["level"] != "MUST"]
    elif "companion" in case:
        raise ScenarioError(f"{cid}: names a companion but needs no declinable feature.")
    if not assertions:
        raise ScenarioError(f"{cid}: no assertion survives the grading rules.")
    result = _case(cid, case["title"], case["description"], case, features, assertions, messages,
                   scenario_path, case["key"], clauses)
    return [result] + ([companion] if companion else [])


def _case(cid, title, description, case, features, assertions, messages, scenario_path, key,
          clauses) -> dict:
    result = {
        "schema_version": SCHEMA_VERSION,
        "id": cid,
        "title": title,
        "description": description,
        "status": case.get("status", "active"),
        "profile": case["profile"],
        "targets": {"wire": ["CESR-2.00", WIRE], "features": features},
        "operation": "keri.process",
        "input": {
            "perspective": {"role": "validator"},
            "messages": [{"stream": m.stream.hex(), "source": m.source} for m in messages],
        },
        "assertions": [{**a, "id": f"a{n}"} for n, a in enumerate(assertions, start=1)],
        "provenance": {
            "scenario": f"{scenario_path}#{key}",
            "generator": {"name": GENERATOR_NAME, "version": GENERATOR_VERSION},
            "reference": None,
        },
    }
    if "dispute" in case:
        d = case["dispute"]
        result["dispute"] = {
            "clauses": [clauses[k][1] for k in d["clauses"]],
            "summary": d["summary"],
            "raised_at": d["raised_at"],
        }
    return result


def _escrow_assertions(out, models, i):
    """INTEROP assertions for the readings that depend on keeping more than the specification
    asks: an early event held, then seen and on the trunk. They must not depend on the order of
    re-evaluation."""
    ideal = models.ideal
    alls = models.select(("all",), (True,))
    stricts = models.select(("thresholds",), (True,))
    ini, fin = ideal.initial[i], ideal.outcome[i]
    for m in alls:
        if ((m.initial[i].state, m.outcome[i].state, m.on_trunk(i))
                != (ini.state, fin.state, ideal.on_trunk(i))):
            raise ScenarioError(f"message {i}'s escrow readings depend on the order of "
                                "re-evaluation.")
    if all((m.initial[i].state, m.outcome[i].state) == (ini.state, fin.state) for m in stricts):
        return
    if ini.state == "kept":
        out.add("disposition", basis=ESCROW_BASIS, note=_note(ini), message=i, phase="initial",
                expected="pending")
    if fin.state == "seen":
        out.add("disposition", basis=ESCROW_BASIS, note=_note(fin), message=i, phase="final",
                expected="seen")
        out.add("trunk", basis=ESCROW_BASIS, note=_note(fin), message=i,
                expected=ideal.on_trunk(i))


def _key_state_grade(out, pre, ideal, how):
    """The key state's clause and inference, from what fixes it. If the trunk was reached by a
    supersession, only rule A0 (lowercase) fixes which keys control, so it is SHOULD, inferred.
    If any refusal of one of the identifier's messages is graded only SHOULD, the state rests on
    that refusal, so it is SHOULD too. Otherwise it is MUST, under line 1737 or the MUST clause
    the scenario names for its content."""
    if not isinstance(how, dict) or set(how) - {"clause"}:
        raise ScenarioError(f"A key-state override names only a MUST clause, not {how!r}.")
    mine = {i for i, p in enumerate(ideal.parsed) if p.pre == pre}
    if any("supersedes" in (ideal.initial[i].reason, ideal.outcome[i].reason) for i in mine):
        level = ("controlling-keys", "recovery")
    elif any(a["check"] == "disposition" and a.get("message") in mine and a["level"] == "SHOULD"
             and a["expected"] in ("not-seen", "rejected") for a in out.items):
        level = ("one-kel", "first-seen")
    else:
        return how.get("clause", "controlling-keys"), None
    if "clause" in how:
        raise ScenarioError(f"A key-state override names {how['clause']!r}, but the state is "
                            "fixed only at SHOULD.")
    return level


def _key_states(out, case, eb, models, messages, normative, receipted):
    ideal = models.ideal
    overrides = case.get("key_state", {})
    names = {eb.prefix(aid): aid for aid in {s["aid"] for s in case["events"]}}
    for pre in sorted(ideal.kels):
        kel = ideal.kels[pre]
        aid = names[pre]
        how = overrides.get(aid, {})
        if how is False:
            continue
        last = kel.trunk[-1].said
        index = next(i for i, m in enumerate(messages)
                     if not m.receipt and ideal.parsed[i].said == last)
        expected = ideal.key_state(pre)
        for model in models.select():
            if model.outcome[index].state == "seen" and model.key_state(pre) != expected:
                raise ScenarioError(f"{case['id']}: {aid}'s key state depends on what the "
                                    f"validator keeps or the order it re-evaluates in.")
        conflicts_here = ("receipt-drop",) if any(r.said in receipted for r in kel.trunk) else ()
        if normative:
            clause, inferred = _key_state_grade(out, pre, ideal, how)
            out.add("key_state", clause, inferred, conflicts=conflicts_here, if_seen=index,
                    aid=pre, expected=expected)
        else:
            out.add("key_state", basis=ESCROW_BASIS, if_seen=index, aid=pre, expected=expected)
