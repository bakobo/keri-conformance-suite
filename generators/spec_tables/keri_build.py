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
  at the level of the clause that fixes the state (line 1737 by default).

A normative case that needs ``keri.escrow`` or ``kel.recovery`` carries no MUST disposition
assertion, because a MUST is never behind a feature an adapter can decline. Such a case must say
``"liveness_only": true``, and the safety half of its scenario is a separate case.
"""

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


def _features(models, messages, graded: set[str]) -> list[str]:
    ideal = models["all"]
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


def build_keri_case(t, scenario_path: str, case: dict, clauses: dict, inferences: dict,
                    conflicts: dict, normative: bool) -> dict:
    cid = case["id"]
    eb = EventBuilder(t, case["events"])
    deliveries = case["messages"]
    messages = [eb.message(d) for d in deliveries]
    streams = [m.stream for m in messages]
    models = {policy: keri_model.run(t, streams, policy) for policy in keri_model.POLICIES}
    ideal = models["all"]

    for i, d in enumerate(deliveries):
        got = [ideal.initial[i].tag, ideal.outcome[i].tag]
        if d.get("expect") != got:
            raise ScenarioError(f"{cid}: message {i} is expected to reach {d.get('expect')}, but "
                                f"the decision procedure gives {got}.")

    receipted = {ideal.parsed[i].said for i, m in enumerate(messages) if m.receipt}
    out = _Assertions(cid, clauses, inferences, conflicts)
    graded: set[str] = set()

    def state(policy, i, phase):
        m = models[policy]
        return (m.initial[i] if phase == "initial" else m.outcome[i]).state

    def seen_grade(i, phase):
        """How a seen reading is graded: (clause, inference, features), or None if it depends on
        keeping more than threshold shortfalls."""
        supersedes = ideal.outcome[i].reason == "supersedes" or \
            ideal.initial[i].reason == "supersedes"
        extra = {"kel.recovery"} if supersedes else set()
        if state("none", i, phase) == "seen":
            return "accept-precondition", ("recovery" if supersedes else "liveness"), extra
        if state("thresholds", i, phase) == "seen":
            return "escrow-thresholds", None, extra | {"keri.escrow"}
        return None

    for i, m in enumerate(messages):
        if m.receipt:
            continue
        p = ideal.parsed[i]
        ini, fin = ideal.initial[i], ideal.outcome[i]
        conflicts_here = ("receipt-drop",) if p.said in receipted else ()
        if not normative:
            _escrow_assertions(out, models, i, conflicts_here)
            continue
        # The initial reading.
        if ini.state == "seen":
            grade = seen_grade(i, "initial")
            if grade:
                clause, inferred, extra = grade
                graded |= extra
                out.add("disposition", clause, inferred, conflicts=conflicts_here, note=_note(ini),
                        message=i, phase="initial", expected="seen")
        else:
            if any(state(pol, i, "initial") == "seen" for pol in keri_model.POLICIES):
                raise ScenarioError(f"{cid}: message {i}'s initial refusal depends on what the "
                                    f"validator keeps.")
            clause, inferred = _not_seen_clause(ini.reason, p.ilk or "")
            extra_conflicts = ("unsigned-may",) if ini.reason in ("unsigned", "unverified") else ()
            if ini.reason in REJECT_REASONS:
                if any(state(pol, i, "initial") != "dropped" for pol in keri_model.POLICIES):
                    raise ScenarioError(f"{cid}: message {i} must be dropped under every policy.")
                expected = "rejected"
            else:
                expected = "not-seen"
            out.add("disposition", clause, inferred, conflicts=conflicts_here + extra_conflicts,
                    note=_note(ini), message=i, phase="initial", expected=expected)
            if ini.reason in keri_model.THRESHOLD_REASONS:
                out.add("disposition", "escrow-thresholds", conflicts=conflicts_here,
                        note=_note(ini), message=i, phase="initial", expected="pending")
        # The final reading and the trunk.
        if fin.state == "seen":
            grade = seen_grade(i, "final")
            if grade and ini.state != "seen":
                clause, inferred, extra = grade
                graded |= extra
                out.add("disposition", clause, inferred, conflicts=conflicts_here, note=_note(fin),
                        message=i, phase="final", expected="seen")
            on = ideal.on_trunk(i)
            policy = "none" if state("none", i, "final") == "seen" else "thresholds"
            if grade and models[policy].on_trunk(i) == on:
                clause, inferred, extra = grade
                if not on:
                    clause, inferred, extra = "accept-precondition", "recovery", {"kel.recovery"}
                graded |= extra
                out.add("trunk", clause, inferred, conflicts=conflicts_here, note=_note(fin),
                        message=i, expected=on)
        else:
            if any(state(pol, i, "final") == "seen" for pol in keri_model.POLICIES):
                raise ScenarioError(f"{cid}: message {i}'s final refusal depends on what the "
                                    f"validator keeps.")
            clause, inferred = _not_seen_clause(fin.reason, p.ilk or "")
            extra_conflicts = ("unsigned-may",) if fin.reason in ("unsigned", "unverified") else ()
            out.add("disposition", clause, inferred, conflicts=conflicts_here + extra_conflicts,
                    note=_note(fin), message=i, phase="final", expected="not-seen")

    _key_states(out, case, eb, models, messages, normative, receipted)
    features = _features(models, messages, graded | ({"keri.escrow"} if not normative else set()))
    assertions = out.numbered()
    if normative and set(features) & set(GATED):
        musts = [a for a in assertions if a["level"] == "MUST" and a["check"] != "key_state"]
        if musts and not case.get("liveness_only"):
            raise ScenarioError(f"{cid}: needs {sorted(set(features) & set(GATED))} but carries "
                                f"MUST assertions; split its safety half into its own case and "
                                f"mark this one liveness_only.")
        assertions = [a for a in assertions if a not in musts]
        assertions = [{**a, "id": f"a{n}"} for n, a in enumerate(assertions, start=1)]
    if not assertions:
        raise ScenarioError(f"{cid}: no assertion survives the grading rules.")

    result = {
        "schema_version": SCHEMA_VERSION,
        "id": cid,
        "title": case["title"],
        "description": case["description"],
        "status": case.get("status", "active"),
        "profile": case["profile"],
        "targets": {"wire": ["CESR-2.00", WIRE], "features": features},
        "operation": "keri.process",
        "input": {
            "perspective": {"role": "validator"},
            "messages": [{"stream": m.stream.hex(), "source": m.source} for m in messages],
        },
        "assertions": assertions,
        "provenance": {
            "scenario": f"{scenario_path}#{case['key']}",
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


def _escrow_assertions(out, models, i, conflicts_here):
    """INTEROP assertions for the readings that depend on keeping more than the specification
    asks: an early event held, then seen and on the trunk."""
    ideal, strict = models["all"], models["thresholds"]
    ini, fin = ideal.initial[i], ideal.outcome[i]
    depends = (ini.state != strict.initial[i].state or fin.state != strict.outcome[i].state)
    if not depends:
        return
    if ini.state == "kept":
        out.add("disposition", basis=ESCROW_BASIS, note=_note(ini), message=i, phase="initial",
                expected="pending")
    if fin.state == "seen":
        out.add("disposition", basis=ESCROW_BASIS, note=_note(fin), message=i, phase="final",
                expected="seen")
        out.add("trunk", basis=ESCROW_BASIS, note=_note(fin), message=i,
                expected=ideal.on_trunk(i))


def _key_states(out, case, eb, models, messages, normative, receipted):
    ideal = models["all"]
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
        for policy, model in models.items():
            if model.outcome[index].state == "seen" and model.key_state(pre) != expected:
                raise ScenarioError(f"{case['id']}: {aid}'s key state depends on what the "
                                    f"validator keeps ({policy}).")
        conflicts_here = ("receipt-drop",) if any(r.said in receipted for r in kel.trunk) else ()
        if normative:
            out.add("key_state", how.get("clause", "controlling-keys"), how.get("inferred_from"),
                    conflicts=conflicts_here, if_seen=index, aid=pre, expected=expected)
        else:
            out.add("key_state", basis=ESCROW_BASIS, if_seen=index, aid=pre, expected=expected)
