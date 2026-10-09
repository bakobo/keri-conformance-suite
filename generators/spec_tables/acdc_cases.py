"""Turn ACDC scenarios into ``acdc.verify`` cases.

A scenario file under ``scenarios/acdc/`` holds named ``fixtures`` (bundle fragments in the form
acdc_build reads) and ``cases``. A case starts from a fixture (``base``) and changes it with
``replace`` (top-level keys), ``patch`` (fields of named items: ``null`` deletes a field),
``append`` and ``remove`` (named items, or KEL deliveries by event). It states, in ``expect``,
every check the decision procedure fails on its bundle, and a refusal names its positive
``pair``. The builder:

1. builds the bundle (acdc_build) and runs the model validator over its bytes (acdc_model),
   under the design's readings and under every other candidate reading of the bytes the text
   leaves open (acdc_saids.CANDIDATES);
2. refuses the case unless the model fails exactly the checks the scenario expects, a refusal
   names a pair whose bundle fails nothing, and every MUST refusal holds under every reading;
3. derives the assertions from what the model found, by the grading calculus of docs/design.md
   ("How levels are derived"), and records each assertion's derivation in its note. No expected
   value is written in a scenario.

The grading, per case:

- **Verdict.** If the presented ACDC fails steps 1 to 5, it is not valid, graded at the highest
  over its failing checks (each an independent derivation) of the level of each, and the note
  names every derivation and the step that decided. Otherwise, if anything else in the DAG fails
  or the registry records more than one update, the verdict is not graded (propagation is MAY,
  line 1114; revocation has no normative meaning). Otherwise it is valid, SHOULD, inferred
  (liveness), or inferred from the reading it depends on.
- **Registry.** When the presented ACDC has a top-level ``rd``: no registry reported, if its
  inception fails, graded by the failing clause; else the registry is reported (liveness) and its
  head is exactly the model's, graded MUST only where a SAID check fixed it and the state is
  unknown, since a reported state depends on the Tag-code reading (A-B3).
- **Edges.** In a wholly valid DAG every edge is reported and valid (liveness). Otherwise each
  failing edge is not valid, MUST, and is reported (SHOULD, inferred).

A case whose liveness assertions need a declinable feature (``acdc.edges``,
``acdc.registry.bup``) and that also has MUST or refusal assertions is split: those go to an
ungated companion the scenario names, because no MUST, and no refusal, hides behind a feature an
adapter can decline (docs/design.md, ACDC, Features). The one exception is a feature only whose
performers can make any of a case's assertions, which a scenario names in ``requires``: a seal
displaced by a recovery rotation is off the trunk only for a validator that performs recovery.
Such a case is not split and may carry no MUST.
"""

import copy

from . import acdc_build, spec_source
from . import acdc_model as am
from . import acdc_saids as sa
from .build import resolve_clauses, resolve_records
from .errors import ScenarioError
from .keri_events import WIRE as KERI_WIRE

GENERATOR_NAME = "kcs-gen-acdc"
GENERATOR_VERSION = "0.1.0"
SCHEMA_VERSION = 1
PROFILE = "acdc-1.0"
WIRE = "ACDCCAACAAJSON"
BASE_FEATURES = ("acdc.version-2.x", "cesr.genus-2.00", "cesr.serialization.json",
                 "crypto.ed25519", "kel.basic", "keri.version-2.x")
EDGES, BUP = "acdc.edges", "acdc.registry.bup"
# Features a scenario may require of a whole case, because only an implementation that performs
# them can make any of its assertions: a seal displaced by a recovery rotation is off the trunk
# only for a validator that performs the recovery. Such a case may carry no MUST.
REQUIRABLE = ("kel.recovery",)
RANK = {"SHOULD": 1, "MUST": 2}

# Each failing check: the clause it rests on, the inference that grades it below the clause's
# level (None when the clause binds a validator directly), and the derivation in words.
REASONS = {
    "unframeable": ("version-size", None, ("line 62 says a stream parser should use the "
                    "version string to extract the body, and its declared size frames none")),
    "protocol": ("version-protocol", "producer-version", ("line 64 fixes the version string's "
                 "protocol, a producer rule; a body framed as another protocol's is not an "
                 "ACDC body, so no later step applies to it")),
    "field-order": ("field-order", "producer-order", "line 32 orders the fields, a producer rule"),
    "required-field": ("required-fields", "producer-required",
                       "line 36 requires the fields, a producer rule"),
    "a-and-A": ("a-and-A", "producer-a-and-A", "line 110 forbids both, a producer rule"),
    "said": ("said-verify", None, ("CESR line 1194 makes SAID verification a validator's "
             "obligation, and ACDC lines 134 to 147 fix the most compact form it is over")),
    "schema-absent": ("schema-enforced", None, ("line 250 requires validation against the "
                      "composed schema, which no schema of the right SAID allows")),
    "schema-said": ("schema-said", None, ("line 248 requires the schema to verify against its "
                    "SAID, so the schema in the bundle is not the one s names")),
    "schema-invalid": ("schema-variant", None, ("lines 246 and 250 require the ACDC to validate "
                       "against its schema")),
    "schema-nonlocal": ("schema-nonlocal", "producer-nonlocal",
                        "line 206 forbids non-local references, a rule for schema authors"),
    "schema-dialect": ("schema-dialect", None, ("line 226 says a dialect mismatch SHOULD fail "
                       "validation")),
    "issuer-kel": ("key-state", "issuer-kel", ("line 95, with the issuer commitment no keyword "
                   "requires (A-G1)")),
    "no-commitment": ("key-state", "commitment", ("line 95 makes the issuer's key state the "
                      "KERI one, and lines 1663 and 1673 bind an ACDC to it only by a seal, which "
                      "no keyword sentence obliges a validator to require (A-G1)")),
    "no-registry-commitment": ("update-anchored", "commitment-registry", ("line 1669 binds the "
                               "issuer to anchor the updates through which an ACDC's registry "
                               "commits to it (A-G1)")),
    "rip-absent": ("registry-anchored", "producer-registry-anchored",
                   "line 1669 binds the issuer"),
    "rip-said": ("said-verify", None, ("CESR line 1194 makes SAID verification a validator's "
                 "obligation")),
    "rip-issuer": ("registry-issuer", "producer-registry-issuer", "line 2015 binds the issuer"),
    "rip-unsealed": ("registry-anchored", "producer-registry-anchored",
                     "line 1669 binds the issuer"),
    "bup-type": ("update-anchored", "producer-update-anchored", "line 1669 binds the issuer"),
    "bup-said": ("said-verify", None, ("CESR line 1194 makes SAID verification a validator's "
                 "obligation")),
    "bup-sn": ("registry-sn", "producer-registry-sn", "line 2023 binds the issuer"),
    "bup-prior": ("registry-prior", "producer-registry-prior", "line 2027 binds the issuer"),
    "bup-unsealed": ("update-anchored", "producer-update-anchored",
                     "lines 1669 and 1922 bind the issuer"),
    "blid-self": ("blid", "blid-analogy", "line 2066 makes a BLID a SAID only by analogy"),
    "blid-other": ("blid", "blid-analogy", ("line 2066 makes the BLID the update's commitment, "
                   "and a BLID is a SAID only by analogy")),
    "far-absent": ("edge-far", None, ("line 1174 requires the validator to confirm the far "
                   "node's SAID")),
    "far-said": ("edge-far", None, ("line 1174 requires the validator to confirm the far node's "
                 "SAID, recomputed from its content")),
    "far-schema": ("edge-far", None, ("line 1174 requires the far node to satisfy its own "
                   "schema")),
    "edge-schema": ("edge-schema", None, ("line 1178 requires the far node to validate against "
                    "the edge's schema")),
    "i2i-issuee": ("edge-i2i", None, "line 1205 states the I2I condition for validity"),
    "i2i-untargeted": ("edge-i2i", None, "line 1205 states the I2I condition for validity"),
    "i2i-hidden": ("edge-i2i", None, "line 1205 states the I2I condition for validity"),
}


# When an acceptance depends on several readings, the inference names the most specific: the
# version string's size touches every form but the compact one, so it comes last.
PRIORITY = ("aggregate", "schema", "ts_code", "lists", "ascii", "compact_v")


def alternatives() -> list[tuple[str, sa.Readings]]:
    """Every candidate reading of the bytes the text leaves open, one field at a time."""
    return [(name, sa.Readings(**{name: value}))
            for name, values in sa.CANDIDATES.items() for value in values[1:]]


# -- the clause registry ----------------------------------------------------------------------


def resolve_registry(registry: dict, texts: dict[str, str]) -> tuple[dict, dict, dict]:
    """The registry's clauses, inferences and conflicts in case-file form, each checked against
    its pinned text. A clause names its spec (``acdc`` unless it says ``cesr``); inferences and
    conflicts quote the ACDC text."""
    pins = {"acdc": spec_source.ACDC, "cesr": spec_source.cesr_pin()}
    groups: dict[str, dict] = {}
    for key, c in registry["clauses"].items():
        spec = c.get("spec", "acdc")
        if spec not in pins:
            raise ScenarioError(f"Clause {key!r} names the spec {spec!r}; ACDC cases cite the "
                                f"ACDC or CESR text.")
        groups.setdefault(spec, {})[key] = {k: v for k, v in c.items() if k != "spec"}
    clauses = {}
    for spec, group in groups.items():
        clauses.update(resolve_clauses(group, texts[spec], pins[spec]))
    inferences = resolve_records(registry.get("inferences", {}), texts["acdc"], "inference")
    conflicts = resolve_records(registry.get("conflicts", {}), texts["acdc"], "why")
    return clauses, inferences, conflicts


# -- composing a scenario's fragment ----------------------------------------------------------

LISTS = ("events", "kels", "schemas", "registries", "acdcs")


def _named(item) -> str:
    return item["name"] if "name" in item else item["event"]


def compose(fixtures: dict, case: dict) -> dict:
    """The bundle fragment a case describes: its fixture, changed as the case says."""
    base = case.get("base")
    if base not in fixtures:
        raise ScenarioError(f"{case.get('key')}: names the fixture {base!r}, which the scenario "
                            f"file does not define.")
    frag = copy.deepcopy(fixtures[base])
    for key, value in case.get("replace", {}).items():
        frag[key] = copy.deepcopy(value)
    for kind, patches in case.get("patch", {}).items():
        for name, fields in patches.items():
            item = next((i for i in frag.get(kind, []) if _named(i) == name), None)
            if item is None:
                raise ScenarioError(f"{case.get('key')}: patches {kind} {name!r}, which the "
                                    f"fixture does not have.")
            for field, value in fields.items():
                if value is None:
                    item.pop(field, None)
                else:
                    item[field] = copy.deepcopy(value)
    for kind, names in case.get("remove", {}).items():
        missing = set(names) - {_named(i) for i in frag.get(kind, [])}
        if missing:
            raise ScenarioError(f"{case.get('key')}: removes {kind} {sorted(missing)!r}, which "
                                f"the fixture does not have.")
        frag[kind] = [i for i in frag[kind] if _named(i) not in names]
    for kind, items in case.get("append", {}).items():
        frag.setdefault(kind, []).extend(copy.deepcopy(items))
    return frag


# -- what the model found -----------------------------------------------------------------------


def found(result: am.Result, names: dict[str, str]) -> list[str]:
    """Every failing check the model reports, named by the scenario's names."""
    out = [f"{names[result.presented.said]} {f.tag}" if result.presented.said in names
           else f"presented {f.tag}" for f in result.presented.failures]
    for said, node in result.far.items():
        out += [f"{names[said]} {f.tag}" for f in node.failures]
    out += [f"{names[e.near]}:{e.path} {e.failure}" for e in result.edges if e.failure]
    if result.registry_failure:
        out.append(f"registry {result.registry_failure}")
    if result.registry and result.registry.stop:
        out.append(f"registry {result.registry.stop}")
    if result.registry and result.registry.block:
        out.append(f"registry {result.registry.block}")
    return sorted(out)


class Evaluation:
    """The model's result under the design's readings and under every other candidate."""

    def __init__(self, t, bundle: acdc_build.Bundle):
        self.bundle = bundle
        trunks = am.kels(t, bundle.request)
        self.result = am.evaluate(t, bundle.request, trunks=trunks)
        self.others = [(name, am.evaluate(t, bundle.request, readings, trunks))
                       for name, readings in alternatives()]

    def depends(self, holds) -> str | None:
        """The reading an acceptance depends on: of the readings under which ``holds(result)``
        is false, the one most specific to what the case tests (PRIORITY), or None."""
        failing = {name for name, r in self.others if not holds(r)}
        return next((name for name in PRIORITY if name in failing), None)


# -- grading ------------------------------------------------------------------------------------


class _Assertions:
    def __init__(self, clauses, inferences, conflicts):
        self.clauses, self.inferences, self.conflicts = clauses, inferences, conflicts
        self.items: list[dict] = []

    def add(self, check, clause, inferred=None, conflicts=(), *, note, **fields):
        level, text = self.clauses[clause]
        out = {"check": check}
        if inferred:
            if text["spec"] != "acdc":
                raise ScenarioError(f"The clause {clause!r} is from the {text['spec']} text, and "
                                    f"an inference quotes the ACDC text, so they cannot be "
                                    f"paired in one assertion.")
            level = "SHOULD"
            out["inferred_from"] = self.inferences[inferred]
        out["level"], out["clause"] = level, text
        if conflicts:
            out["spec_conflicts"] = [self.conflicts[k] for k in conflicts]
        out["note"] = note
        out.update(fields)
        self.items.append(out)


def _level(clauses, reason) -> str:
    clause, inferred, _ = REASONS[reason]
    return "SHOULD" if inferred else clauses[clause][0]


def _derivation(failure: am.Failure, clauses) -> str:
    _clause, inferred, words = REASONS[failure.reason]
    how = "inferred" if inferred else "direct"
    return f"step {failure.step} {failure.reason}: {_level(clauses, failure.reason)}, {how}, " \
           f"because {words}"


def _verdict(out, ev, case, clauses):
    result = ev.result
    failures = result.presented.failures
    if failures:
        unique = list({f.reason: f for f in failures}.values())
        best = max(unique, key=lambda f: (RANK[_level(clauses, f.reason)], -f.step))
        first = min(failures, key=lambda f: f.step)
        level = _level(clauses, best.reason)
        if level == "MUST":
            for name, other in ev.others:
                if not any(_level(clauses, f.reason) == "MUST"
                           for f in other.presented.failures):
                    raise ScenarioError(f"{case['key']}: its MUST refusal does not hold under "
                                        f"the reading {name}, so the design grades it SHOULD; "
                                        f"it is left for a later batch.")
        note = (f"Decided at step {first.step} ({first.reason}). Derivations: "
                + "; ".join(_derivation(f, clauses) for f in unique)
                + ". Graded at the highest, over the derivations, of the level of each.")
        clause, inferred, _ = REASONS[best.reason]
        out.add("verdict", clause, inferred, case.get("spec_conflicts", ()), note=note,
                expected="not-valid")
        return
    registry = result.registry
    if result.failing() or (registry and registry.updates > 1):
        return
    depends = ev.depends(lambda r: not r.failing())
    clause = case.get("accept_clause", "schema-enforced")
    inferred = f"reading-{depends}" if depends else (
        "liveness" if clauses[clause][0] == "MUST" else None)
    note = ("Decision procedure step 7: every check passes" +
            (f", under the design's reading of {depends}." if depends else "."))
    out.add("verdict", clause, inferred, case.get("spec_conflicts", ()), note=note,
            expected="valid")


def _registry(out, ev, case):
    result = ev.result
    if result.presented.body is None or "rd" not in result.presented.body:
        return
    for name, other in ev.others:
        same = (other.registry_failure == result.registry_failure and
                (other.registry and other.registry.facts()) ==
                (result.registry and result.registry.facts()))
        if not same:
            raise ScenarioError(f"{case['key']}: the registry's head depends on the reading "
                                f"{name}, which no first-batch case may.")
    if result.registry is None:
        clause, inferred, words = REASONS[result.registry_failure]
        out.add("registry_reported", clause, inferred,
                note=f"Decision procedure step 5: the registry inception fails "
                     f"({result.registry_failure}), because {words}.", expected=False)
        return
    registry = result.registry
    out.add("registry_reported", "registry-anchored", "liveness-registry",
            note="Decision procedure step 5: the registry inception verifies.", expected=True)
    stop = registry.stop
    chain = (f"the chain stops at an update that fails ({stop}), so the head is the last event "
             f"before it" if stop else "every update in the bundle verifies, so the head is the "
             "last of them")
    if registry.ts is not None:
        clause, inferred = "blinded-attachment", "ts-code"
    elif registry.block:
        clause, inferred, _ = REASONS[registry.block]
        chain += f", and its blinded state block does not verify ({registry.block})"
    elif stop and (registry.n == 0 or REASONS[stop][1] is not None):
        # The stop's own clause decides the head: nothing before it was counted, or the stop
        # is itself an inferred SHOULD.
        clause, inferred, _ = REASONS[stop]
    elif stop:
        # A check a validator owes directly stops the chain, but the head also counts updates
        # before it, whose acceptance rests on rules that bind the issuer, so the check alone
        # does not decide the head (docs/design.md, ACDC, Registry state).
        clause, inferred = "registry-prior", "registry-head"
        chain += ", and the updates before it count by rules that bind the issuer"
    else:
        clause, inferred = "registry-prior", "registry-head"
    out.add("registry_state", clause, inferred,
            note=f"Decision procedure step 5: {chain}.",
            expected=registry.facts())


def _edges(out, ev, case):
    result = ev.result
    if result.presented.failures:
        return
    wholly = not result.failing()
    for edge in result.edges:
        where = {"near": edge.near, "path": edge.path}
        if wholly:
            depends = ev.depends(lambda r, e=edge: not r.failing())
            inferred = f"reading-{depends}" if depends else "liveness-edge"
            note = "Decision procedure step 6: every edge in the DAG passes its own checks."
            out.add("edge_reported", "edge-far", inferred, note=note, **where)
            out.add("edge_valid", "edge-far", inferred, note=note, **where, expected=True)
        elif edge.failure:
            for name, other in ev.others:
                if not any((e.near, e.path) == (edge.near, edge.path) and e.failure
                           for e in other.edges):
                    raise ScenarioError(f"{case['key']}: the edge {edge.path} fails only under "
                                        f"some readings ({name} passes it).")
            clause, _, words = REASONS[edge.failure]
            note = f"Decision procedure step 6: the edge fails ({edge.failure}), because {words}."
            out.add("edge_reported", "edge-far", "liveness-edge", note=note, **where)
            out.add("edge_valid", clause, note=note, **where, expected=False)


def _gated(a) -> bool:
    """Whether an assertion is liveness that needs a declinable feature."""
    return ((a["check"] == "verdict" and a["expected"] == "valid")
            or (a["check"] == "registry_reported" and a["expected"] is True)
            or a["check"] == "edge_reported"
            or (a["check"] == "edge_valid" and a["expected"] is True))


def _mover(a) -> bool:
    """Whether an assertion must stay ungated: a MUST or a refusal."""
    return a["level"] == "MUST" or (a["check"] == "verdict" and a["expected"] == "not-valid") \
        or (a["check"] in ("registry_reported", "edge_valid") and a["expected"] is False)


def _features(assertions, result) -> list[str]:
    features = set(BASE_FEATURES)
    for a in assertions:
        if not _gated(a):
            continue
        if a["check"] in ("edge_reported", "edge_valid") or (
                a["check"] == "verdict" and result.edges):
            features.add(EDGES)
        if a["check"] == "registry_reported" or (
                a["check"] == "verdict" and "rd" in result.presented.body):
            features.add(BUP)
    return sorted(features)


def _case(cid, title, description, case, features, assertions, ev, scenario_path, key) -> dict:
    b = ev.bundle
    wire = ["CESR-2.00"] + ([KERI_WIRE] if b.request["kels"] else []) + [WIRE]
    return {
        "schema_version": SCHEMA_VERSION,
        "id": cid,
        "title": title,
        "description": description,
        "status": case.get("status", "active"),
        "profile": PROFILE,
        "targets": {"wire": wire, "features": features},
        "operation": "acdc.verify",
        "input": b.case_input(),
        "assertions": [{**a, "id": f"a{n}"} for n, a in enumerate(assertions, start=1)],
        "provenance": {
            "scenario": f"{scenario_path}#{key}",
            "generator": {"name": GENERATOR_NAME, "version": GENERATOR_VERSION},
            "reference": None,
        },
        "dag": b.dag,
        "as_of": b.as_of,
    }


def build(t, fixtures: dict, case: dict) -> Evaluation:
    """The bundle a case describes and what the model finds in it, checked against ``expect``."""
    bundle = acdc_build.build_bundle(t, compose(fixtures, case))
    ev = Evaluation(t, bundle)
    names = {said: name for name, said in bundle.saids.items()}
    got = found(ev.result, names)
    if sorted(case.get("expect", [])) != got:
        raise ScenarioError(f"{case['key']}: expects the checks {sorted(case.get('expect', []))}"
                            f" to fail, but the decision procedure fails {got}.")
    return ev


def build_acdc_case(scenario_path: str, case: dict, ev: Evaluation, pairs: dict, clauses: dict,
                    inferences: dict, conflicts: dict) -> list[dict]:
    """The case a scenario describes, and its ungated companion when it has one. ``pairs`` maps
    each scenario key to (case id, whether its bundle fails any check)."""
    key = case["key"]
    description = case["description"]
    if ev.result.failing():
        pair = case.get("pair")
        if pair not in pairs:
            raise ScenarioError(f"{key}: a refusal names its positive pair, a scenario that "
                                f"differs only in the defect; {pair!r} is not one.")
        if pairs[pair][1]:
            raise ScenarioError(f"{key}: its pair {pair} fails a check itself, so it is not a "
                                f"positive pair.")
        description += (f" Its positive pair is {pair} ({pairs[pair][0]}), which differs from it "
                        f"only in the defect.")
    elif "pair" in case:
        raise ScenarioError(f"{key}: fails no check, so it is a positive scenario and names no "
                            f"pair.")
    out = _Assertions(clauses, inferences, conflicts)
    _verdict(out, ev, case, clauses)
    _registry(out, ev, case)
    _edges(out, ev, case)
    assertions = out.items
    if not assertions:
        raise ScenarioError(f"{key}: no assertion survives the grading rules.")
    features = _features(assertions, ev.result)
    gated = len(features) > len(BASE_FEATURES)
    required = case.get("requires", [])
    if required:
        unknown = sorted(set(required) - set(REQUIRABLE))
        if unknown:
            raise ScenarioError(f"{key}: requires {unknown!r}; a scenario requires only "
                                f"{', '.join(REQUIRABLE)}.")
        if any(a["level"] == "MUST" for a in assertions):
            raise ScenarioError(f"{key}: requires {', '.join(required)} but has a MUST "
                                f"assertion, and no MUST is gated behind a feature an adapter "
                                f"can decline.")
        features = sorted(set(features) | set(required))
    movers = [a for a in assertions if _mover(a)]
    if gated and movers:
        comp = case.get("companion")
        if not isinstance(comp, dict) or not all(k in comp for k in ("id", "key", "title",
                                                                        "description")):
            raise ScenarioError(f"{key}: needs {', '.join(sorted(set(features) - set(BASE_FEATURES)))}"
                                f" for its liveness assertions and has MUST or refusal "
                                f"assertions, so it must name a companion (id, key, title, "
                                f"description) to carry those ungated.")
        rest = [a for a in assertions if not _mover(a)]
        main = _case(case["id"], case["title"], description, case, features, rest, ev,
                     scenario_path, key)
        companion = _case(comp["id"], comp["title"], comp["description"] + description[
                              len(case["description"]):], case,
                          sorted(BASE_FEATURES), movers, ev, scenario_path, comp["key"])
        return [main, companion]
    if "companion" in case:
        raise ScenarioError(f"{key}: names a companion but has nothing to split.")
    return [_case(case["id"], case["title"], description, case, features, assertions, ev,
                  scenario_path, key)]
