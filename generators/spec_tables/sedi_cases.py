"""Turn sedi-1 verifier scenarios into ``acdc.verify`` cases graded by the sedi-1 model.

A scenario file under ``scenarios/sedi/`` (other than the profile source and its release record)
holds named ``fixtures`` in the form acdc_build reads and ``cases``, composed as acdc_cases
composes them (``base``, ``replace``, ``patch``, ``remove``, ``append``). Each case states:

- ``expect``: every finding the sedi-1 model makes, as ``<where> <grade>/<reason>``, where
  ``where`` is the scenario's name for the node (or ``presented``) and an edge path follows it
  after a colon. The generator refuses a case whose model findings differ, so a scenario cannot
  drift from what it was written to test;
- ``choices``: the sedi-1 choices its verdict rests on, which the profile's choice-to-case
  matrix counts on the side the verdict falls (sedi_profile);
- ``triage``: the security consequence of an implementation getting it wrong, or why there is
  none, which the embargo gate reads before the case is published (docs/profiles/sedi-test-plan.md,
  Embargo);
- ``pair``, for a case whose verdict is not valid: the key of a valid case that differs from it
  only in the defect.

The expected verdict is never written in a scenario: it is the model's. Every assertion is
INTEROP, rests on the choices it names, and quotes their readings as its basis.
"""

import copy

from . import acdc_build, sedi_present
from . import acdc_cases as ac
from . import acdc_saids as sa
from . import sedi_model as sm
from .errors import ScenarioError

GENERATOR_NAME = "kcs-gen-sedi"
GENERATOR_VERSION = "0.1.0"
PROFILE = "sedi-1"
BATCH_STATUS = "draft"
EDGES, BUP, PRESENTATION = "acdc.edges", "acdc.registry.bup", "acdc.presentation"
CASE_FIELDS = {"id", "key", "title", "description", "base", "replace", "patch", "remove",
               "append", "expect", "choices", "triage", "pair", "status", "disclosure"}
# A holder case's verdict when the holder must refuse; one it must present is valid.
REFUSED = "refused"


class Evaluation:
    def __init__(self, t, bundle: acdc_build.Bundle):
        self.bundle = bundle
        self.result = sm.evaluate(t, bundle.request)
        self.disclosure = None


class HolderEvaluation:
    """A holder case (choice holder-presents): the held bundle, and either the body the holder
    must present for the disclosure or why it must refuse (the verifier's findings when a
    verifier would refuse the held ACDC), with the secrets the answer must not carry."""

    def __init__(self, t, frag: dict, disclosure: dict):
        self.bundle = acdc_build.build_bundle(t, frag)
        self.disclosure = disclosure
        name = frag["presented"]
        held = self.bundle.forms[name]
        verified = sm.evaluate(t, self.bundle.request)
        shown, why = None, None
        if verified.verdict == sm.VALID:
            shown, why = sedi_present.form(held, self.bundle.expanded[name], disclosure)
        if shown is None:
            findings = (verified.findings if why is None
                        else [sm.Finding(REFUSED, self.bundle.saids[name], why)])
            self.result = sm.Result(REFUSED, findings)
            self.body = None
            # A refusal presents nothing, so it may carry nothing the compact form hides.
            self.secrets = sedi_present.secrets(held, self._present(t, frag, name, "compact"))
        else:
            self.result = verified
            body = self._present(t, frag, name, shown)
            self.body = sa.serialize(body)
            self.secrets = sedi_present.secrets(held, body)

    @staticmethod
    def _present(t, frag: dict, name: str, shown) -> dict:
        presented = copy.deepcopy(frag)
        next(a for a in presented["acdcs"] if a["name"] == name)["form"] = shown
        return acdc_build.build_bundle(t, presented).forms[name]


def found(result: sm.Result, names: dict[str, str]) -> list[str]:
    """Every finding, with each SAID replaced by the scenario's name for it."""
    out = []
    for f in result.findings:
        said, _, path = f.where.partition(".")
        where = names.get(said, said) + (f":{path}" if path else "")
        out.append(f"{where} {f.grade}/{f.reason}")
    return sorted(out)


def build(t, fixtures: dict, case: dict) -> Evaluation:
    """The bundle a case describes, evaluated, and checked against its ``expect``."""
    unknown = set(case) - CASE_FIELDS
    if unknown:
        raise ScenarioError(f"{case.get('key')}: unknown fields {sorted(unknown)!r}.")
    for field in ("id", "key", "title", "description", "choices", "triage"):
        if not case.get(field):
            raise ScenarioError(f"{case.get('key')}: a sedi-1 case needs {field!r}.")
    frag = ac.compose(fixtures, case)
    if "disclosure" in case:
        ev = HolderEvaluation(t, frag, case["disclosure"])
    else:
        ev = Evaluation(t, acdc_build.build_bundle(t, frag))
    names = {said: name for name, said in ev.bundle.saids.items()}
    got = found(ev.result, names)
    if sorted(case.get("expect", [])) != got:
        raise ScenarioError(f"{case['key']}: expects the findings {sorted(case.get('expect', []))}"
                            f", but the sedi-1 model finds {got}.")
    return ev


def _holder_case(scenario_path: str, case: dict, ev: HolderEvaluation, description: str,
                 basis: str, wire: list[str]) -> dict:
    """An acdc.present case: the held bundle and the disclosure in, and the body the holder must
    present with the secrets it must not carry, or a refusal (this.i 37ehqmh4)."""
    common = {"level": "INTEROP", "basis": basis, "choices": list(case["choices"])}
    if ev.body is None:
        why = "; ".join(f"{f.grade} ({f.reason})" for f in ev.result.findings)
        assertions = [{"id": "a1", "check": "present_refused", **common,
                       "note": f"The holder must refuse: {why}."}]
        hidden = "Every string of the held ACDC that its compact form hides, which a refusal "
    else:
        assertions = [{"id": "a1", "check": "presented", **common,
                       "note": "The body the disclosure asks for, byte for byte; the "
                               "attachments only need to be well formed.",
                       "expected": {"body": ev.body.hex()}}]
        hidden = "Every string of the held ACDC that the disclosure hides, which the response "
    if ev.secrets:
        assertions.append({"id": "a2", "check": "secrets_absent", **common,
                           "note": hidden + "must not carry.", "expected": ev.secrets})
    request = ev.bundle.request
    return {
        "schema_version": ac.SCHEMA_VERSION,
        "id": case["id"],
        "title": case["title"],
        "description": description,
        "status": case.get("status", BATCH_STATUS),
        "profile": PROFILE,
        "targets": {"wire": wire, "features": _features(ev)},
        "operation": "acdc.present",
        "input": {"perspective": {"role": "holder"}, "kels": request["kels"],
                  "registry": request["registry"], "schemas": request["schemas"],
                  "acdcs": request["acdcs"], "held": request["presented"],
                  "disclosure": ev.disclosure},
        "assertions": assertions,
        "provenance": {
            "scenario": f"{scenario_path}#{case['key']}",
            "generator": {"name": GENERATOR_NAME, "version": GENERATOR_VERSION},
            "reference": None,
        },
    }


def _features(ev: Evaluation) -> list[str]:
    """A sedi-1 credential is committed only through a blindable registry, so every case needs
    acdc.registry.bup, and one with an edge section needs acdc.edges, even an empty group with
    no edge in it; sedi-1 requires both of a claimant, so neither hides a case from an adapter
    that can claim the profile. A case with a presentation context needs acdc.presentation,
    which sedi-1 also requires."""
    features = {*ac.BASE_FEATURES, BUP}
    if ev.bundle.dag.get("edges") or any("e" in acdc for acdc in ev.bundle.expanded.values()):
        features.add(EDGES)
    if "presentation" in ev.bundle.request:
        features.add(PRESENTATION)
    return sorted(features)


def build_sedi_case(scenario_path: str, case: dict, ev: Evaluation, pairs: dict,
                    readings: dict[str, str]) -> dict:
    """The case a scenario describes. ``pairs`` maps each scenario key to (case id, verdict);
    ``readings`` maps each choice id to its reading."""
    key = case["key"]
    verdict = ev.result.verdict
    description = case["description"]
    if verdict != sm.VALID:
        pair = case.get("pair")
        if pair not in pairs:
            raise ScenarioError(f"{key}: a refusal names its positive pair, a scenario that "
                                f"differs only in the defect; {pair!r} is not one.")
        if pairs[pair][1] != sm.VALID:
            raise ScenarioError(f"{key}: its pair {pair} is {pairs[pair][1]} itself, so it is "
                                f"not a positive pair.")
        description += (f" Its positive pair is {pair} ({pairs[pair][0]}), which differs from it "
                        f"only in the defect.")
    elif "pair" in case:
        raise ScenarioError(f"{key}: is valid, so it is a positive scenario and names no pair.")
    unknown = [c for c in case["choices"] if c not in readings]
    if unknown:
        raise ScenarioError(f"{key}: names {', '.join(unknown)}, which {PROFILE} does not "
                            f"choose.")
    basis = " ".join(f"{PROFILE} {c}: {readings[c]}" for c in case["choices"])
    findings = "; ".join(f"{f.grade} ({f.reason})" for f in ev.result.findings)
    note = (f"The sedi-1 model finds {findings}, so the verdict is {verdict}." if findings
            else "The sedi-1 model finds nothing that keeps the ACDC from valid.")
    b = ev.bundle
    wire = ["CESR-2.00"] + ([ac.KERI_WIRE] if b.request["kels"] else []) + [ac.WIRE]
    if ev.disclosure is not None:
        return _holder_case(scenario_path, case, ev, description, basis, wire)
    return {
        "schema_version": ac.SCHEMA_VERSION,
        "id": case["id"],
        "title": case["title"],
        "description": description,
        "status": case.get("status", BATCH_STATUS),
        "profile": PROFILE,
        "targets": {"wire": wire, "features": _features(ev)},
        "operation": "acdc.verify",
        "input": b.case_input(),
        "assertions": [{"id": "a1", "check": "verdict", "level": "INTEROP", "basis": basis,
                        "choices": list(case["choices"]), "note": note, "expected": verdict}],
        "provenance": {
            "scenario": f"{scenario_path}#{key}",
            "generator": {"name": GENERATOR_NAME, "version": GENERATOR_VERSION},
            "reference": None,
        },
        "dag": b.dag,
        "as_of": b.as_of,
    }
