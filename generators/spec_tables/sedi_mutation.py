"""Mutation acceptance for sedi-1 (test-plan item 15): for each profile choice, a deliberately wrong
variant of the reference model is run over every sedi-1 scenario, and the cases whose outcome it
changes are recorded. A choice's mutant must change the outcome of at least one case that rests on
that choice, which shows the cases would catch a verifier, issuer or holder that gets the choice
wrong; branch coverage only shows that code ran.

A case's outcome is its verdict, and for a holder case also the body it must present. Most mutants
are a verifier that skips one check, made by dropping that check's findings from the model's
answer; the rest replace one function the model reads with a wrong one. A choice no case rests on
yet (a draft's open side) has no mutant run against it and is listed as such.
"""

import copy
import pathlib
from unittest import mock

from . import acdc_build, sedi_cases, sedi_issue, sedi_present
from . import acdc_cases as ac
from . import sedi_model as sm
from .errors import E_SCENARIO, GeneratorError, ScenarioError
from .regenerate import SEDI_RELEASED, SEDI_SOURCE, _load_json

DOC = "docs/profiles/sedi-mutation.md"


def _dropping(*reasons):
    """A verifier that never makes the checks whose findings carry ``reasons``."""
    evaluate = sm.evaluate

    def wrong(t, request, trunks=None):
        result = evaluate(t, request, trunks)
        kept = [f for f in result.findings if f.reason not in reasons]
        return sm.Result(sm.combine([f.grade for f in kept]), kept, result.head)

    return mock.patch.object(sm, "evaluate", wrong)


def _grading(change):
    """A verifier whose verdict ``change`` rewrites."""
    evaluate = sm.evaluate

    def wrong(t, request, trunks=None):
        result = evaluate(t, request, trunks)
        return sm.Result(change(result.verdict), result.findings, result.head)

    return mock.patch.object(sm, "evaluate", wrong)


def _near_only():
    """A verifier that judges the presented ACDC and its own edges' checks, but never lets a far
    node's own verdict reach it: the opposite of chain-strict."""
    evaluate = sm.evaluate

    def wrong(t, request, trunks=None):
        result = evaluate(t, request, trunks)
        parsed = sm._parse(t, bytes.fromhex(request["presented"]["stream"]))
        said = parsed[0].get("d") if parsed and isinstance(parsed[0], dict) else None
        kept = [f for f in result.findings if f.where.split(".")[0] in (said, "presented")]
        return sm.Result(sm.combine([f.grade for f in kept]), kept, result.head)

    return mock.patch.object(sm, "evaluate", wrong)


def _unresolved_first(grades, operator="AND"):
    """combine with something unevaluable outranking a failure."""
    if operator == "OR" and sm.VALID in grades:
        return sm.VALID
    for grade in (sm.INCOMPLETE, sm.INVALID):
        if grade in grades:
            return grade
    return sm.VALID


def _operators(change):
    operators = sm.operators
    return mock.patch.object(sm, "operators", lambda o: change(o, operators))


def _scalar_only(o, operators):
    return (None, sm.INCOMPLETE) if isinstance(o, list) else operators(o)


def _earliest_wins(o, operators):
    ops, bad = operators(o)
    return (list(reversed(ops)) if ops else ops), bad


def _issuee(change):
    issuee = sm.issuee
    return mock.patch.object(sm, "issuee", lambda body: change(body, issuee))


def _issuee_at_first_block(body, issuee):
    if isinstance(body, dict) and isinstance(body.get("A"), list) and body["A"]:
        return issuee({"A": [None, body["A"][0]]})
    return issuee(body)


def _untargeted_unbound(body, issuee):
    who = issuee(body)
    return ... if who is None else who


def _any_disclosure(held, expanded, disclosure):
    shown, why = _FORM(held, expanded, disclosure)
    return (shown, None) if why is None else ("compact", None)


_FORM = sedi_present.form

# One mutant per choice: what the wrong variant does, and how to make it.
MUTANTS = {
    "tel-sequence": ("accepts an update whose n skips its prior's plus one",
                     lambda: _dropping("bup-sequence")),
    "registry-head": ("accepts two anchored updates at one n",
                      lambda: _dropping("registry-duplicity")),
    "registry-evidence": ("ignores registry evidence it cannot account for",
                          lambda: _dropping("registry-unseen", "registry-gap", "registry-state")),
    "direct-issuance": ("takes a digest seal as committing a credential whatever its schema",
                        lambda: mock.patch.object(sm, "forbids_rd", lambda schema: True)),
    "revoked": ("accepts a revoked credential", lambda: _dropping("revoked")),
    "seal-shape": ("accepts any seal shape naming the update",
                   lambda: _dropping("bup-anchor", "rip-anchor")),
    "seal-couple-code": ("reads attachments it should refuse",
                         lambda: _dropping("bup-attachments", "rip-attachments", "attachments")),
    "blind-state-code": ("reads attachments it should refuse",
                         lambda: _dropping("bup-attachments", "rip-attachments", "attachments")),
    "edge-said": ("does not require an edge's own SAID", lambda: _dropping("edge-said", "said")),
    "unknown-operator": ("evaluates past an operator it does not know",
                         lambda: _dropping("operator-unknown")),
    "default-operator": ("never applies the default operator",
                         lambda: _dropping("i2i-issuee")),
    "operator-list": ("reads o only as a string", lambda: _operators(_scalar_only)),
    "operator-shape": ("lets the earliest of conflicting operators win",
                       lambda: _operators(_earliest_wins)),
    "chain-strict": ("ignores a far node's own verdict",
                     lambda: _near_only()),
    "presenter-binding": ("does not check the presenter", lambda: _dropping("presenter")),
    "aggregate-issuee": ("reads an aggregate's issuee at A[0]",
                         lambda: _issuee(_issuee_at_first_block)),
    "bearer-untargeted": ("treats an untargeted credential as unbound",
                          lambda: _issuee(_untargeted_unbound)),
    "issuer-issues": ("issues whatever it is asked",
                      lambda: mock.patch.object(sedi_issue, "refusal",
                                                lambda schemas, request: None)),
    "holder-presents": ("presents the compact form instead of refusing",
                        lambda: mock.patch.object(sedi_present, "form", _any_disclosure)),
    "unresolved-grading": ("accepts what it cannot evaluate",
                           lambda: _grading(lambda v: sm.VALID if v == sm.INCOMPLETE else v)),
    "valid-is-interop": ("refuses everything", lambda: _grading(lambda v: sm.INVALID)),
    "failure-precedence": ("lets something it cannot evaluate outrank a failure",
                           lambda: mock.patch.object(sm, "combine", _unresolved_first)),
    "bounds": ("holds to no maxima",
               lambda: _dropping("bound-registry-events", "bound-aggregate-blocks",
                                 "bound-edge-group-depth", "bound-operator-list",
                                 "bound-attribute-bytes", "bound-salt-chars")),
    "no-1x": ("accepts the 1.x forms",
              lambda: _dropping("unframeable", "field-order", "no-registry")),
}


def _scenarios(root: pathlib.Path):
    skip = {pathlib.PurePath(SEDI_SOURCE).name, pathlib.PurePath(SEDI_RELEASED).name}
    for path in sorted((root / "scenarios" / "sedi").glob("*.json")):
        if path.name in skip:
            continue
        doc = _load_json(path)  # read with the generator's size bound
        for case in doc["cases"]:
            yield doc.get("fixtures", {}), case


def _outcome(t, fixtures, case, bundle=None):
    """A case's outcome under whatever model is in force: its verdict, and for a holder case its
    presented body. A verifier case's bundle, once built, is reused."""
    frag = ac.compose(fixtures, case)
    if "issue" in case:
        return (sedi_cases.IssuerEvaluation(t, frag, case["issue"]).result.verdict, None), None
    if "disclosure" in case:
        ev = sedi_cases.HolderEvaluation(t, frag, case["disclosure"])
        return (ev.result.verdict, ev.body), None
    bundle = bundle or acdc_build.build_bundle(t, frag)
    return (sm.evaluate(t, bundle.request).verdict, None), bundle


def run(t, root: pathlib.Path, only: set[str] | None = None) -> dict:
    """For each choice (or each in ``only``), its mutant and the cases resting on it whose outcome
    the mutant changes."""
    cases = [(fixtures, copy.deepcopy(case)) for fixtures, case in _scenarios(root)
             if only is None or only & set(case["choices"])]
    baseline, bundles = {}, {}
    for fixtures, case in cases:
        if case["id"] in baseline:
            # Outcomes are kept by case id, so two cases sharing one would be compared with each
            # other's; the generator refuses such scenarios too.
            raise ScenarioError(f"The case id {case['id']} is used twice in the sedi "
                                f"scenarios.")
        baseline[case["id"]], bundles[case["id"]] = _outcome(t, fixtures, case)
    source = _load_json(root / SEDI_SOURCE)
    out = {}
    for choice in (c["id"] for c in source["choices"] if only is None or c["id"] in only):
        resting = [(f, c) for f, c in cases if choice in c["choices"]]
        if choice not in MUTANTS or not resting:
            # A choice with cases but no mutant keeps its cases, so the gate sees it uncaught.
            out[choice] = {"mutant": MUTANTS.get(choice, (None,))[0],
                           "cases": sorted(c["id"] for _, c in resting), "caught_by": []}
            continue
        what, make = MUTANTS[choice]
        caught = []
        with make():
            for fixtures, case in resting:
                got, _ = _outcome(t, fixtures, case, bundles[case["id"]])
                if got != baseline[case["id"]]:
                    caught.append(case["id"])
        out[choice] = {"mutant": what, "cases": sorted(c["id"] for _, c in resting),
                       "caught_by": sorted(caught)}
    return out


def render(matrix: dict) -> str:
    intro = ("For each sedi-1 choice, a deliberately wrong variant of the reference model and the "
             "cases resting on that choice whose outcome it changes (test-plan item 15). Every "
             "choice with cases must have at least one. Generated by "
             "`generators/spec_tables/sedi_mutation.py`; do not edit.")
    lines = ["# sedi-1 mutation acceptance", "", intro, "",
             "| Choice | Wrong variant | Cases resting on it | Caught by |",
             "| --- | --- | --- | --- |"]
    for choice, row in matrix.items():
        what = row["mutant"] or "none yet"
        cases = ", ".join(row["cases"]) or "none yet"
        caught = ", ".join(row["caught_by"]) or ("none" if row["cases"] else "")
        lines.append(f"| `{choice}` | {what} | {cases} | {caught} |")
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    """Write docs/profiles/sedi-mutation.md, or with --check say whether it is current. Exits 0
    when written or current, 1 when not current, and 3 with the coded error when the scenarios
    cannot be read, as scripts/regenerate does."""
    import argparse
    import sys

    from . import spec_source, tables

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    root = pathlib.Path(__file__).resolve().parents[2]
    try:
        text = render(run(tables.load(spec_source.load_spec()), root))
    except GeneratorError as e:
        print(str(e), file=sys.stderr)
        return 3
    except (ValueError, KeyError, TypeError, LookupError, AttributeError, OSError) as e:
        # A scenario that is not JSON or not shaped as one; scripts/regenerate refuses it too.
        print(f"{E_SCENARIO}: the sedi scenarios cannot be read: {type(e).__name__}: {e}",
              file=sys.stderr)
        return 3
    path = root / DOC
    if args.check:
        current = path.read_text(encoding="utf-8") if path.exists() else ""
        if current != text:
            print(f"{DOC} is not what the scenarios generate; run "
                  "`uv run python scripts/sedi-mutation`.", file=sys.stderr)
            return 1
        return 0
    path.write_text(text, encoding="utf-8")
    return 0
