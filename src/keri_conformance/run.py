"""`kcs run`: send every case to the adapter, evaluate its assertions, and build the report.

Outcomes, per assertion: pass, fail, not-implemented (this runner version cannot evaluate the
check), not-supported (the adapter did not declare what the case needs, so nothing was sent), or
skipped (the case is deprecated). A case's outcome is fail if any assertion failed, incomplete if
none failed but one could not be evaluated, pass otherwise, or not-supported/skipped.

Only MUST assertions in active cases decide the verdict. Draft and disputed cases are run and
reported but never decide it, and not-supported cases are listed: the claim is scoped to the
features the adapter declared. A run in which no active MUST assertion passed or failed is
no-evidence, never conformant; a run cut short because a restarted adapter refused hello or
changed it is aborted, and its report holds the cases completed before that.
"""

from keri_conformance import __version__
from keri_conformance.assertions import evaluate
from keri_conformance.errors import HelloRefused
from keri_conformance.protocol import PROTOCOL_VERSION
from keri_conformance.session import AdapterSession, Failure

VERDICT_EXIT = {"conformant": 0, "not-conformant": 1, "aborted": 3, "incomplete": 4,
                "no-evidence": 5}
# Session probes the design calls for that this runner cannot perform yet; listed in every report
# so that their absence is visible.
PROBES = {"statelessness": "not-yet-available"}


def _record(assertion, outcome, actual=None, detail=None, self_agreement=False):
    return {
        "id": assertion["id"],
        "check": assertion["check"],
        "level": assertion["level"],
        "outcome": outcome,
        "expected": assertion.get("expected"),
        "actual": actual,
        "detail": detail,
        "self_agreement": self_agreement,
    }


def _case_outcome(records) -> str:
    outcomes = {r["outcome"] for r in records}
    if "fail" in outcomes:
        return "fail"
    if "not-implemented" in outcomes:
        return "incomplete"
    return "pass"


def run_case(session: AdapterSession, case: dict) -> dict:
    """Run one case and return its entry in the report."""
    hello = session.hello
    entry = {"id": case["id"], "status": case["status"], "profile": case["profile"],
             "operation": case["operation"], "failure": None, "stderr": ""}
    missing = [f for f in case["targets"]["features"] if f not in hello["features"]]
    if case["status"] == "deprecated":
        entry["outcome"] = "skipped"
    elif case["operation"] not in hello["operations"]:
        entry["outcome"] = "not-supported"
        entry["missing_operation"] = case["operation"]
    elif missing:
        entry["outcome"] = "not-supported"
        entry["missing_features"] = missing
    if "outcome" in entry:
        entry["assertions"] = [_record(a, entry["outcome"]) for a in case["assertions"]]
        return entry

    outcome = session.request(case["operation"], case["input"])
    entry["stderr"] = session.take_stderr()
    if isinstance(outcome, Failure):
        entry["failure"] = {"kind": outcome.kind, "detail": outcome.detail}
        records = [_record(a, "fail", detail=outcome.detail) for a in case["assertions"]]
    else:
        reference = case["provenance"].get("reference")
        self_reference = (reference is not None
                          and reference["implementation"] == hello["implementation"]["name"])
        records = []
        for assertion in case["assertions"]:
            evaluation = evaluate(assertion, outcome.result)
            records.append(_record(assertion, evaluation.outcome, evaluation.actual,
                                   evaluation.detail,
                                   self_reference and evaluation.outcome == "pass"))
    entry["assertions"] = records
    entry["outcome"] = _case_outcome(records)
    return entry


def summarize(entries: list[dict]) -> tuple[dict, str]:
    """Counts per status, level and outcome; and the verdict."""
    counts: dict = {}
    for entry in entries:
        for record in entry["assertions"]:
            by_level = counts.setdefault(entry["status"], {}).setdefault(record["level"], {})
            by_level[record["outcome"]] = by_level.get(record["outcome"], 0) + 1
    must = counts.get("active", {}).get("MUST", {})
    if must.get("fail"):
        verdict = "not-conformant"
    elif must.get("not-implemented"):
        verdict = "incomplete"
    elif not must.get("pass"):
        verdict = "no-evidence"
    else:
        verdict = "conformant"
    summary = {
        "counts": counts,
        "not_supported_active": [e["id"] for e in entries
                                 if e["status"] == "active" and e["outcome"] == "not-supported"],
        "self_agreement_passes": sum(r["self_agreement"] for e in entries
                                     for r in e["assertions"]),
    }
    return summary, verdict


def run_suite(session: AdapterSession, cases: list[dict], *, profile: str | None,
              cases_dir: str) -> dict:
    """Run the cases (filtered by profile) and return the conformance report."""
    session_stderr = session.take_stderr()
    entries, aborted = [], None
    for case in cases:
        if profile is not None and case["profile"] != profile:
            continue
        try:
            entries.append(run_case(session, case))
        except HelloRefused as refusal:
            aborted = {"code": refusal.code, "reason": refusal.message,
                       "problems": refusal.problems, "at_case": case["id"]}
            break
    summary, verdict = summarize(entries)
    if aborted:
        verdict = "aborted"
    hello = session.hello
    return {
        "report_version": 1,
        "runner_version": __version__,
        "suite_version": __version__,
        "protocol_version": PROTOCOL_VERSION,
        "hello": hello,
        "declared_features": hello["features"],
        "composes": hello.get("composes", []),
        "filters": {"profile": profile, "cases_dir": cases_dir},
        "session_stderr": session_stderr,
        "verdict": verdict,
        "aborted": aborted,
        "probes": dict(PROBES),
        "summary": summary,
        "cases": entries,
    }


def human_summary(report: dict, report_path: str | None) -> str:
    """A few lines for a person reading the terminal."""
    hello = report["hello"]
    adapter, impl = hello["adapter"], hello["implementation"]
    outcomes: dict = {}
    for entry in report["cases"]:
        outcomes[entry["outcome"]] = outcomes.get(entry["outcome"], 0) + 1
    must = report["summary"]["counts"].get("active", {}).get("MUST", {})
    composes = report["composes"]
    lines = [
        f"kcs {report['runner_version']}: {adapter['name']} {adapter['version']} for "
        f"{impl['name']} {impl['version']} ({impl['commit']})"
        + (f", composing {', '.join(composes)}" if composes else ""),
        "cases: " + (", ".join(f"{n} {k}" for k, n in sorted(outcomes.items())) or "none"),
        "active MUST assertions: "
        + (", ".join(f"{n} {k}" for k, n in sorted(must.items())) or "none"),
        f"verdict: {report['verdict']}",
    ]
    if report_path:
        lines.append(f"report: {report_path}")
    return "\n".join(lines)
