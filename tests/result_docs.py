"""Builders for published results: a small, internally consistent runner report and its envelope.

The report is assembled the way run_suite assembles one, and its summary comes from the runner's
own summarize, so a test that breaks consistency does so on purpose.
"""

import copy

from keri_conformance.run import summarize


def record(aid="a1", level="MUST", outcome="pass", self_agreement=False, detail=None):
    return {"id": aid, "check": "rejected", "level": level, "outcome": outcome,
            "expected": None, "actual": {"reject": {"class": "x"}} if outcome == "pass" else None,
            "detail": detail, "self_agreement": self_agreement}


def case(cid="CESR-0001", status="active", outcome="pass", records=None, profile="cesr-1.0"):
    records = [record()] if records is None else records
    return {"id": cid, "status": status, "profile": profile, "operation": "cesr.parse",
            "failure": None, "stderr": "", "outcome": outcome, "assertions": records}


def report(cases=None, *, profile="cesr-1.0", name="keripy", version="2.1.0.dev1",
           suite_version="0.0.1", composes=None, aborted=None):
    cases = [case()] if cases is None else cases
    summary, verdict = summarize(cases)
    hello = {"protocol": 1, "adapter": {"name": "kcs-adapter-keripy", "version": "0.1.0"},
             "implementation": {"name": name, "version": version, "commit": "9a8b7aa"},
             "operations": ["cesr.parse"], "features": ["cesr.genus-2.00"],
             "composes": list(composes or [])}
    return {
        "report_version": 1, "runner_version": "0.0.1", "suite_version": suite_version,
        "protocol_version": 1, "supported_protocols": [1], "negotiated_protocol": 1,
        "hello": hello, "declared_features": hello["features"],
        "composes": list(composes or []),
        "filters": {"profile": profile, "cases_dir": "cases"}, "session_stderr": "",
        "verdict": "aborted" if aborted else verdict, "aborted": aborted,
        "probes": {"statelessness": "not-yet-available"}, "summary": summary,
        "cases": cases,
    }


SUBMITTED = {"kind": "submitted", "submitter": "Jane Maintainer",
             "pull_request": "https://github.com/bakobo/keri-conformance-suite/pull/7",
             "date": "2026-10-09"}
REPRODUCED = {"kind": "reproduced",
              "run": "https://github.com/bakobo/keri-conformance-suite/actions/runs/123",
              "commit": "0" * 40, "date": "2026-10-09"}


def result(rep=None, provenance=None):
    return {"result_version": 1, "provenance": copy.deepcopy(provenance or SUBMITTED),
            "report": rep if rep is not None else report()}
