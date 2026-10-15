"""The outcome comparison behind scripts/reproduce-results check: a regression fails, an
improvement must refresh the committed result, and an unchanged run matches. What is compared is
the verdict, every case's outcome and failure kind, and every assertion's outcome."""

import json

from tools import outcomes as baseline

IMPL = {"name": "keripy", "version": "2", "commit": "abc"}


def case(cid, outcome="pass", failure=None, **assertions):
    return {"id": cid, "status": "active", "outcome": outcome,
            "failure": None if failure is None else {"kind": failure, "detail": "..."},
            "assertions": [{"id": aid, "level": "MUST", "outcome": out}
                           for aid, out in (assertions or {"a1": "pass"}).items()]}


def report(*cases, profile="cesr-v1.0", commit="abc", verdict="conformant"):
    return {"filters": {"profile": profile},
            "hello": {"implementation": {**IMPL, "commit": commit}},
            "verdict": verdict, "cases": list(cases)}


def base_report(**kw):
    return report(case("CESR-0001"), case("CESR-0022", "fail", a1="fail"), **kw)


def summary(**kw):
    return baseline.summarize(base_report(**kw))


def test_summarize_keeps_verdict_case_outcomes_failure_kinds_and_assertions():
    assert summary() == {
        "profile": "cesr-v1.0",
        "implementation": IMPL,
        "verdict": "conformant",
        "cases": {
            "CESR-0001": {"outcome": "pass", "failure": None, "assertions": {"a1": "pass"}},
            "CESR-0022": {"outcome": "fail", "failure": None, "assertions": {"a1": "fail"}},
        },
    }


def test_an_unchanged_run_matches():
    assert baseline.compare(summary(), base_report()) == ([], [])


def test_a_pass_that_no_longer_passes_is_a_regression():
    now = report(case("CESR-0001", "fail", a1="fail"), case("CESR-0022", "fail", a1="fail"))
    regressions, improvements = baseline.compare(summary(), now)
    assert regressions == ["CESR-0001: outcome pass -> fail", "CESR-0001/a1: pass -> fail"]
    assert improvements == []


def test_a_case_that_starts_crashing_is_a_regression_though_it_still_fails():
    # CESR-0022 still fails and the verdict is still conformant: only the failure kind changed.
    now = report(case("CESR-0001"), case("CESR-0022", "fail", "exited", a1="fail"))
    regressions, improvements = baseline.compare(summary(), now)
    assert regressions == ["CESR-0022: failure none -> exited"]
    assert improvements == []


def test_a_different_failure_kind_is_a_regression():
    base = baseline.summarize(report(case("CESR-0022", "fail", "timeout", a1="fail")))
    now = report(case("CESR-0022", "fail", "malformed", a1="fail"))
    assert baseline.compare(base, now) == (["CESR-0022: failure timeout -> malformed"], [])


def test_a_case_that_stops_crashing_is_an_improvement_to_record():
    base = baseline.summarize(report(case("CESR-0022", "fail", "error-harness", a1="fail")))
    now = report(case("CESR-0022", "fail", a1="fail"))
    assert baseline.compare(base, now) == ([], ["CESR-0022: failure error-harness -> none"])


def test_a_new_pass_is_an_improvement():
    now = report(case("CESR-0001"), case("CESR-0022"))
    assert baseline.compare(summary(), now) == (
        [], ["CESR-0022: outcome fail -> pass", "CESR-0022/a1: fail -> pass"])


def test_cases_and_assertions_added_or_removed():
    now = report(case("CESR-0001", a1="pass", a2="pass"), case("CESR-0099"))
    regressions, improvements = baseline.compare(summary(), now)
    assert regressions == ["CESR-0022: absent from the run"]
    assert improvements == ["CESR-0001/a2: absent -> pass", "CESR-0099: new case"]


def test_an_assertion_that_disappears_is_a_regression():
    base = baseline.summarize(report(case("CESR-0001", a1="pass", a2="pass")))
    assert baseline.compare(base, report(case("CESR-0001"))) == (
        ["CESR-0001/a2: pass -> absent"], [])


def test_a_different_profile_is_a_regression():
    regressions, _ = baseline.compare(summary(), base_report(profile="other"))
    assert regressions == ["profile: cesr-v1.0 -> other"]


def test_a_different_implementation_commit_needs_the_baseline_updated():
    assert baseline.compare(summary(), base_report(commit="def")) == (
        [], ["implementation commit: abc -> def"])


def test_a_different_verdict_is_a_regression():
    assert baseline.compare(summary(), base_report(verdict="no-evidence")) == (
        ["verdict: conformant -> no-evidence"], [])


def test_a_verdict_that_becomes_conformant_is_an_improvement():
    assert baseline.compare(summary(verdict="not-conformant"), base_report()) == (
        [], ["verdict: not-conformant -> conformant"])


def test_a_non_normative_run_that_becomes_interoperable_is_an_improvement():
    # A non-normative profile's verdict says whether the implementation interoperates.
    assert baseline.compare(summary(verdict="no-evidence"), base_report(verdict="interoperable")) \
        == ([], ["verdict: no-evidence -> interoperable"])


def test_a_run_that_stops_interoperating_is_a_regression():
    assert baseline.compare(summary(verdict="interoperable"),
                            base_report(verdict="not-interoperable")) == (
        ["verdict: interoperable -> not-interoperable"], [])


def test_the_interop_verdicts_are_ones_kcs_reports():
    assert {"interoperable", "not-interoperable"} <= baseline.VERDICTS


def test_an_aborted_run_is_a_regression_even_against_an_aborted_baseline():
    regressions, _ = baseline.compare(summary(verdict="aborted"), base_report(verdict="aborted"))
    assert regressions == ["verdict: aborted (an aborted run never matches a committed result)"]


# -- reading the files


def test_a_committed_result_is_read_as_the_summary_of_its_report(tmp_path):
    path = tmp_path / "result.json"
    path.write_text(json.dumps({"result_version": 1, "provenance": {}, "report": base_report()}))
    assert baseline.read_committed(path) == summary()


def test_a_report_is_read_and_checked(tmp_path):
    path = tmp_path / "report.json"
    path.write_text(json.dumps(base_report()))
    assert baseline.read_report(path) == base_report()
