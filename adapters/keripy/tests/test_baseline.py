"""The CI level-2 baseline comparison: a regression fails, an improvement must update the
baseline, and an unchanged run passes. The baseline records the verdict, every case's outcome
and failure kind, and every assertion's outcome."""

import json
import runpy
import sys

import pytest

from kcs_adapter_keripy import baseline

IMPL = {"name": "keripy", "version": "2", "commit": "abc"}


def case(cid, outcome="pass", failure=None, **assertions):
    return {"id": cid, "status": "active", "outcome": outcome,
            "failure": None if failure is None else {"kind": failure, "detail": "..."},
            "assertions": [{"id": aid, "level": "MUST", "outcome": out}
                           for aid, out in (assertions or {"a1": "pass"}).items()]}


def report(*cases, profile="cesr-1.0", commit="abc", verdict="conformant"):
    return {"filters": {"profile": profile},
            "hello": {"implementation": {**IMPL, "commit": commit}},
            "verdict": verdict, "cases": list(cases)}


def base_report(**kw):
    return report(case("CESR-0001"), case("CESR-0022", "fail", a1="fail"), **kw)


def summary(**kw):
    return baseline.summarize(base_report(**kw))


def test_summarize_keeps_verdict_case_outcomes_failure_kinds_and_assertions():
    assert summary() == {
        "format": 2,
        "profile": "cesr-1.0",
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
    assert regressions == ["profile: cesr-1.0 -> other"]


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
    assert regressions == ["verdict: aborted (an aborted run never satisfies the baseline)"]


# -- the command line

@pytest.fixture
def files(tmp_path):
    base, rep = tmp_path / "baseline.json", tmp_path / "report.json"
    base.write_text(json.dumps(summary()))
    return base, rep


def run(*args):
    return baseline.main([*map(str, args)])


def test_main_exits_zero_when_the_run_matches(files, capsys):
    base, rep = files
    rep.write_text(json.dumps(base_report()))
    assert run("compare", base, rep) == 0
    assert "matches the baseline" in capsys.readouterr().out


def test_main_exits_one_on_a_regression(files, capsys):
    base, rep = files
    rep.write_text(json.dumps(report(case("CESR-0001"),
                                     case("CESR-0022", "fail", "exited", a1="fail"))))
    assert run("compare", base, rep) == 1
    out = capsys.readouterr().out
    assert "e.state.conflict.baseline-regression.f: CESR-0022: failure none -> exited" in out


def test_main_exits_one_on_an_improvement_until_the_baseline_is_updated(files, capsys):
    base, rep = files
    rep.write_text(json.dumps(report(case("CESR-0001"), case("CESR-0022"))))
    assert run("compare", base, rep) == 1
    assert "e.state.conflict.baseline-stale.f" in capsys.readouterr().out
    assert run("write", base, rep) == 0
    assert run("compare", base, rep) == 0


def test_main_fails_an_aborted_run(files, capsys):
    base, rep = files
    rep.write_text(json.dumps(base_report(verdict="aborted")))
    assert run("compare", base, rep) == 1
    assert "verdict: aborted (an aborted run never satisfies" in capsys.readouterr().out


def test_write_refuses_to_record_an_aborted_report(files, capsys):
    base, rep = files
    before = base.read_text()
    rep.write_text(json.dumps(base_report(verdict="aborted")))
    assert run("write", base, rep) == 1
    assert "e.input.range.aborted-report.f" in capsys.readouterr().err
    assert base.read_text() == before


def test_main_refuses_bad_usage(capsys):
    assert baseline.main(["frobnicate"]) == 2
    assert "e.input.format.usage.f" in capsys.readouterr().err


@pytest.mark.filterwarnings("ignore:.*found in sys.modules:RuntimeWarning")
def test_it_runs_as_a_module(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["baseline"])
    with pytest.raises(SystemExit) as info:
        runpy.run_module("kcs_adapter_keripy.baseline", run_name="__main__")
    assert info.value.code == 2
