"""The CI level-2 baseline comparison: a regression fails, an improvement must update the
baseline, and an unchanged run passes."""

import json

import pytest

from kcs_adapter_keripy import baseline


def report(outcomes, profile="cesr-1.0", commit="abc"):
    """A minimal conformance report: {case id: {assertion id: outcome}}."""
    return {
        "filters": {"profile": profile},
        "hello": {"implementation": {"name": "keripy", "version": "2", "commit": commit}},
        "verdict": "conformant",
        "cases": [{"id": cid, "status": "active", "outcome": "pass",
                   "assertions": [{"id": aid, "level": "MUST", "outcome": out}
                                  for aid, out in assertions.items()]}
                  for cid, assertions in outcomes.items()],
    }


BASE = {"CESR-0001": {"a1": "pass"}, "CESR-0022": {"a1": "fail"}}


def test_summarize_keeps_only_what_the_comparison_needs():
    summary = baseline.summarize(report(BASE))
    assert summary == {
        "profile": "cesr-1.0",
        "implementation": {"name": "keripy", "version": "2", "commit": "abc"},
        "verdict": "conformant",
        "assertions": {"CESR-0001/a1": "pass", "CESR-0022/a1": "fail"},
    }


def test_an_unchanged_run_matches():
    assert baseline.compare(baseline.summarize(report(BASE)), report(BASE)) == ([], [])


def test_a_pass_that_no_longer_passes_is_a_regression():
    now = report({"CESR-0001": {"a1": "fail"}, "CESR-0022": {"a1": "fail"}})
    regressions, improvements = baseline.compare(baseline.summarize(report(BASE)), now)
    assert regressions == ["CESR-0001/a1: pass -> fail"]
    assert improvements == []


def test_a_new_pass_is_an_improvement():
    now = report({"CESR-0001": {"a1": "pass"}, "CESR-0022": {"a1": "pass"}})
    assert baseline.compare(baseline.summarize(report(BASE)), now) == (
        [], ["CESR-0022/a1: fail -> pass"])


def test_assertions_added_or_removed_need_the_baseline_updated():
    now = report({"CESR-0001": {"a1": "pass"}, "CESR-0099": {"a1": "pass"}})
    regressions, improvements = baseline.compare(baseline.summarize(report(BASE)), now)
    assert regressions == ["CESR-0022/a1: fail -> absent"]
    assert improvements == ["CESR-0099/a1: absent -> pass"]


def test_a_different_profile_is_a_regression():
    regressions, _ = baseline.compare(baseline.summarize(report(BASE)),
                                      report(BASE, profile="other"))
    assert regressions == ["profile: cesr-1.0 -> other"]


def test_a_different_implementation_commit_needs_the_baseline_updated():
    regressions, improvements = baseline.compare(baseline.summarize(report(BASE)),
                                                 report(BASE, commit="def"))
    assert regressions == []
    assert improvements == ["implementation commit: abc -> def"]


@pytest.fixture
def files(tmp_path):
    base, rep = tmp_path / "baseline.json", tmp_path / "report.json"
    base.write_text(json.dumps(baseline.summarize(report(BASE))))
    return base, rep


def test_main_exits_zero_when_the_run_matches(files, capsys):
    base, rep = files
    rep.write_text(json.dumps(report(BASE)))
    assert baseline.main(["compare", str(base), str(rep)]) == 0
    assert "matches the baseline" in capsys.readouterr().out


def test_main_exits_one_on_a_regression(files, capsys):
    base, rep = files
    rep.write_text(json.dumps(report({"CESR-0001": {"a1": "fail"}, "CESR-0022": {"a1": "fail"}})))
    assert baseline.main(["compare", str(base), str(rep)]) == 1
    out = capsys.readouterr().out
    assert "e.state.conflict.baseline-regression.f" in out and "CESR-0001/a1" in out


def test_main_exits_one_on_an_improvement_until_the_baseline_is_updated(files, capsys):
    base, rep = files
    rep.write_text(json.dumps(report({"CESR-0001": {"a1": "pass"}, "CESR-0022": {"a1": "pass"}})))
    assert baseline.main(["compare", str(base), str(rep)]) == 1
    assert "e.state.conflict.baseline-stale.f" in capsys.readouterr().out
    assert baseline.main(["write", str(base), str(rep)]) == 0
    assert baseline.main(["compare", str(base), str(rep)]) == 0


def test_main_refuses_bad_usage(capsys):
    assert baseline.main(["frobnicate"]) == 2
    assert "e.input.format.usage.f" in capsys.readouterr().err


@pytest.mark.filterwarnings("ignore:.*found in sys.modules:RuntimeWarning")
def test_it_runs_as_a_module(monkeypatch, capsys):
    import runpy
    import sys

    monkeypatch.setattr(sys, "argv", ["baseline"])
    with pytest.raises(SystemExit) as info:
        runpy.run_module("kcs_adapter_keripy.baseline", run_name="__main__")
    assert info.value.code == 2
