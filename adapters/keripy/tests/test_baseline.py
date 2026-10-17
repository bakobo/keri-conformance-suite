"""The CI level-2 baseline comparison: a regression fails, an improvement must update the
baseline, and an unchanged run passes. The baseline records the verdict, every case's outcome
and failure kind, and every assertion's outcome."""

import json
import os
import runpy
import subprocess
import sys

import pytest

from kcs_adapter_keripy import baseline

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
        "format": 2,
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
    assert regressions == ["verdict: aborted (an aborted run never satisfies the baseline)"]


# -- the command line

@pytest.fixture(autouse=True)
def no_embargo_list(monkeypatch, tmp_path):
    """No test reads the maintainer's own list: no variable, no global or system git config, and a
    working directory outside any checkout."""
    monkeypatch.delenv(baseline.ENV_PATTERNS, raising=False)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")


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


# -- the embargo gate (docs/profiles/sedi-test-plan.md, item 12)

def held_report(rep):
    rep.write_text(json.dumps(base_report()))


def test_write_refuses_a_case_on_the_embargo_list(files, tmp_path, monkeypatch, capsys):
    base, rep = files
    before = base.read_text()
    held_report(rep)
    listed = tmp_path / "list.txt"
    listed.write_text("# held\n\ncesr-0022\n")
    monkeypatch.setenv(baseline.ENV_PATTERNS, str(listed))
    assert run("write", base, rep) == 1
    err = capsys.readouterr().err
    assert "e.rule.embargo.f: The cases CESR-0022 are under embargo" in err
    assert base.read_text() == before


def test_write_goes_ahead_when_nothing_is_on_the_list(files, tmp_path, monkeypatch, capsys):
    base, rep = files
    held_report(rep)
    listed = tmp_path / "list.txt"
    listed.write_text("something else\n")
    monkeypatch.setenv(baseline.ENV_PATTERNS, str(listed))
    assert run("write", base, rep) == 0
    assert "patterns-missing" not in capsys.readouterr().err


def test_without_any_list_the_write_goes_ahead_and_says_so(files, capsys):
    base, rep = files
    held_report(rep)
    assert run("write", base, rep) == 0
    assert "w.rule.embargo.patterns-missing.f" in capsys.readouterr().err


@pytest.mark.parametrize("value", ["", "   ", "missing.txt", "bad-utf8",
                                   "~kcs-no-such-user-4c0d/list.txt"])
def test_a_configured_list_that_cannot_be_read_refuses(files, tmp_path, monkeypatch, capsys,
                                                       value):
    base, rep = files
    held_report(rep)
    if value == "bad-utf8":
        (tmp_path / "bad.txt").write_bytes(b"\xff\xfe")
        value = str(tmp_path / "bad.txt")
    elif value == "missing.txt":
        value = str(tmp_path / value)
    monkeypatch.setenv(baseline.ENV_PATTERNS, value)
    assert run("write", base, rep) == 2
    assert "e.input.format.embargo-patterns.f" in capsys.readouterr().err


def checkout(tmp_path):
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    return repo


@pytest.mark.parametrize("where", ["default", "relative", "absolute"])
def test_the_list_is_found_as_the_push_guard_finds_it(tmp_path, capsys, where):
    repo = checkout(tmp_path)
    if where == "default":
        listed = repo / ".git" / "info" / "embargo-patterns.txt"
        listed.parent.mkdir(exist_ok=True)
    else:
        listed = repo / "held.txt"
        name = "held.txt" if where == "relative" else str(listed)
        subprocess.run(["git", "-C", str(repo), "config", "kcs.embargoPatterns", name],
                       check=True)
    listed.write_text("CESR-0022\n")
    base, rep = repo / "baseline.json", repo / "report.json"
    held_report(rep)
    assert run("write", base, rep) == 1
    assert not base.exists()
    assert "e.rule.embargo.f" in capsys.readouterr().err


def test_a_checkout_with_no_list_goes_ahead(tmp_path):
    repo = checkout(tmp_path)
    base, rep = repo / "baseline.json", repo / "report.json"
    held_report(rep)
    assert run("write", base, rep) == 0


def test_without_git_there_is_no_default_list(files, monkeypatch, capsys):
    def no_git(*args, **kw):
        raise FileNotFoundError("git")

    monkeypatch.setattr(baseline.subprocess, "run", no_git)
    base, rep = files
    held_report(rep)
    assert run("write", base, rep) == 0
    assert "patterns-missing" in capsys.readouterr().err


def test_a_baseline_written_outside_the_checkout_is_still_checked(tmp_path, monkeypatch, capsys):
    repo = checkout(tmp_path)
    listed = repo / ".git" / "info" / "embargo-patterns.txt"
    listed.parent.mkdir(exist_ok=True)
    listed.write_text("CESR-0022\n")
    monkeypatch.chdir(repo)
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    base, rep = outside / "baseline.json", outside / "report.json"
    held_report(rep)
    assert run("write", base, rep) == 1
    assert not base.exists()


def test_a_dangling_default_list_refuses(tmp_path, capsys):
    repo = checkout(tmp_path)
    listed = repo / ".git" / "info" / "embargo-patterns.txt"
    listed.parent.mkdir(exist_ok=True)
    listed.symlink_to(tmp_path / "gone.txt")
    base, rep = repo / "baseline.json", repo / "report.json"
    held_report(rep)
    assert run("write", base, rep) == 2
    assert "e.input.format.embargo-patterns.f" in capsys.readouterr().err


@pytest.mark.parametrize("value", ["held.txt ", ""])
def test_a_configured_name_is_used_exactly_as_written(tmp_path, capsys, value):
    repo = checkout(tmp_path)
    (repo / "held.txt").write_text("nothing held\n")
    (repo / "held.txt ").write_text("CESR-0022\n")
    subprocess.run(["git", "-C", str(repo), "config", "kcs.embargoPatterns", value], check=True)
    base, rep = repo / "baseline.json", repo / "report.json"
    held_report(rep)
    assert run("write", base, rep) == (1 if value else 2)
    assert not base.exists()


def test_a_git_config_that_cannot_be_read_refuses(tmp_path, monkeypatch, capsys):
    repo = checkout(tmp_path)
    real = subprocess.run

    def broken_config(argv, **kw):
        if "config" in argv:
            return subprocess.CompletedProcess(argv, 128, b"", b"fatal: bad config")
        return real(argv, **kw)

    monkeypatch.setattr(baseline.subprocess, "run", broken_config)
    base, rep = repo / "baseline.json", repo / "report.json"
    held_report(rep)
    assert run("write", base, rep) == 2
    assert "could not be read" in capsys.readouterr().err


def configure_by_environment(monkeypatch, value: bytes):
    """Set kcs.embargoPatterns through git's environment, which can carry any bytes."""
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "kcs.embargoPatterns")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", os.fsdecode(value))


def test_a_carriage_return_in_the_configured_name_is_kept(tmp_path, monkeypatch):
    repo = checkout(tmp_path)
    (repo / "held\r.txt").write_text("CESR-0022\n")
    (repo / "held\n.txt").write_text("nothing held\n")
    configure_by_environment(monkeypatch, b"held\r.txt")
    base, rep = repo / "baseline.json", repo / "report.json"
    held_report(rep)
    assert run("write", base, rep) == 1
    assert not base.exists()


def test_a_configured_name_that_is_not_utf8_is_read_as_a_file_name(tmp_path, monkeypatch,
                                                                    capsys):
    repo = checkout(tmp_path)
    configure_by_environment(monkeypatch, b"\xff")
    base, rep = repo / "baseline.json", repo / "report.json"
    held_report(rep)
    assert run("write", base, rep) == 2  # no file of that name: the coded refusal, not a crash
    assert "e.input.format.embargo-patterns.f" in capsys.readouterr().err
    (repo / os.fsdecode(b"\xff")).write_text("CESR-0022\n")
    assert run("write", base, rep) == 1
