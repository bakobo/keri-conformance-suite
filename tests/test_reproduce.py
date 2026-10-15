"""tools/reproduce.py: refresh, check, readmes and reproduce for the shipped adapters' committed
results. Adapter runs are replaced by a function that writes a prepared report, except in the one
test that drives the real runner against a fake adapter."""

import json
import os
import subprocess
import sys

import pytest
from conftest import FAKES, ROOT
from result_docs import MAINTAINER_RUN, SUBMITTED, case, record, report, result

from keri_conformance.errors import RunnerError
from tools import reproduce as P
from tools.results import result_path

ALPHA = P.Instance("alpha", "adapters/alpha/bin/run", ("cesr-v1.0", "keri-v1.0.1"),
                   "kcs-adapter-keripy", "adapters/alpha/README.md")
BETA = P.Instance("beta", "adapters/beta/bin/run", ("cesr-v1.0",), "kcs-adapter-beta",
                  "adapters/beta/README.md")
TABLE = f"intro\n\n{P.BEGIN}\nold\n{P.END}\n\nmore\n"


def keri_report(**kw):
    return report([case("KERI-0001", profile="keri-v1.0.1")], profile="keri-v1.0.1", **kw)


class Runs:
    """Stands in for kcs_run: writes the report it holds for (executable name, profile)."""

    def __init__(self, reports, skip=()):
        self.reports, self.skip, self.calls = reports, set(skip), []

    def __call__(self, repo, executable, profile, out):
        adapter = executable.parts[-3]
        self.calls.append((adapter, profile))
        if (adapter, profile) not in self.skip:
            out.write_text(json.dumps(self.reports[(adapter, profile)]))


def default_reports(overrides=None):
    beta = report(name="betaimpl", version="3")
    beta["hello"]["adapter"]["name"] = "kcs-adapter-beta"
    reports = {("alpha", "cesr-v1.0"): report(), ("alpha", "keri-v1.0.1"): keri_report(),
               ("beta", "cesr-v1.0"): beta}
    reports.update(overrides or {})
    return reports


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                          text=True).stdout


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.setattr(P, "INSTANCES", (ALPHA, BETA))
    root = tmp_path / "repo"
    for instance in (ALPHA, BETA):
        exe = root / instance.executable
        exe.parent.mkdir(parents=True)
        exe.write_text("#!/bin/sh\n")
        exe.chmod(0o755)
        (root / instance.readme).write_text(TABLE)
    (root / "results").mkdir()
    (root / "results" / "README.md").write_text("results\n")
    (root / ".gitignore").write_text("bin/\n")
    git(root, "init", "-q")
    git(root, "-c", "user.name=T", "-c", "user.email=t@x", "add", "-A")
    git(root, "-c", "user.name=T", "-c", "user.email=t@x", "commit", "-qm", "init")
    return root


def committed(root, doc):
    path = root / "results" / result_path(doc)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc))
    return path


def refresh(root, runs=None, names=()):
    return P.refresh(root, names, maintainer="Daniel Hardman", day="2026-10-15",
                     run=runs or Runs(default_reports()))


# --- refresh -------------------------------------------------------------------------------------

def test_refresh_writes_maintainer_run_results_and_the_readme_tables(repo):
    head = git(repo, "rev-parse", "HEAD").strip()
    lines = refresh(repo)
    assert "wrote results/keripy/2.1.0.dev1/cesr-v1.0.json" in lines
    doc = json.loads((repo / "results/keripy/2.1.0.dev1/keri-v1.0.1.json").read_text())
    assert doc["provenance"] == {"kind": "maintainer-run", "maintainer": "Daniel Hardman",
                                 "commit": head, "date": "2026-10-15"}
    assert (repo / "results/betaimpl/3/cesr-v1.0.json").is_file()
    table = (repo / ALPHA.readme).read_text()
    assert table.startswith("intro\n\n" + P.BEGIN) and table.endswith(P.END + "\n\nmore\n")
    assert ("| keripy 2.1.0.dev1 | `cesr-v1.0` | conformant | 1 / 0 | 0 / 0 | 0 | "
            f"[2026-10-15, suite {head[:8]}](../../results/keripy/2.1.0.dev1/cesr-v1.0.json) |"
            in table)
    assert "betaimpl" not in table and "betaimpl" in (repo / BETA.readme).read_text()
    assert "rewrote the results table in adapters/alpha/README.md" in lines


def test_refresh_replaces_an_existing_result(repo):
    refresh(repo)
    git(repo, "add", "-A")
    git(repo, "-c", "user.name=T", "-c", "user.email=t@x", "commit", "-qm", "results")
    rep = report([case(outcome="fail", records=[record(outcome="fail")])])
    refresh(repo, Runs(default_reports({("alpha", "cesr-v1.0"): rep})), ["alpha"])
    doc = json.loads((repo / "results/keripy/2.1.0.dev1/cesr-v1.0.json").read_text())
    assert doc["report"]["verdict"] == "not-conformant"


def test_refresh_removes_the_result_a_new_version_supersedes(repo):
    old = committed(repo, result(report(version="2.0.0"), MAINTAINER_RUN))
    keep = committed(repo, result(keri_report(version="2.0.0"), MAINTAINER_RUN))
    claim = committed(repo, result(report(version="1.0.0"), SUBMITTED))
    lines = refresh(repo, names=["beta"]) + refresh(repo, names=["alpha"])
    assert "removed results/keripy/2.0.0/cesr-v1.0.json, superseded" in lines
    assert not old.exists()
    # The other profile's result is superseded too, and only then is its directory removed.
    assert not keep.exists() and not keep.parent.exists()
    assert claim.exists()


@pytest.mark.parametrize(("code", "errno_"), [("e.env.filesystem.result-write.f", 13),
                                               ("e.env.filesystem.result-write.r", 28)])
def test_refresh_reports_a_result_it_could_not_move_into_place(repo, monkeypatch, code, errno_):
    def fail(source, target):
        raise OSError(errno_, "simulated")

    monkeypatch.setattr(P.os, "replace", fail)
    with pytest.raises(RunnerError) as info:
        refresh(repo)
    assert info.value.code == code
    assert not list((repo / "results").rglob("*.tmp"))


def test_refresh_reports_a_results_directory_it_cannot_write_in(repo, monkeypatch):
    real = P.tempfile.mkstemp

    def fail_in_results(*args, dir=None, **kwargs):
        if str(dir).startswith(str(repo / "results")):
            raise PermissionError(13, "denied")
        return real(*args, dir=dir, **kwargs)

    monkeypatch.setattr(P.tempfile, "mkstemp", fail_in_results)
    with pytest.raises(RunnerError) as info:
        refresh(repo)
    assert info.value.code == P.E_RESULT_WRITE


def test_refresh_selects_adapters(repo):
    runs = Runs(default_reports())
    refresh(repo, runs, ["beta"])
    assert runs.calls == [("beta", "cesr-v1.0")]


def test_refresh_refuses_a_tree_with_changes_outside_what_it_writes(repo):
    (repo / ALPHA.readme).write_text(TABLE + "edited\n")
    (repo / "results" / "README.md").write_text("edited\n")
    refresh(repo)  # READMEs and results/ may be dirty
    for n in range(7):
        (repo / f"stray{n}.txt").write_text("x")
    with pytest.raises(RunnerError) as info:
        refresh(repo)
    assert info.value.code == P.E_DIRTY
    assert "stray0.txt" in str(info.value) and "and more" in str(info.value)


def test_refresh_refuses_an_aborted_run_and_writes_nothing(repo):
    aborted = {"code": "e.x.f", "reason": "stopped", "problems": [], "at_case": "CESR-0001",
               "exit_code": 3}
    runs = Runs(default_reports({("beta", "cesr-v1.0"): report(aborted=aborted)}))
    with pytest.raises(RunnerError) as info:
        refresh(repo, runs)
    assert info.value.code == P.E_ABORTED
    assert not (repo / "results" / "keripy").exists()


def test_refresh_refuses_an_unpublishable_report_and_writes_nothing(repo):
    runs = Runs(default_reports({("beta", "cesr-v1.0"): report(name="!!!")}))
    with pytest.raises(RunnerError):
        refresh(repo, runs)
    assert not (repo / "results" / "keripy").exists()


def test_an_adapter_that_is_not_built_is_refused_before_anything_runs(repo):
    (repo / BETA.executable).unlink()
    runs = Runs(default_reports())
    with pytest.raises(RunnerError) as info:
        refresh(repo, runs)
    assert info.value.code == P.E_NOT_BUILT and "beta" in str(info.value)
    assert runs.calls == []


def test_an_adapter_that_writes_no_report_is_refused(repo):
    with pytest.raises(RunnerError) as info:
        refresh(repo, Runs(default_reports(), skip=[("alpha", "keri-v1.0.1")]))
    assert info.value.code == P.E_NO_REPORT and "keri-v1.0.1" in str(info.value)


def test_refresh_outside_a_git_checkout_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(P, "INSTANCES", ())
    with pytest.raises(RunnerError) as info:
        refresh(tmp_path)
    assert info.value.code == P.E_GIT


def test_git_that_cannot_start_is_refused(repo, monkeypatch):
    def missing(*args, **kwargs):
        raise FileNotFoundError(2, "No such file", "git")

    monkeypatch.setattr(P.subprocess, "run", missing)
    with pytest.raises(RunnerError) as info:
        refresh(repo)
    assert info.value.code == P.E_GIT


# --- check ---------------------------------------------------------------------------------------

def test_check_passes_when_every_run_matches(repo):
    refresh(repo)
    assert P.check(repo, run=Runs(default_reports())) == []


def test_check_reports_regressions_and_improvements(repo):
    refresh(repo)
    worse = report([case(outcome="fail", records=[record(outcome="fail")])])
    lines = P.check(repo, ["alpha"], run=Runs(default_reports({("alpha", "cesr-v1.0"): worse})))
    assert f"{P.E_REGRESSION}: alpha cesr-v1.0: CESR-0001: outcome pass -> fail" in lines
    better = keri_report()
    better["hello"]["implementation"]["commit"] = "newer"
    lines = P.check(repo, ["alpha"], run=Runs(default_reports({("alpha", "keri-v1.0.1"): better})))
    assert lines == [(f"{P.E_STALE}: alpha keri-v1.0.1: implementation commit: 9a8b7aa -> newer "
                      "(an improvement; record it with scripts/reproduce-results refresh "
                      "--adapter alpha)")]


def test_check_reports_a_run_with_no_committed_result(repo):
    lines = P.check(repo, ["beta"], run=Runs(default_reports()))
    assert lines[0] == (f"{P.E_UNCOMMITTED}: beta cesr-v1.0: no committed result at "
                        "results/betaimpl/3/cesr-v1.0.json")


def test_check_reports_a_committed_result_it_cannot_read(repo, monkeypatch):
    # The README tables would refuse the tree first; scripts/results check names the problem too.
    monkeypatch.setattr(P, "check_readmes", lambda repo: [])
    path = repo / "results/betaimpl/3/cesr-v1.0.json"
    path.parent.mkdir(parents=True)
    path.write_text("{}")
    lines = P.check(repo, ["beta"], run=Runs(default_reports()))
    assert lines[0].startswith(f"{P.E_UNCOMMITTED}: beta cesr-v1.0: e.input.format.committed")


def test_check_reports_a_run_whose_report_could_not_be_published(repo):
    lines = P.check(repo, ["beta"], run=Runs(default_reports({
        ("beta", "cesr-v1.0"): report(name="!!!")})))
    assert lines[0].startswith(f"{P.E_REGRESSION}: beta cesr-v1.0: the run's report could not")


def test_check_reports_a_stale_readme_table(repo):
    refresh(repo)
    (repo / ALPHA.readme).write_text(TABLE)
    assert P.check(repo, ["beta"], run=Runs(default_reports())) == [
        (f"{P.E_STALE}: the results table in adapters/alpha/README.md does not match results/; "
         "rewrite it with scripts/reproduce-results readmes")]


# --- readmes -------------------------------------------------------------------------------------

def test_the_table_lists_only_its_own_adapters_maintainer_runs(repo):
    committed(repo, result(report(version="1|2"), MAINTAINER_RUN))
    committed(repo, result(report(name="claimed"), SUBMITTED))
    assert P.update_readmes(repo) == ["rewrote the results table in adapters/alpha/README.md",
                                      "rewrote the results table in adapters/beta/README.md"]
    table = (repo / ALPHA.readme).read_text()
    assert "| keripy 1\\|2 | `cesr-v1.0` |" in table and "claimed" not in table
    assert P.update_readmes(repo) == []
    assert P.check_readmes(repo) == []


@pytest.mark.parametrize("text", ["no markers\n", f"{P.END}\n{P.BEGIN}\n",
                                  f"{P.BEGIN}\n{P.BEGIN}\n{P.END}\n"])
def test_a_readme_without_one_well_placed_pair_of_markers_is_refused(repo, text):
    (repo / BETA.readme).write_text(text)
    with pytest.raises(RunnerError) as info:
        P.update_readmes(repo)
    assert info.value.code == P.E_README


# --- reproduce -----------------------------------------------------------------------------------

def test_reproduce_writes_reproduced_results_into_a_directory(repo, tmp_path):
    run_url = "https://github.com/bakobo/keri-conformance-suite/actions/runs/9"
    lines = P.reproduce(repo, tmp_path / "out", run_url=run_url, commit="2" * 40,
                        day="2026-10-15", run=Runs(default_reports()))
    assert len(lines) == 3
    doc = json.loads((tmp_path / "out/betaimpl/3/cesr-v1.0.json").read_text())
    assert doc["provenance"] == {"kind": "reproduced", "run": run_url, "commit": "2" * 40,
                                 "date": "2026-10-15"}
    assert not (repo / "results" / "betaimpl").exists()


# --- the real runner ------------------------------------------------------------------------------

def test_kcs_run_drives_the_runner(tmp_path):
    out = tmp_path / "report.json"
    P.kcs_run(ROOT, f"{sys.executable} {FAKES / 'good.py'}", "cesr-strict", out)
    assert json.loads(out.read_text())["filters"]["profile"] == "cesr-strict"


# --- command line --------------------------------------------------------------------------------

def main(repo, *args):
    return P.main(["--repo", str(repo), *map(str, args)])


@pytest.fixture
def fake_runs(monkeypatch):
    runs = Runs(default_reports())
    monkeypatch.setattr(P, "kcs_run", runs)
    for fn in (P.refresh, P.check, P.reproduce):
        monkeypatch.setattr(fn, "__kwdefaults__", {**fn.__kwdefaults__, "run": runs})
    return runs


def test_main_refresh_then_check(repo, fake_runs, capsys):
    git(repo, "config", "user.name", "Git Name")
    assert main(repo, "refresh", "--date", "2026-10-15") == 0
    assert "wrote results/" in capsys.readouterr().out
    doc = json.loads((repo / "results/betaimpl/3/cesr-v1.0.json").read_text())
    assert doc["provenance"]["maintainer"] == "Git Name"
    assert main(repo, "check", "--adapter", "beta") == 0
    assert "match the committed results" in capsys.readouterr().out
    (repo / BETA.readme).write_text(TABLE)
    assert main(repo, "check", "--adapter", "beta") == 1
    assert P.E_STALE in capsys.readouterr().out


def test_main_refresh_with_a_named_maintainer(repo, fake_runs):
    assert main(repo, "refresh", "--maintainer", "Someone") == 0
    doc = json.loads((repo / "results/betaimpl/3/cesr-v1.0.json").read_text())
    assert doc["provenance"]["maintainer"] == "Someone"


def test_main_refresh_needs_a_maintainer(repo, fake_runs, capsys, monkeypatch):
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    assert main(repo, "refresh") == 2
    assert "user.name is empty" in capsys.readouterr().err


def test_main_refresh_outside_git_is_a_fault(tmp_path, fake_runs, capsys):
    assert main(tmp_path, "refresh") == 4
    assert P.E_GIT in capsys.readouterr().err


def test_main_refresh_without_git_to_name_the_maintainer_is_a_fault(repo, capsys, monkeypatch):
    def missing(*args, **kwargs):
        raise FileNotFoundError(2, "No such file", "git")

    monkeypatch.setattr(P.subprocess, "run", missing)
    assert main(repo, "refresh") == 4
    assert P.E_GIT in capsys.readouterr().err


def test_main_reports_a_fault(repo, fake_runs, capsys):
    (repo / BETA.executable).unlink()
    assert main(repo, "check") == 4
    assert P.E_NOT_BUILT in capsys.readouterr().err


def test_main_readmes(repo, capsys):
    assert main(repo, "readmes", "--check") == 1
    assert main(repo, "readmes") == 0
    assert "rewrote" in capsys.readouterr().out
    assert main(repo, "readmes", "--check") == 0
    assert "match results/" in capsys.readouterr().out


def test_main_reproduce(repo, fake_runs, tmp_path):
    assert main(repo, "reproduce", tmp_path / "out", "--run",
                "https://github.com/bakobo/keri-conformance-suite/actions/runs/9",
                "--commit", "2" * 40) == 0
    assert (tmp_path / "out/betaimpl/3/cesr-v1.0.json").is_file()


@pytest.mark.parametrize("args", [[], ["frobnicate"], ["check", "--adapter", "nope"],
                                  ["reproduce", "out"]])
def test_main_usage_errors(repo, args, capsys):
    assert main(repo, *args) == 2
    assert "e.input.format.f" in capsys.readouterr().err


def test_the_script_runs(tmp_path):
    done = subprocess.run([sys.executable, str(ROOT / "scripts" / "reproduce-results"),
                           "readmes", "--check"], capture_output=True, text=True, check=False,
                          env={**os.environ, "PYTHONPATH": str(ROOT / "src")})
    assert done.returncode in (0, 1), done.stderr


def test_the_real_instances_name_built_adapters_readmes_and_profiles():
    for instance in P.INSTANCES:
        assert (ROOT / instance.readme).is_file()
        for profile in instance.profiles:
            assert (ROOT / "profiles" / f"{profile}.json").is_file()
