"""The weekly check of the keripy adapter against other keripy refs (this.i 4numcxwq): which refs
it runs, which it skips, what counts as a difference, and how failures are reported."""

import json
import runpy
import subprocess
import sys

import pytest

from kcs_adapter_keripy import refs

SHA_A = "a" * 40
SHA_B = "b" * 40
MAIN_PROFILES = ["cesr-1.0", "keri-1.0"]


def entry(name="upstream-main", ref="main", python="3.14", profiles=None,
          source="https://github.com/WebOfTrust/keripy"):
    return {"name": name, "source": source, "ref": ref, "python": python,
            "profiles": list(MAIN_PROFILES if profiles is None else profiles)}


def case(cid, outcome="pass", **assertions):
    return {"id": cid, "status": "active", "outcome": outcome, "failure": None,
            "assertions": [{"id": aid, "level": "MUST", "outcome": out}
                           for aid, out in (assertions or {"a1": "pass"}).items()]}


def report(profile, commit, *cases, verdict="conformant"):
    return {"filters": {"profile": profile},
            "hello": {"implementation": {"name": "keripy", "version": "2", "commit": commit}},
            "verdict": verdict, "cases": list(cases) or [case("CESR-0001")]}


@pytest.fixture
def suite(tmp_path):
    """A suite checkout holding a baseline for each profile the tests use."""
    root = tmp_path / "suite"
    adapter = root / "adapters" / "keripy"
    adapter.mkdir(parents=True)
    for profile in (*MAIN_PROFILES, "keripy-1x-interop"):
        base = refs.baseline.summarize(report(profile, "pinned"))
        (adapter / f"baseline-{profile}.json").write_text(json.dumps(base))
    return root


class Fake:
    """Stands in for the commands the check runs. ls-remote answers from `remote`; `kcs run`
    writes the report `reports` holds for the profile, unless the profile is in `no_report`."""

    def __init__(self, remote=None, reports=None, fail=(), no_report=()):
        self.remote = remote or {}
        self.reports = reports or {}
        self.fail = set(fail)
        self.no_report = set(no_report)
        self.calls = []

    def __call__(self, cmd, *, check=True):
        self.calls.append(cmd)
        verb = cmd[1] if cmd[0] in ("git", "uv") else cmd[0]
        if verb in self.fail:
            raise refs.CommandError(f"{verb} failed")
        if cmd[:2] == ["git", "ls-remote"]:
            return "".join(f"{sha}\t{name}\n" for name, sha in self.remote.get(cmd[2], {}).items())
        if "kcs" in cmd and "run" in cmd:
            profile = cmd[cmd.index("--profile") + 1]
            path = cmd[cmd.index("--report") + 1]
            if profile not in self.no_report:
                with open(path, "w") as handle:
                    json.dump(self.reports[profile], handle)
        return ""

    def verbs(self):
        return [c[1] if c[0] in ("git", "uv") else c[0] for c in self.calls]


UPSTREAM = "https://github.com/WebOfTrust/keripy"


def matching(commit=SHA_A, profiles=MAIN_PROFILES):
    return {p: report(p, commit) for p in profiles}


class TestResolve:
    def test_a_full_commit_is_its_own_answer(self):
        fake = Fake()
        assert refs.resolve(UPSTREAM, SHA_B, fake) == SHA_B
        assert fake.calls == []

    def test_a_branch_resolves_to_its_head(self):
        fake = Fake({UPSTREAM: {"refs/heads/main": SHA_A}})
        assert refs.resolve(UPSTREAM, "main", fake) == SHA_A
        assert fake.calls == [["git", "ls-remote", UPSTREAM, "main"]]

    def test_an_annotated_tag_resolves_to_the_commit_it_points_at(self):
        fake = Fake({UPSTREAM: {"refs/tags/1.3.6": SHA_B, "refs/tags/1.3.6^{}": SHA_A}})
        assert refs.resolve(UPSTREAM, "1.3.6", fake) == SHA_A

    def test_a_lightweight_tag_resolves_to_its_commit(self):
        fake = Fake({UPSTREAM: {"refs/tags/v1": SHA_B}})
        assert refs.resolve(UPSTREAM, "v1", fake) == SHA_B

    def test_a_tag_wins_over_a_branch_of_the_same_name(self):
        fake = Fake({UPSTREAM: {"refs/heads/x": SHA_B, "refs/tags/x": SHA_A}})
        assert refs.resolve(UPSTREAM, "x", fake) == SHA_A

    def test_a_ref_that_names_nothing_is_an_error(self):
        fake = Fake({UPSTREAM: {"refs/heads/other": SHA_A}})
        with pytest.raises(refs.CommandError, match=r"^e\.input\.missing\.keripy-ref\.f: "):
            refs.resolve(UPSTREAM, "main", fake)

    def test_a_line_that_is_not_a_ref_listing_is_ignored(self):
        fake = Fake({UPSTREAM: {"refs/heads/main": SHA_A}})
        fake.remote[UPSTREAM]["garbage"] = "not-a-sha"
        assert refs.resolve(UPSTREAM, "main", fake) == SHA_A


class TestDifferences:
    def test_only_the_commit_differs_so_nothing_is_reported(self):
        base = refs.baseline.summarize(report("cesr-1.0", "pinned"))
        assert refs.differences(base, report("cesr-1.0", SHA_A)) == []

    def test_a_regression_is_reported(self):
        base = refs.baseline.summarize(report("cesr-1.0", "pinned"))
        now = report("cesr-1.0", SHA_A, case("CESR-0001", "fail", a1="fail"),
                     verdict="not-conformant")
        lines = refs.differences(base, now)
        assert "CESR-0001: outcome pass -> fail" in lines
        assert any(line.startswith("verdict:") for line in lines)

    def test_an_improvement_is_a_difference_too(self):
        base = refs.baseline.summarize(report("cesr-1.0", "pinned", case("CESR-0001", "fail")))
        lines = refs.differences(base, report("cesr-1.0", SHA_A))
        assert lines == ["CESR-0001: outcome fail -> pass"]


class TestLoadRefs:
    def write(self, tmp_path, data):
        path = tmp_path / "refs.json"
        path.write_text(json.dumps(data) if not isinstance(data, str) else data)
        return path

    def test_reads_a_valid_list(self, tmp_path):
        path = self.write(tmp_path, [entry()])
        assert refs.load_refs(path) == [entry()]

    @pytest.mark.parametrize("bad, why", [
        ("not json", "not JSON"),
        ({"name": "x"}, "not a list"),
        ([], "empty"),
        (["x"], "not an object"),
        ([{**entry(), "extra": 1}], "unknown field"),
        ([{k: v for k, v in entry().items() if k != "ref"}], "missing field"),
        ([entry(name="Bad Name")], "name"),
        ([entry(), entry()], "duplicate name"),
        ([entry(source="http://example.com/keripy")], "source"),
        ([entry(source="https://github.com/a/b;rm")], "source"),
        ([entry(ref="-upload-pack=x")], "ref"),
        ([entry(ref="")], "ref"),
        ([entry(ref=5)], "ref"),
        ([entry(python="3")], "python"),
        ([entry(profiles=[])], "profiles"),
        ([{**entry(), "profiles": "cesr-1.0"}], "profiles"),
        ([entry(profiles=["../etc"])], "profile name"),
    ])
    def test_refuses_a_malformed_list(self, tmp_path, bad, why):
        with pytest.raises(refs.UsageError, match=r"^e\.input\.format\.keripy-refs\.f: "):
            refs.load_refs(self.write(tmp_path, bad))

    def test_refuses_a_missing_file(self, tmp_path):
        with pytest.raises(refs.UsageError, match=r"^e\.input\.missing\.file\.f: "):
            refs.load_refs(tmp_path / "absent.json")

    def test_refuses_an_oversize_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr(refs, "MAX_FILE_BYTES", 4)
        with pytest.raises(refs.UsageError, match=r"^e\.input\.range\.file-size\.f: "):
            refs.load_refs(self.write(tmp_path, [entry()]))

    def test_the_committed_list_is_valid_and_has_a_baseline_for_every_profile(self):
        import pathlib
        adapter = pathlib.Path(refs.__file__).resolve().parents[2]
        listed = refs.load_refs(adapter / "refs.json")
        assert listed
        for item in listed:
            for profile in item["profiles"]:
                assert (adapter / f"baseline-{profile}.json").is_file(), (item["name"], profile)


class TestState:
    def test_a_missing_state_file_is_an_empty_state(self, tmp_path):
        assert refs.load_state(tmp_path / "none.json") == {}

    @pytest.mark.parametrize("text", ["junk", "[]", '{"format": 9, "refs": {}}', '{"format": 1}',
                                      '{"format": 1, "refs": {"x": 1}}'])
    def test_an_unreadable_state_is_treated_as_empty_and_said_so(self, tmp_path, text, capsys):
        path = tmp_path / "state.json"
        path.write_text(text)
        assert refs.load_state(path) == {}
        assert "w.input.format.keripy-refs-state.f" in capsys.readouterr().err

    def test_round_trip(self, tmp_path):
        path = tmp_path / "sub" / "state.json"
        state = {"upstream-main": {"keripy": SHA_A, "inputs": "h", "differences": []}}
        refs.save_state(path, state)
        assert refs.load_state(path) == state


class TestCheck:
    def run(self, suite, tmp_path, refs_list, state, fake, inputs="h1"):
        return refs.check_all(refs_list, state, inputs, suite, tmp_path / "work", fake)

    def test_a_new_ref_is_installed_run_and_recorded(self, suite, tmp_path):
        fake = Fake({UPSTREAM: {"refs/heads/main": SHA_A}}, matching())
        code, state, lines = self.run(suite, tmp_path, [entry()], {}, fake)
        assert code == 0
        assert state == {"upstream-main": {"keripy": SHA_A, "inputs": "h1", "differences": []}}
        install = [c for c in fake.calls if c[:2] == ["uv", "pip"]]
        assert any(f"keri @ git+{UPSTREAM}@{SHA_A}" in c for c in install)
        assert any("--no-deps" in c for c in install)
        assert any("match" in line for line in lines)

    def test_an_unchanged_ref_is_skipped_without_installing_anything(self, suite, tmp_path):
        fake = Fake({UPSTREAM: {"refs/heads/main": SHA_A}})
        prior = {"upstream-main": {"keripy": SHA_A, "inputs": "h1", "differences": []}}
        code, state, lines = self.run(suite, tmp_path, [entry()], dict(prior), fake)
        assert code == 0
        assert state == prior
        assert fake.verbs() == ["ls-remote"]
        assert any("unchanged" in line for line in lines)

    def test_a_new_keripy_commit_reruns_it(self, suite, tmp_path):
        fake = Fake({UPSTREAM: {"refs/heads/main": SHA_B}}, matching(SHA_B))
        prior = {"upstream-main": {"keripy": SHA_A, "inputs": "h1", "differences": []}}
        code, state, _ = self.run(suite, tmp_path, [entry()], prior, fake)
        assert code == 0
        assert state["upstream-main"]["keripy"] == SHA_B
        assert "venv" in fake.verbs()

    def test_changed_suite_inputs_rerun_it(self, suite, tmp_path):
        fake = Fake({UPSTREAM: {"refs/heads/main": SHA_A}}, matching())
        prior = {"upstream-main": {"keripy": SHA_A, "inputs": "h0", "differences": []}}
        _, state, _ = self.run(suite, tmp_path, [entry()], prior, fake)
        assert state["upstream-main"]["inputs"] == "h1"
        assert "venv" in fake.verbs()

    def test_a_difference_fails_and_is_recorded(self, suite, tmp_path):
        reports = matching()
        reports["keri-1.0"] = report("keri-1.0", SHA_A, case("CESR-0001", "fail", a1="fail"),
                                     verdict="not-conformant")
        fake = Fake({UPSTREAM: {"refs/heads/main": SHA_A}}, reports)
        code, state, lines = self.run(suite, tmp_path, [entry()], {}, fake)
        assert code == 1
        assert any(d.startswith("keri-1.0: CESR-0001: outcome pass -> fail")
                   for d in state["upstream-main"]["differences"])
        assert any(line.startswith("e.state.conflict.keripy-ref-differs.f: upstream-main")
                   for line in lines)

    def test_an_unchanged_ref_that_differed_last_time_still_fails(self, suite, tmp_path):
        fake = Fake({UPSTREAM: {"refs/heads/main": SHA_A}})
        prior = {"upstream-main": {"keripy": SHA_A, "inputs": "h1",
                                   "differences": ["keri-1.0: CESR-0001: outcome pass -> fail"]}}
        code, state, lines = self.run(suite, tmp_path, [entry()], dict(prior), fake)
        assert code == 1
        assert state == prior
        assert fake.verbs() == ["ls-remote"]
        assert any("CESR-0001" in line for line in lines)

    def test_one_failing_ref_does_not_stop_the_others(self, suite, tmp_path):
        other = "https://github.com/bakobo/keripy"
        fake = Fake({other: {"refs/heads/main": SHA_B}}, matching())
        refs_list = [entry(), entry(name="bakobo-main", source=other)]
        code, state, lines = self.run(suite, tmp_path, refs_list, {}, fake)
        assert code == 1
        assert set(state) == {"bakobo-main"}
        assert any(line.startswith("e.env.dependency.keripy-ref.r: upstream-main: "
                                   "e.input.missing.keripy-ref.f") for line in lines)

    def test_a_ref_that_cannot_be_resolved_fails_and_keeps_its_state(self, suite, tmp_path):
        fake = Fake(fail={"ls-remote"})
        prior = {"upstream-main": {"keripy": SHA_A, "inputs": "h1", "differences": []}}
        code, state, lines = self.run(suite, tmp_path, [entry()], dict(prior), fake)
        assert code == 1
        assert state == prior
        assert any("ls-remote failed" in line for line in lines)

    def test_an_install_failure_fails_and_records_nothing(self, suite, tmp_path):
        fake = Fake({UPSTREAM: {"refs/heads/main": SHA_A}}, matching(), fail={"pip"})
        code, state, lines = self.run(suite, tmp_path, [entry()], {}, fake)
        assert code == 1
        assert state == {}
        assert any(line.startswith("e.env.dependency.keripy-ref.r: upstream-main")
                   for line in lines)

    def test_a_run_that_wrote_no_report_fails_and_records_nothing(self, suite, tmp_path):
        fake = Fake({UPSTREAM: {"refs/heads/main": SHA_A}}, matching(), no_report={"keri-1.0"})
        code, state, lines = self.run(suite, tmp_path, [entry()], {}, fake)
        assert code == 1
        assert state == {}
        assert any("keri-1.0" in line for line in lines)

    def test_every_ref_in_the_list_is_checked(self, suite, tmp_path):
        other = "https://github.com/bakobo/keripy"
        fake = Fake({UPSTREAM: {"refs/heads/main": SHA_A}, other: {"refs/heads/main": SHA_B}},
                    matching())
        refs_list = [entry(), entry(name="bakobo-main", source=other)]
        code, state, _ = self.run(suite, tmp_path, refs_list, {}, fake)
        assert code == 0
        assert set(state) == {"upstream-main", "bakobo-main"}

    def test_kcs_run_is_told_the_suite_the_profile_and_the_adapter(self, suite, tmp_path):
        fake = Fake({UPSTREAM: {"refs/heads/main": SHA_A}}, matching())
        self.run(suite, tmp_path, [entry()], {}, fake)
        kcs = [c for c in fake.calls if "kcs" in c]
        assert len(kcs) == len(MAIN_PROFILES)
        first = kcs[0]
        assert first[first.index("--suite") + 1] == str(suite)
        assert first[first.index("--adapter") + 1].endswith("/bin/kcs-adapter-keripy")


class TestRunCommand:
    def test_returns_stdout(self):
        assert refs.run_command([sys.executable, "-c", "print('hi')"]) == "hi\n"

    def test_a_failing_command_raises_with_its_stderr(self):
        with pytest.raises(refs.CommandError, match="boom"):
            refs.run_command([sys.executable, "-c", "import sys; sys.exit('boom')"])

    def test_check_false_tolerates_a_failing_exit(self):
        assert refs.run_command([sys.executable, "-c", "import sys; sys.exit(3)"],
                                check=False) == ""

    def test_a_missing_program_raises(self):
        with pytest.raises(refs.CommandError, match="could not start"):
            refs.run_command(["/nonexistent/program"])

    def test_a_timeout_raises(self, monkeypatch):
        def slow(*a, **k):
            raise subprocess.TimeoutExpired(cmd="x", timeout=1)
        monkeypatch.setattr(refs.subprocess, "run", slow)
        with pytest.raises(refs.CommandError, match="did not finish"):
            refs.run_command(["x"])


class TestMain:
    def args(self, tmp_path, suite, refs_path):
        return ["run", "--refs", str(refs_path), "--state", str(tmp_path / "state.json"),
                "--inputs", "h1", "--suite", str(suite), "--work", str(tmp_path / "work")]

    def test_runs_writes_state_and_prints(self, tmp_path, suite, capsys, monkeypatch):
        refs_path = tmp_path / "refs.json"
        refs_path.write_text(json.dumps([entry()]))
        monkeypatch.setattr(refs, "run_command",
                            Fake({UPSTREAM: {"refs/heads/main": SHA_A}}, matching()))
        code = refs.main(self.args(tmp_path, suite, refs_path))
        assert code == 0
        assert json.loads((tmp_path / "state.json").read_text())["refs"]["upstream-main"]
        assert "upstream-main" in capsys.readouterr().out

    def test_a_bad_refs_file_is_a_usage_error(self, tmp_path, suite, capsys):
        refs_path = tmp_path / "refs.json"
        refs_path.write_text("[]")
        code = refs.main(self.args(tmp_path, suite, refs_path))
        assert code == 2
        assert "e.input.format.keripy-refs.f" in capsys.readouterr().err

    def test_bad_arguments_are_a_usage_error(self, capsys):
        with pytest.raises(SystemExit) as exit_info:
            refs.main(["frobnicate"])
        assert exit_info.value.code == 2

    def test_a_state_that_cannot_be_written_is_reported(self, tmp_path, suite, capsys,
                                                        monkeypatch):
        refs_path = tmp_path / "refs.json"
        refs_path.write_text(json.dumps([entry()]))
        monkeypatch.setattr(refs, "run_command",
                            Fake({UPSTREAM: {"refs/heads/main": SHA_A}}, matching()))
        blocker = tmp_path / "state.json"
        blocker.mkdir()
        args = self.args(tmp_path, suite, refs_path)
        code = refs.main(args)
        assert code == 2
        assert "e.env.filesystem.write" in capsys.readouterr().err

    def test_runs_as_a_module(self, monkeypatch):
        monkeypatch.setattr(sys, "argv", ["refs", "frobnicate"])
        with pytest.raises(SystemExit) as exit_info:
            runpy.run_module("kcs_adapter_keripy.refs", run_name="__main__")
        assert exit_info.value.code == 2
