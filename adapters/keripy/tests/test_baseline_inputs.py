"""The baseline tool's handling of bad inputs and failed writes: every one is a coded error
with a non-zero exit, never a traceback, and write never emits an unusable baseline."""

import copy
import json

import pytest
from test_baseline import base_report, case, report, summary

from kcs_adapter_keripy import baseline


@pytest.fixture
def files(tmp_path):
    base, rep = tmp_path / "baseline.json", tmp_path / "report.json"
    base.write_text(json.dumps(summary()))
    rep.write_text(json.dumps(base_report()))
    return base, rep


def run(*args):
    return baseline.main([*map(str, args)])


# -- missing and unreadable files

@pytest.mark.parametrize("which", ["baseline", "report"])
def test_a_missing_file_is_a_coded_error(files, capsys, which):
    base, rep = files
    (base if which == "baseline" else rep).unlink()
    assert run("compare", base, rep) == 2
    err = capsys.readouterr().err
    assert "e.input.missing.file.f" in err and "does not exist" in err


def test_an_unreadable_file_is_a_coded_error(files, capsys, tmp_path):
    base, _ = files
    assert run("compare", base, tmp_path) == 2  # a directory
    assert "e.env.filesystem.read.r" in capsys.readouterr().err


# -- bounded reads (N)

def test_the_file_bound_is_64_mib():
    assert baseline.MAX_FILE_BYTES == 64 * 1024 * 1024


@pytest.mark.parametrize("which", ["baseline", "report"])
def test_a_file_over_the_bound_is_a_coded_size_error(files, capsys, monkeypatch, which):
    base, rep = files
    path = base if which == "baseline" else rep
    monkeypatch.setattr(baseline, "MAX_FILE_BYTES", path.stat().st_size - 1)
    assert run("compare", base, rep) == 2
    assert "e.input.range.file-size.f" in capsys.readouterr().err


def test_a_file_of_exactly_the_bound_is_read(files, monkeypatch):
    base, rep = files
    monkeypatch.setattr(baseline, "MAX_FILE_BYTES",
                        max(base.stat().st_size, rep.stat().st_size))
    assert run("compare", base, rep) == 0


# -- malformed reports (O)

def _broken_reports():
    good = base_report()
    cases = []

    def broken(label, mutate):
        value = copy.deepcopy(good)
        mutate(value)
        cases.append(pytest.param(value, id=label))

    broken("not-an-object", lambda r: r.clear() or r.update({"x": 1}))
    broken("filters-missing", lambda r: r.pop("filters"))
    broken("profile-not-string", lambda r: r["filters"].update(profile=3))
    broken("hello-not-object", lambda r: r.update(hello=[]))
    broken("implementation-missing", lambda r: r["hello"].pop("implementation"))
    for field in ("name", "version", "commit"):
        broken(f"implementation-{field}-not-string",
               lambda r, f=field: r["hello"]["implementation"].update({f: None}))
    broken("verdict-unknown", lambda r: r.update(verdict="great"))
    broken("cases-not-list", lambda r: r.update(cases={}))
    broken("case-not-object", lambda r: r["cases"].append("x"))
    broken("case-id-not-string", lambda r: r["cases"][0].update(id=1))
    broken("case-id-duplicated", lambda r: r["cases"].append(copy.deepcopy(r["cases"][0])))
    broken("case-outcome-unknown", lambda r: r["cases"][0].update(outcome="meh"))
    broken("failure-not-object", lambda r: r["cases"][0].update(failure="exited"))
    broken("failure-kind-unknown", lambda r: r["cases"][0].update(failure={"kind": "boom"}))
    broken("assertions-not-list", lambda r: r["cases"][0].update(assertions={}))
    broken("assertion-not-object", lambda r: r["cases"][0]["assertions"].append(1))
    broken("assertion-id-not-string", lambda r: r["cases"][0]["assertions"][0].update(id=2))
    broken("assertion-id-duplicated",
           lambda r: r["cases"][0]["assertions"].append(r["cases"][0]["assertions"][0]))
    broken("assertion-outcome-unknown",
           lambda r: r["cases"][0]["assertions"][0].update(outcome="passed"))
    return cases


@pytest.mark.parametrize("bad", _broken_reports())
@pytest.mark.parametrize("command", ["compare", "write"])
def test_a_malformed_report_is_a_coded_error_and_writes_nothing(files, capsys, bad, command):
    base, rep = files
    before = base.read_text()
    rep.write_text(json.dumps(bad))
    assert run(command, base, rep) == 2
    assert "e.input.format.report.f" in capsys.readouterr().err
    assert base.read_text() == before


@pytest.mark.parametrize("content", [b"{not json", b"[1, 2]", b"\xff"])
def test_a_report_that_is_not_json_is_a_coded_error(files, capsys, content):
    base, rep = files
    rep.write_bytes(content)
    assert run("compare", base, rep) == 2
    assert "e.input.format.report.f" in capsys.readouterr().err


def test_every_known_value_is_accepted():
    cases = [case(f"C-{n}", outcome, failure, a1=assertion)
             for n, (outcome, failure, assertion) in enumerate(
                 [(o, None, "pass") for o in sorted(baseline.CASE_OUTCOMES)]
                 + [("fail", k, "fail") for k in sorted(baseline.FAILURE_KINDS)]
                 + [("pass", None, a) for a in sorted(baseline.ASSERTION_OUTCOMES)])]
    for verdict in sorted(baseline.VERDICTS):
        assert baseline.report_problem(report(*cases, verdict=verdict)) is None


@pytest.mark.parametrize("content", [
    '{"profile": "cesr-1.0"}',
    json.dumps({**summary(), "format": 1}),
    json.dumps({**summary(), "profile": None}),
    json.dumps({**summary(), "verdict": "great"}),
    json.dumps({**summary(), "implementation": {"name": "keripy"}}),
    json.dumps({**summary(), "cases": []}),
    json.dumps({**summary(), "cases": {"C": {"outcome": "pass", "failure": "boom",
                                             "assertions": {}}}}),
    json.dumps({**summary(), "cases": {"C": {"outcome": "pass", "failure": None,
                                             "assertions": {"a1": "passed"}}}}),
    json.dumps({**summary(), "cases": {"C": {"outcome": "pass", "failure": None}}}),
    json.dumps({**summary(), "cases": {"C": {"outcome": "meh", "failure": None,
                                             "assertions": {}}}}),
])
def test_a_malformed_or_old_baseline_is_a_coded_error(files, capsys, content):
    base, rep = files
    base.write_text(content)
    assert run("compare", base, rep) == 2
    assert "e.input.format.baseline.f" in capsys.readouterr().err
