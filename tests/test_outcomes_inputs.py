"""The outcome comparison's handling of bad inputs: every one is a coded InputError, never a
traceback, so a check that meets one says what was wrong with which file."""

import copy
import json

import pytest
from test_outcomes import base_report, case, report

from tools import outcomes


@pytest.fixture
def files(tmp_path):
    committed, rep = tmp_path / "committed.json", tmp_path / "report.json"
    committed.write_text(json.dumps({"result_version": 1, "report": base_report()}))
    rep.write_text(json.dumps(base_report()))
    return committed, rep


def refused(code, read, path):
    with pytest.raises(outcomes.InputError) as info:
        read(path)
    assert str(info.value).startswith(code)
    return str(info.value)


READERS = {"committed": outcomes.read_committed, "report": outcomes.read_report}


# -- missing and unreadable files

@pytest.mark.parametrize("which", ["committed", "report"])
def test_a_missing_file_is_a_coded_error(files, which):
    path = files[0] if which == "committed" else files[1]
    path.unlink()
    assert "does not exist" in refused(outcomes.E_MISSING_FILE, READERS[which], path)


def test_an_unreadable_file_is_a_coded_error(tmp_path):
    refused(outcomes.E_READ, outcomes.read_report, tmp_path)  # a directory


# -- bounded reads

def test_the_file_bound_is_64_mib():
    assert outcomes.MAX_FILE_BYTES == 64 * 1024 * 1024


@pytest.mark.parametrize("which", ["committed", "report"])
def test_a_file_over_the_bound_is_a_coded_size_error(files, monkeypatch, which):
    path = files[0] if which == "committed" else files[1]
    monkeypatch.setattr(outcomes, "MAX_FILE_BYTES", path.stat().st_size - 1)
    refused(outcomes.E_FILE_SIZE, READERS[which], path)


def test_a_file_of_exactly_the_bound_is_read(files, monkeypatch):
    committed, rep = files
    monkeypatch.setattr(outcomes, "MAX_FILE_BYTES",
                        max(committed.stat().st_size, rep.stat().st_size))
    assert outcomes.read_committed(committed) == outcomes.summarize(base_report())
    assert outcomes.read_report(rep) == base_report()


# -- malformed reports

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
def test_a_malformed_report_is_a_coded_error(files, bad):
    committed, rep = files
    rep.write_text(json.dumps(bad))
    refused(outcomes.E_REPORT_FORMAT, outcomes.read_report, rep)
    committed.write_text(json.dumps({"report": bad}))
    refused(outcomes.E_COMMITTED_FORMAT, outcomes.read_committed, committed)


@pytest.mark.parametrize("content", [b"{not json", b"[1, 2]", b"\xff"])
def test_a_report_that_is_not_json_is_a_coded_error(files, content):
    _, rep = files
    rep.write_bytes(content)
    refused(outcomes.E_REPORT_FORMAT, outcomes.read_report, rep)


@pytest.mark.parametrize("content", ["[]", "{}", '{"report": null}'])
def test_a_committed_file_without_a_report_is_a_coded_error(files, content):
    committed, _ = files
    committed.write_text(content)
    message = refused(outcomes.E_COMMITTED_FORMAT, outcomes.read_committed, committed)
    assert "scripts/results check" in message


def test_a_committed_result_of_another_kind_is_refused_when_a_kind_is_asked_for(files):
    committed, _ = files
    assert outcomes.read_committed(committed) == outcomes.summarize(base_report())
    message = refused(outcomes.E_COMMITTED_FORMAT,
                      lambda p: outcomes.read_committed(p, kind="maintainer-run"), committed)
    assert "labelled null, not maintainer-run" in message
    committed.write_text(json.dumps({"provenance": {"kind": "submitted"},
                                     "report": base_report()}))
    message = refused(outcomes.E_COMMITTED_FORMAT,
                      lambda p: outcomes.read_committed(p, kind="maintainer-run"), committed)
    assert 'labelled "submitted"' in message
    committed.write_text(json.dumps({"provenance": {"kind": "maintainer-run"},
                                     "report": base_report()}))
    assert outcomes.read_committed(committed, kind="maintainer-run") == \
        outcomes.summarize(base_report())


def test_every_known_value_is_accepted():
    cases = [case(f"C-{n}", outcome, failure, a1=assertion)
             for n, (outcome, failure, assertion) in enumerate(
                 [(o, None, "pass") for o in sorted(outcomes.CASE_OUTCOMES)]
                 + [("fail", k, "fail") for k in sorted(outcomes.FAILURE_KINDS)]
                 + [("pass", None, a) for a in sorted(outcomes.ASSERTION_OUTCOMES)])]
    for verdict in sorted(outcomes.VERDICTS):
        assert outcomes.report_problem(report(*cases, verdict=verdict)) is None
