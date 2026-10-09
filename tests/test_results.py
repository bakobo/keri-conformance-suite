"""tools/results.py: the one door through which published results are read, and the wrap command
that puts a runner report into its envelope at the path the door expects."""

import errno
import json
import os

import pytest
from result_docs import REPRODUCED, SUBMITTED, case, record, report, result

from keri_conformance.errors import RunnerError
from keri_conformance.jsonfile import JsonFileError
from tools import results as R


def put(root, doc, rel=None):
    rel = rel or R.result_path(doc)
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def refused(code, fn, *args, **kwargs):
    with pytest.raises(RunnerError) as exc:
        fn(*args, **kwargs)
    assert exc.value.code == code, exc.value.message
    return exc.value.message


# --- slugs and paths ----------------------------------------------------------------------------

@pytest.mark.parametrize(("text", "slug"), [
    ("keripy", "keripy"),
    ("2.1.0.dev1", "2.1.0.dev1"),
    ("0.1.8 (said 0.4.3)", "0.1.8-said-0.4.3"),
    ("Affinidi KERI Core", "affinidi-keri-core"),
    ("1.0+local", "1.0+local"),
    ("..", None),
    ("-.-", None),
    ("()", None),
    ("x" * 64, "x" * 64),
    ("x" * 65, None),
    ("é", None),
])
def test_slug(text, slug):
    assert R.slug(text) == slug


def test_result_path_comes_from_the_report():
    doc = result(report(name="cesrox", version="0.1.8 (said 0.4.3)", profile="keripy-1x-interop"))
    assert R.result_path(doc).as_posix() == "cesrox/0.1.8-said-0.4.3/keripy-1x-interop.json"


# --- meaning ------------------------------------------------------------------------------------

def test_a_consistent_result_has_no_problem():
    assert R.result_problem(result()) is None
    assert R.result_problem(result(provenance=REPRODUCED)) is None


def test_shape_is_checked_before_meaning():
    doc = result()
    del doc["report"]["summary"]
    assert "summary" in R.result_problem(doc)
    assert R.result_problem([]) == "the document must be an object"


def test_an_unpublishable_name_is_refused():
    assert "name" in R.result_problem(result(report(name="()")))
    assert "version" in R.result_problem(result(report(version="..")))


def test_a_case_whose_adapter_failed_must_fail_every_assertion():
    """Hostile pass on #18: a failure recorded on a case cannot sit beside passing assertions."""
    entry = case()
    entry["failure"] = {"kind": "timeout", "detail": "adapter never answered"}
    assert "failure" in R.result_problem(result(report([entry])))
    failed = case(outcome="fail", records=[record(outcome="fail", detail="adapter never answered")])
    failed["failure"] = {"kind": "timeout", "detail": "adapter never answered"}
    assert R.result_problem(result(report([failed]))) is None


@pytest.mark.parametrize("name", ["index", "Index", "index.md", "keripy.md"])
def test_a_name_that_collides_with_a_page_is_refused(name):
    """Hostile pass on #18: results/index.md is the index page, so no slug may be "index" or end
    in ".md"."""
    assert "name" in R.result_problem(result(report(name=name)))
    assert "version" in R.result_problem(result(report(version=name)))


def test_a_suite_version_component_is_bounded():
    """Hostile pass on #18: the site sorts versions numerically, so each component is short."""
    assert R.result_problem(result(report(suite_version="999999999.1"))) is None
    assert "suite_version" in R.result_problem(result(report(suite_version="1" * 10 + ".1")))
    # A suffix may not carry digits on into the last component (panel review of the fix).
    assert "suite_version" in R.result_problem(result(report(suite_version="1.0.0.1234567890")))
    assert R.result_problem(result(report(suite_version="0.1.0-rc.1"))) is None


def test_a_case_from_another_profile_is_refused():
    doc = result(report([case(profile="keri-1.0")]))
    assert "profile" in R.result_problem(doc)


def test_a_repeated_case_is_refused():
    doc = result(report([case(), case()]))
    assert "twice" in R.result_problem(doc)


def test_a_repeated_assertion_is_refused():
    """Copilot on #18: a repeated passing assertion inflates a summary that still agrees with the
    cases, so an assertion id may appear only once in its case."""
    doc = result(report([case(records=[record(), record()])]))
    assert "a1" in R.result_problem(doc) and "twice" in R.result_problem(doc)
    assert R.result_problem(result(report([case(records=[record(), record("a2")])]))) is None


def test_text_that_is_not_valid_unicode_is_refused(tmp_path):
    """Hostile fix pass on #18: JSON can carry a lone surrogate, which no UTF-8 file or page can
    hold, so a result carrying one is refused before anything is written."""
    rep = report(name="keripy\ud800")
    assert "Unicode" in R.result_problem(result(rep))
    source = tmp_path / "report.json"
    source.write_text(json.dumps(rep))
    refused(R.E_RESULT_FORMAT, R.wrap, source, SUBMITTED, tmp_path / "out")
    assert not (tmp_path / "out").exists() or not any((tmp_path / "out").rglob("*"))


def test_assertion_ids_are_checked_in_linear_time():
    """Hostile fix pass on #18: the repeat check must not rescan the list for every id."""
    import time
    records = [record(f"a{n}") for n in range(20000)]
    doc = result(report([case(records=records)]))
    started = time.perf_counter()
    R.result_problem(doc)
    assert time.perf_counter() - started < 3  # the quadratic check took about 9 seconds here


@pytest.mark.parametrize("provenance", [SUBMITTED, REPRODUCED])
@pytest.mark.parametrize("date", ["2026-02-30", "2025-02-29", "2026-04-31"])
def test_an_impossible_date_is_refused(provenance, date):
    """Copilot on #18: the date pattern is only syntax, so the calendar is checked as meaning."""
    doc = result(provenance={**provenance, "date": date})
    assert R.shape_problem(doc) is None
    assert "date" in R.result_problem(doc)
    assert R.result_problem(result(provenance={**provenance, "date": "2024-02-29"})) is None


@pytest.mark.parametrize(("outcome", "records"), [
    ("pass", [record(outcome="fail")]),
    ("fail", [record(outcome="pass")]),
    ("skipped", [record(outcome="pass")]),
    ("not-supported", [record(outcome="skipped")]),
])
def test_a_case_outcome_must_follow_from_its_assertions(outcome, records):
    doc = result(report([case(outcome=outcome, records=records)]))
    assert "outcome" in R.result_problem(doc)


@pytest.mark.parametrize(("outcome", "records"), [
    ("incomplete", [record(outcome="not-implemented"), record("a2")]),
    ("skipped", [record(outcome="skipped")]),
    ("not-supported", [record(outcome="not-supported")]),
    ("pass", [record(outcome="not-applicable"), record("a2")]),
])
def test_consistent_case_outcomes(outcome, records):
    assert R.result_problem(result(report([case(outcome=outcome, records=records)]))) is None


def test_an_edited_summary_is_refused():
    doc = result()
    doc["report"]["summary"]["counts"]["active"]["MUST"]["pass"] = 9
    assert "summary" in R.result_problem(doc)


def test_an_edited_verdict_is_refused():
    doc = result(report([case(outcome="fail", records=[record(outcome="fail")])]))
    doc["report"]["verdict"] = "conformant"
    assert "verdict" in R.result_problem(doc)


def test_an_aborted_report_must_say_aborted():
    aborted = {"code": "e.x.f", "reason": "r", "problems": [], "at_case": "CESR-0001",
               "exit_code": 3}
    assert R.result_problem(result(report(aborted=aborted))) is None
    doc = result(report(aborted=aborted))
    doc["report"]["verdict"] = "conformant"
    assert "verdict" in R.result_problem(doc)


# --- loading ------------------------------------------------------------------------------------

def test_load_reads_every_result_sorted(tmp_path):
    put(tmp_path, result(report(name="zeta")))
    put(tmp_path, result(report(name="alpha", profile="keri-1.0",
                                cases=[case("KERI-0001", profile="keri-1.0")])))
    put(tmp_path, result(report(name="alpha")))
    (tmp_path / "README.md").write_text("about\n")
    loaded = R.load_results(tmp_path, kinds=("submitted",))
    assert [r.path.as_posix() for r in loaded] == [
        "alpha/2.1.0.dev1/cesr-1.0.json", "alpha/2.1.0.dev1/keri-1.0.json",
        "zeta/2.1.0.dev1/cesr-1.0.json"]
    assert loaded[0].doc["report"]["hello"]["implementation"]["name"] == "alpha"


def test_load_of_an_empty_tree_is_empty(tmp_path):
    assert R.load_results(tmp_path, kinds=("submitted",)) == []


def test_a_directory_that_cannot_be_scanned_is_refused(tmp_path, monkeypatch):
    """Hostile pass on #18: os.walk swallows scan errors unless told otherwise."""
    put(tmp_path, result())
    real = os.scandir

    def deny(path):
        if str(path) == str(tmp_path):
            raise PermissionError(errno.EACCES, "denied", str(path))
        return real(path)

    monkeypatch.setattr(os, "scandir", deny)
    refused(R.E_RESULT_READ, R.load_results, tmp_path, kinds=("submitted",))


def test_a_missing_directory_is_refused(tmp_path):
    refused(R.E_RESULTS_MISSING, R.load_results, tmp_path / "nope", kinds=("submitted",))


def test_a_kind_the_directory_may_not_hold_is_refused(tmp_path):
    put(tmp_path, result(provenance=REPRODUCED))
    message = refused(R.E_RESULT_PROVENANCE, R.load_results, tmp_path, kinds=("submitted",))
    assert "reproduced" in message
    assert len(R.load_results(tmp_path, kinds=("reproduced",))) == 1


def test_a_result_at_the_wrong_path_is_refused(tmp_path):
    put(tmp_path, result(), "keripy/9.9.9/cesr-1.0.json")
    message = refused(R.E_RESULT_PATH, R.load_results, tmp_path, kinds=("submitted",))
    assert "keripy/2.1.0.dev1/cesr-1.0.json" in message


@pytest.mark.parametrize("rel", ["stray.json", "keripy/x.json", "keripy/2/cesr/x.json",
                                 "keripy/2/notes.txt", "keripy/README.md", ".hidden.json"])
def test_anything_outside_the_layout_is_refused(tmp_path, rel):
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{}")
    refused(R.E_RESULT_PATH, R.load_results, tmp_path, kinds=("submitted",))


def test_a_symlink_is_refused(tmp_path):
    put(tmp_path, result())
    (tmp_path / "keripy" / "link").symlink_to(tmp_path / "keripy" / "2.1.0.dev1")
    message = refused(R.E_RESULT_PATH, R.load_results, tmp_path, kinds=("submitted",))
    assert "symbolic link" in message


def test_too_many_files_are_refused_before_any_is_read(tmp_path):
    for n in range(3):
        put(tmp_path, {"not": "read"}, f"impl{n}/1/cesr-1.0.json")
    refused(R.E_RESULTS_COUNT, R.load_results, tmp_path, kinds=("submitted",), max_files=2)


def test_too_many_bytes_are_refused_before_any_is_read(tmp_path):
    for n in range(2):
        put(tmp_path, {"not": "read", "pad": "x" * 100}, f"impl{n}/1/cesr-1.0.json")
    refused(R.E_RESULTS_BYTES, R.load_results, tmp_path, kinds=("submitted",),
            max_total_bytes=150)


def test_an_oversized_file_is_refused(tmp_path):
    put(tmp_path, result())
    refused(R.E_RESULT_SIZE, R.load_results, tmp_path, kinds=("submitted",), max_bytes=100)


def test_a_file_that_is_not_json_is_refused(tmp_path):
    path = put(tmp_path, result())
    path.write_text("{")
    refused(R.E_RESULT_FORMAT, R.load_results, tmp_path, kinds=("submitted",))


def test_a_malformed_result_is_refused_naming_its_file(tmp_path):
    doc = result()
    path = put(tmp_path, doc)
    doc["report"]["verdict"] = "great"
    path.write_text(json.dumps(doc))
    message = refused(R.E_RESULT_FORMAT, R.load_results, tmp_path, kinds=("submitted",))
    assert str(path) in message and "verdict" in message


def test_an_unreadable_file_is_refused(tmp_path, monkeypatch):
    put(tmp_path, result())

    def fail(transient):
        def read(path, max_bytes):
            raise JsonFileError("could not be read: denied", "io", transient)
        return read

    monkeypatch.setattr(R, "read_json", fail(False))
    refused(R.E_RESULT_READ, R.load_results, tmp_path, kinds=("submitted",))
    monkeypatch.setattr(R, "read_json", fail(True))
    refused(R.E_RESULT_READ_TRANSIENT, R.load_results, tmp_path, kinds=("submitted",))


def test_a_file_that_cannot_be_sized_is_refused(tmp_path, monkeypatch):
    put(tmp_path, result())

    def fail(path):
        raise OSError(errno.EIO, "I/O error")

    monkeypatch.setattr(R.os.path, "getsize", fail)
    refused(R.E_RESULT_READ_TRANSIENT, R.load_results, tmp_path, kinds=("submitted",))

    def fail_hard(path):
        raise OSError(errno.EACCES, "Permission denied")

    monkeypatch.setattr(R.os.path, "getsize", fail_hard)
    refused(R.E_RESULT_READ, R.load_results, tmp_path, kinds=("submitted",))


# --- wrap ---------------------------------------------------------------------------------------

def test_wrap_writes_the_envelope_at_its_path(tmp_path):
    source = tmp_path / "report.json"
    source.write_text(json.dumps(report(version="0.1.8 (said 0.4.3)")))
    into = tmp_path / "results"
    written = R.wrap(source, SUBMITTED, into)
    assert written == into / "keripy" / "0.1.8-said-0.4.3" / "cesr-1.0.json"
    doc = json.loads(written.read_text())
    assert doc == result(report(version="0.1.8 (said 0.4.3)"), SUBMITTED)
    assert R.load_results(into, kinds=("submitted",))[0].doc == doc
    assert written.read_text().endswith("}\n")


def test_wrap_refuses_to_overwrite(tmp_path):
    source = tmp_path / "report.json"
    source.write_text(json.dumps(report()))
    R.wrap(source, SUBMITTED, tmp_path / "out")
    refused(R.E_RESULT_EXISTS, R.wrap, source, SUBMITTED, tmp_path / "out")


def test_wrap_never_replaces_a_file_that_appears_after_its_check(tmp_path, monkeypatch):
    """Copilot on #18: a result created between the existence check and the write must survive,
    and the temporary file must not be left behind."""
    source = tmp_path / "report.json"
    source.write_text(json.dumps(report()))
    into = tmp_path / "out"
    target = into / R.result_path(result())
    real = R.tempfile.mkstemp

    def racing(*args, **kwargs):
        target.write_text("theirs")
        return real(*args, **kwargs)

    monkeypatch.setattr(R.tempfile, "mkstemp", racing)
    refused(R.E_RESULT_EXISTS, R.wrap, source, SUBMITTED, into)
    assert target.read_text() == "theirs"
    assert [p.name for p in target.parent.iterdir()] == [target.name]


def test_wrap_refuses_an_inconsistent_report_and_writes_nothing(tmp_path):
    rep = report()
    rep["verdict"] = "not-conformant"
    source = tmp_path / "report.json"
    source.write_text(json.dumps(rep))
    refused(R.E_RESULT_FORMAT, R.wrap, source, SUBMITTED, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_wrap_refuses_a_missing_report(tmp_path):
    refused(R.E_RESULT_READ, R.wrap, tmp_path / "none.json", SUBMITTED, tmp_path / "out")


def test_wrap_reports_a_write_failure(tmp_path, monkeypatch):
    source = tmp_path / "report.json"
    source.write_text(json.dumps(report()))

    def fail(*args, **kwargs):
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(R.os, "link", fail)
    refused(R.E_RESULT_WRITE, R.wrap, source, SUBMITTED, tmp_path / "out")
    assert not [p for p in (tmp_path / "out").rglob("*") if p.is_file()]

    def fail_soft(*args, **kwargs):
        raise OSError(errno.EAGAIN, "Try again")

    monkeypatch.setattr(R.os, "link", fail_soft)
    refused(R.E_RESULT_WRITE_TRANSIENT, R.wrap, source, SUBMITTED, tmp_path / "out")


def test_wrap_reports_a_temporary_file_it_could_not_remove(tmp_path, monkeypatch):
    """Hostile fix pass on #18: the result is published, but a leftover temporary file would make
    the next results check refuse the directory, so say so with a code instead of crashing."""
    source = tmp_path / "report.json"
    source.write_text(json.dumps(report()))

    def deny(path):
        raise PermissionError(errno.EACCES, "Permission denied")

    monkeypatch.setattr(R.os, "unlink", deny)
    message = refused(R.E_RESULT_WRITE, R.wrap, source, SUBMITTED, tmp_path / "out")
    assert "temporary file" in message
    assert (tmp_path / "out" / R.result_path(result(report()))).is_file()

    def busy(path):
        raise OSError(errno.EAGAIN, "Try again")

    monkeypatch.setattr(R.os, "unlink", busy)
    refused(R.E_RESULT_WRITE_TRANSIENT, R.wrap, source, SUBMITTED, tmp_path / "again")


def test_a_failed_cleanup_never_hides_the_write_failure(tmp_path, monkeypatch):
    source = tmp_path / "report.json"
    source.write_text(json.dumps(report()))

    def fail(*args, **kwargs):
        raise OSError(errno.ENOSPC, "No space left on device")

    def deny(path):
        raise PermissionError(errno.EACCES, "Permission denied")

    monkeypatch.setattr(R.os, "link", fail)
    monkeypatch.setattr(R.os, "unlink", deny)
    message = refused(R.E_RESULT_WRITE, R.wrap, source, SUBMITTED, tmp_path / "out")
    assert "No space left" in message


# --- command line -------------------------------------------------------------------------------

def test_check_command(tmp_path, capsys):
    put(tmp_path, result())
    assert R.main(["check", str(tmp_path)]) == 0
    assert "1 result" in capsys.readouterr().out
    put(tmp_path, result(provenance=REPRODUCED), "x/1/cesr-1.0.json")
    assert R.main(["check", str(tmp_path)]) == 4
    assert R.E_RESULT_PROVENANCE in capsys.readouterr().err


def test_wrap_command_submitted(tmp_path, capsys):
    source = tmp_path / "report.json"
    source.write_text(json.dumps(report()))
    code = R.main(["wrap", str(source), "--into", str(tmp_path / "r"), "--date", "2026-10-09",
                   "--submitted", "--submitter", "Jane Maintainer", "--pull-request",
                   SUBMITTED["pull_request"]])
    assert code == 0
    written = tmp_path / "r" / "keripy" / "2.1.0.dev1" / "cesr-1.0.json"
    assert str(written) in capsys.readouterr().out
    assert json.loads(written.read_text())["provenance"] == SUBMITTED


def test_wrap_command_reproduced(tmp_path):
    source = tmp_path / "report.json"
    source.write_text(json.dumps(report()))
    code = R.main(["wrap", str(source), "--into", str(tmp_path / "r"), "--date", "2026-10-09",
                   "--reproduced", "--run", REPRODUCED["run"], "--commit", "0" * 40])
    assert code == 0
    written = tmp_path / "r" / "keripy" / "2.1.0.dev1" / "cesr-1.0.json"
    assert json.loads(written.read_text())["provenance"] == REPRODUCED


@pytest.mark.parametrize("args", [
    [],
    ["wrap", "r.json", "--into", "o", "--date", "2026-10-09", "--submitted"],
    ["wrap", "r.json", "--into", "o", "--date", "2026-10-09", "--reproduced", "--run", "x"],
    ["wrap", "r.json", "--into", "o", "--date", "2026-10-09"],
    ["frobnicate"],
])
def test_usage_errors(args, capsys):
    assert R.main(args) == 2
    assert "e.input." in capsys.readouterr().err


def test_wrap_command_refuses_a_bad_provenance(tmp_path, capsys):
    source = tmp_path / "report.json"
    source.write_text(json.dumps(report()))
    code = R.main(["wrap", str(source), "--into", str(tmp_path / "r"), "--date", "yesterday",
                   "--submitted", "--submitter", "J", "--pull-request", "x"])
    assert code == 4
    assert R.E_RESULT_FORMAT in capsys.readouterr().err


def test_module_entry_point_runs(tmp_path):
    import subprocess
    import sys

    from conftest import ROOT

    out = subprocess.run([sys.executable, str(ROOT / "scripts" / "results"), "check",
                          str(tmp_path)], capture_output=True, text=True, check=False,
                         env={**os.environ, "PYTHONPATH": str(ROOT / "src")})
    assert out.returncode == 0, out.stderr
