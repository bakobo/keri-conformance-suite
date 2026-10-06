"""`kcs run` end to end against fake adapters running as real subprocesses."""

import json
import os
import shlex
import tomllib

import pytest
from conftest import ROOT, assertion, bad, good, make_case

from keri_conformance import __version__, cli, errors
from keri_conformance import session as session_module
from keri_conformance.protocol import PROTOCOL_VERSION

SUITE_VERSION = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]

STATE = {"sn": 0, "said": "EAbc", "keys": ["DAbc"], "kt": "0x1", "ndigs": ["EGhi"], "nt": "1",
         "wits": [], "bt": "0", "delegator": None}

HELLO = {
    "protocol": 1,
    "adapter": {"name": "x", "version": "1"},
    "implementation": {"name": "i", "version": "1", "commit": "c"},
    "operations": ["cesr.parse"],
    "features": ["cesr.genus-2.00"],
}

PASSING = [
    make_case("CESR-0001", "cesr.parse", {"stream": "2d4b"}, [assertion("rejected")],
              features=["cesr.genus-2.00"]),
    make_case("CESR-0002", "cesr.parse", {"stream": "00"}, [assertion("decoded", expected=[
        {"kind": "counter", "start": 0, "end": 4, "code": "-K", "size": 0, "group_end": 4}])]),
    make_case("CESR-0003", "cesr.encode", {"code": "E", "raw": "00", "domain": "text"},
              [assertion("encoded", expected="10"),
               assertion("encoded", name="a2", level="SHOULD", expected="11")]),
    make_case("KERI-0001", "keri.process",
              {"perspective": {"role": "validator"},
               "messages": [{"stream": "7b7d", "source": "controller"}]},
              [assertion("disposition", message=0, phase="final", expected="seen"),
               assertion("key_state", name="a2", level="SHOULD", if_seen=0, aid="EAbc",
                         expected=STATE)],
              features=["kel.basic"], reference={"implementation": "fake-impl", "commit": "0123abc"},
              profile="keri-1.0"),
]
NOT_SUPPORTED = make_case("KERI-0002", "keri.process",
                          {"perspective": {"role": "validator"},
                           "messages": [{"stream": "7b7d", "source": "controller"}]},
                          [assertion("disposition", message=0, phase="final", expected="pending")],
                          features=["kel.delegation"])
DEPRECATED = make_case("CESR-0009", "cesr.parse", {"stream": "00"}, [assertion("rejected")],
                       status="deprecated")
DRAFT_FAIL = make_case("CESR-0010", "cesr.parse", {"stream": "00"}, [assertion("rejected")],
                       status="draft")
DISPUTED_FAIL = make_case("CESR-0011", "cesr.parse", {"stream": "00"}, [assertion("rejected")],
                          status="disputed")
ACTIVE_FAIL = make_case("CESR-0012", "cesr.parse", {"stream": "00"}, [assertion("rejected")])
EMIT = make_case("KERI-0003", "keri.emit", {"event": {"t": "icp"}, "seeds": {"DAbc": "00"}},
                 [assertion("emitted_body", expected="7b7d")])


def run(argv_adapter, cases, tmp_path, *extra):
    report = tmp_path / "report.json"
    code = cli.main(["run", "--adapter", shlex.join(argv_adapter), "--suite", str(ROOT),
                     "--cases", str(cases), "--report", str(report), *extra])
    return code, (json.loads(report.read_text()) if report.exists() else None)


def by_id(report):
    return {c["id"]: c for c in report["cases"]}


def test_a_conformant_run(cases_dir, tmp_path, capsys):
    cases = cases_dir(*PASSING, NOT_SUPPORTED, DEPRECATED, DRAFT_FAIL, DISPUTED_FAIL)
    code, report = run(good(), cases, tmp_path)
    assert code == errors.EXIT_CONFORMANT
    assert report["verdict"] == "conformant"
    assert report["runner_version"] == __version__
    assert report["suite_version"] == SUITE_VERSION
    assert report["protocol_version"] == PROTOCOL_VERSION
    assert report["negotiated_protocol"] == 1
    assert report["supported_protocols"] == [1]
    assert report["hello"]["composes"] == ["keri.escrow"]
    assert report["declared_features"] == report["hello"]["features"]
    assert report["composes"] == ["keri.escrow"]
    assert report["filters"] == {"profile": None, "cases_dir": str(cases)}
    cases_ = by_id(report)
    assert [c["id"] for c in report["cases"]] == sorted(cases_)
    assert cases_["CESR-0001"]["outcome"] == "pass"
    assert cases_["CESR-0003"]["outcome"] == "fail"  # the SHOULD fails
    assert cases_["CESR-0003"]["assertions"][1]["actual"] == "10"
    assert cases_["KERI-0002"]["outcome"] == "not-supported"
    assert cases_["KERI-0002"]["missing_features"] == ["kel.delegation"]
    assert cases_["CESR-0009"]["outcome"] == "skipped"
    assert cases_["CESR-0010"]["outcome"] == "fail"
    assert cases_["CESR-0011"]["outcome"] == "fail"
    counts = report["summary"]["counts"]
    assert counts["active"]["MUST"] == {"pass": 4, "not-supported": 1}
    assert counts["active"]["SHOULD"] == {"pass": 1, "fail": 1}
    assert counts["draft"]["MUST"] == {"fail": 1}
    assert counts["disputed"]["MUST"] == {"fail": 1}
    assert counts["deprecated"]["MUST"] == {"skipped": 1}
    assert report["summary"]["not_supported_active"] == ["KERI-0002"]
    # A claim states its SHOULD results beside the MUST verdict (docs/design.md, Versioning).
    assert report["summary"]["should"] == {"pass": 1, "fail": 1}
    assert report["summary"]["should_failed"] == 1
    out = capsys.readouterr().out
    assert "conformant" in out
    assert "fake-adapter" in out
    assert "active SHOULD assertions: 1 fail, 1 pass" in out
    assert "1 active SHOULD assertion failed" in out
    assert "1 active SHOULD assertion failed" in report["summary"]["should_warning"]


def test_a_run_whose_should_assertions_all_pass_says_nothing_more(cases_dir, tmp_path, capsys):
    _code, report = run(good(), cases_dir(*PASSING[:2]), tmp_path)
    assert report["summary"]["should"] == {}
    assert report["summary"]["should_failed"] == 0
    assert report["summary"]["should_warning"] is None
    out = capsys.readouterr().out
    assert "active SHOULD assertions: none" in out
    assert "SHOULD assertion failed" not in out


NOT_SEEN = [{"match": {"op": "keri.process"}, "result": {
    "dispositions": [{"initial": "pending", "final": "pending", "trunk": False}],
    "key_states": {}}}]


def test_a_conditional_key_state_whose_message_was_not_seen_does_not_apply(cases_dir, tmp_path,
                                                                           write_json):
    case = make_case("KERI-0006", "keri.process", PASSING[3]["input"],
                     [assertion("disposition", message=0, phase="final", expected="not-seen"),
                      assertion("key_state", name="a2", if_seen=0, aid="EAbc", expected=STATE)])
    code, report = run(good("--table", write_json("t.json", NOT_SEEN)), cases_dir(case),
                       tmp_path)
    entry = report["cases"][0]
    assert [a["outcome"] for a in entry["assertions"]] == ["pass", "not-applicable"]
    assert entry["outcome"] == "pass"
    assert report["summary"]["counts"]["active"]["MUST"] == {"pass": 1, "not-applicable": 1}
    assert (code, report["verdict"]) == (errors.EXIT_CONFORMANT, "conformant")


def test_not_applicable_is_not_evidence(cases_dir, tmp_path, write_json):
    case = make_case("KERI-0007", "keri.process", PASSING[3]["input"],
                     [assertion("key_state", if_seen=0, aid="EAbc", expected=STATE)])
    code, report = run(good("--table", write_json("t.json", NOT_SEEN)), cases_dir(case),
                       tmp_path)
    assert (code, report["verdict"]) == (errors.EXIT_NO_EVIDENCE, "no-evidence")


def test_self_agreement_marks_passes_when_the_reference_is_under_test(cases_dir, tmp_path):
    _code, report = run(good(), cases_dir(*PASSING), tmp_path)
    keri = by_id(report)["KERI-0001"]
    assert [a["self_agreement"] for a in keri["assertions"]] == [True, True]
    assert by_id(report)["CESR-0001"]["assertions"][0]["self_agreement"] is False
    assert report["summary"]["self_agreement_passes"] == 2


def test_an_active_must_failure_is_not_conformant(cases_dir, tmp_path, capsys):
    code, report = run(good(), cases_dir(PASSING[0], ACTIVE_FAIL), tmp_path)
    assert code == errors.EXIT_FAILED
    assert report["verdict"] == "not-conformant"
    assert "not-conformant" in capsys.readouterr().out


def test_an_unevaluable_must_is_incomplete(cases_dir, tmp_path):
    code, report = run(good(), cases_dir(PASSING[0], EMIT), tmp_path)
    assert code == errors.EXIT_FAULT
    assert report["verdict"] == "incomplete"
    emit = by_id(report)["KERI-0003"]
    assert emit["outcome"] == "incomplete"
    assert emit["assertions"][0]["outcome"] == "not-implemented"


def test_the_profile_filter(cases_dir, tmp_path):
    _code, report = run(good(), cases_dir(*PASSING), tmp_path, "--profile", "keri-1.0")
    assert [c["id"] for c in report["cases"]] == ["KERI-0001"]
    assert report["filters"]["profile"] == "keri-1.0"


def test_an_undeclared_operation_is_not_supported_and_not_sent(cases_dir, tmp_path, write_json):
    path = write_json("hello.json", HELLO)
    _code, report = run(good("--hello", path), cases_dir(PASSING[0], PASSING[2]), tmp_path)
    assert by_id(report)["CESR-0003"]["outcome"] == "not-supported"
    assert by_id(report)["CESR-0003"]["missing_operation"] == "cesr.encode"


def test_a_crashing_adapter_fails_every_assertion_and_is_restarted(cases_dir, tmp_path):
    cases = cases_dir(PASSING[0], PASSING[2])
    code, report = run(bad("crash"), cases, tmp_path)
    assert code == errors.EXIT_FAILED
    for case in report["cases"]:
        assert case["outcome"] == "fail"
        assert case["failure"]["kind"] == "exited"
        assert "boom" in case["stderr"]
        assert all(a["outcome"] == "fail" and a["actual"] is None for a in case["assertions"])


def test_a_partial_result_shape_fails_every_assertion(cases_dir, tmp_path, write_json):
    table = write_json("table.json", [{"match": {"op": "cesr.parse"}, "result": {"items": [
        {"kind": "counter", "start": 0, "end": 4, "code": "-K", "size": 0}]}}])
    code, report = run(good("--table", table), cases_dir(PASSING[1]), tmp_path)
    case = report["cases"][0]
    assert code == errors.EXIT_FAILED
    assert case["failure"]["kind"] == "malformed"
    assert "group_end" in case["failure"]["detail"]
    assert [a["outcome"] for a in case["assertions"]] == ["fail"]


def test_too_few_dispositions_fail_the_case_end_to_end(cases_dir, tmp_path):
    two = make_case("KERI-0009", "keri.process",
                    {"perspective": {"role": "validator"},
                     "messages": [{"stream": "7b7d", "source": "controller"}] * 2},
                    [assertion("disposition", message=0, phase="final", expected="seen")])
    code, report = run(bad("few-dispositions"), cases_dir(two), tmp_path)
    case = report["cases"][0]
    assert code == errors.EXIT_FAILED
    assert case["failure"]["kind"] == "malformed"
    assert [a["outcome"] for a in case["assertions"]] == ["fail"]


def test_a_case_feature_outside_the_vocabulary_is_a_malformed_case(cases_dir, tmp_path, capsys):
    unknown = make_case("CESR-0030", "cesr.parse", {"stream": "2d4b"}, [assertion("rejected")],
                        features=["cesr.genus-2.00", "kel.teleport"])
    dump = tmp_path / "hello.json"
    code, report = run(good("--hello-dump", dump), cases_dir(PASSING[0], unknown), tmp_path)
    assert code == errors.EXIT_FAULT
    assert report is None
    err = capsys.readouterr().err
    assert errors.E_CASE_FORMAT in err
    assert "CESR-0030" in err
    assert "kel.teleport" in err


def test_the_retained_output_budget_aborts_the_run(cases_dir, tmp_path, capsys, monkeypatch):
    from keri_conformance import run as run_module

    # A one-byte budget is passed by the hello alone, so the run stops after the first case,
    # keeping it, and the second is never sent.
    monkeypatch.setattr(run_module, "MAX_RETAINED_BYTES", 1)
    second = {**PASSING[0], "id": "CESR-0008"}
    code, report = run(good(), cases_dir(PASSING[0], second), tmp_path)
    assert code == errors.EXIT_FAULT
    assert report["verdict"] == "aborted"
    assert report["aborted"]["code"] == errors.E_REPORT_BUDGET
    assert [c["id"] for c in report["cases"]] == ["CESR-0001"]
    assert errors.E_REPORT_BUDGET in capsys.readouterr().err


def test_the_default_budget_is_512_mib():
    from keri_conformance import run as run_module

    assert run_module.MAX_RETAINED_BYTES == 512 * 1024 * 1024


def test_a_hanging_adapter_times_out(cases_dir, tmp_path):
    _code, report = run(bad("hang"), cases_dir(PASSING[0]), tmp_path, "--timeout", "0.5")
    assert report["cases"][0]["failure"]["kind"] == "timeout"


def test_an_oversized_response(cases_dir, tmp_path):
    _code, report = run(bad("oversize", 5000), cases_dir(PASSING[0]), tmp_path,
                       "--max-response", "1000")
    assert report["cases"][0]["failure"]["kind"] == "oversize"


def test_an_error_reply_fails_the_case(cases_dir, tmp_path):
    code, report = run(bad("error-unsupported"), cases_dir(PASSING[0]), tmp_path)
    assert report["cases"][0]["failure"]["kind"] == "error-unsupported"
    assert code == errors.EXIT_FAILED


def test_state_leaking_between_requests_shows_up_in_results(cases_dir, tmp_path):
    first = make_case("KERI-0004", "keri.process", PASSING[3]["input"],
                      [assertion("disposition", message=0, phase="final", expected="seen")])
    second = {**first, "id": "KERI-0005"}
    _code, report = run(bad("leak"), cases_dir(first, second), tmp_path)
    assert [c["outcome"] for c in report["cases"]] == ["pass", "fail"]


def test_pass_env(cases_dir, tmp_path, monkeypatch):
    monkeypatch.setenv("KCS_RUN_PASS", "yes")
    dump = tmp_path / "env.json"
    run(good("--env-dump", dump), cases_dir(PASSING[0]), tmp_path, "--pass-env", "KCS_RUN_PASS")
    assert json.loads(dump.read_text())["KCS_RUN_PASS"] == "yes"


def test_a_refused_hello_exits_3_and_runs_nothing(cases_dir, tmp_path, write_json, capsys):
    path = write_json("hello.json", {"protocol": 1})
    code, report = run(good("--hello", path), cases_dir(PASSING[0]), tmp_path)
    assert code == errors.EXIT_REFUSED
    assert report is None
    err = capsys.readouterr().err
    assert errors.E_ADAPTER_HELLO in err
    assert '"features" is missing.' in err


def test_a_version_outside_supported_exits_3(cases_dir, tmp_path, capsys):
    code, report = run(bad("hello-version"), cases_dir(PASSING[0]), tmp_path)
    assert code == errors.EXIT_REFUSED
    assert report is None
    assert '"supported" list [1]' in capsys.readouterr().err


def test_running_as_root_is_refused(cases_dir, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    code, _report = run(good(), cases_dir(PASSING[0]), tmp_path)
    assert code == errors.EXIT_FAULT
    assert errors.E_ROOT in capsys.readouterr().err


def test_an_adapter_that_cannot_start_is_a_runner_fault(cases_dir, tmp_path, capsys):
    code, _report = run([str(tmp_path / "missing")], cases_dir(PASSING[0]), tmp_path)
    assert code == errors.EXIT_FAULT
    assert errors.E_ADAPTER_START in capsys.readouterr().err


def test_a_malformed_case_is_a_runner_fault(cases_dir, tmp_path, capsys):
    cases = cases_dir(PASSING[0])
    (cases / "broken.json").write_text("{}")
    code, _report = run(good(), cases, tmp_path)
    assert code == errors.EXIT_FAULT
    assert "broken.json" in capsys.readouterr().err


def test_default_cases_dir_is_under_the_suite(tmp_path, cases_dir, capsys):
    cases_dir(PASSING[0])  # creates tmp_path/cases
    (tmp_path / "profiles").mkdir()
    (tmp_path / "profiles" / "features.json").write_text(
        (ROOT / "profiles" / "features.json").read_text())
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "s"\nversion = "9.9.9"\n')
    report = tmp_path / "r.json"
    code = cli.main(["run", "--adapter", shlex.join(good()), "--suite", str(tmp_path),
                     "--report", str(report)])
    assert code == errors.EXIT_CONFORMANT
    data = json.loads(report.read_text())
    assert data["filters"]["cases_dir"] == str(tmp_path / "cases")
    assert data["suite_version"] == "9.9.9"
    assert data["runner_version"] == __version__


def _suite_without_version(tmp_path, cases_dir, pyproject):
    cases_dir(PASSING[0])
    (tmp_path / "profiles").mkdir()
    (tmp_path / "profiles" / "features.json").write_text(
        (ROOT / "profiles" / "features.json").read_text())
    if pyproject is not None:
        (tmp_path / "pyproject.toml").write_bytes(pyproject)


@pytest.mark.parametrize("pyproject", [
    None,
    b'[project]\nname = "s"\n',
    b"[tool.x]\n",
    b'[project]\nversion = 3\n',
    b'[project]\nversion = ""\n',
    b"project = 1\n",
    b"this is = = not toml",
    b"\xff\xfe",
    b"x = 1\n" + b" " * 2_000_000,
], ids=["absent", "no-version", "no-project", "not-a-string", "empty", "project-not-table",
        "not-toml", "not-utf8", "oversized"])
def test_a_suite_without_a_readable_version_is_refused(tmp_path, cases_dir, capsys, pyproject):
    _suite_without_version(tmp_path, cases_dir, pyproject)
    report = tmp_path / "r.json"
    code = cli.main(["run", "--adapter", shlex.join(good()), "--suite", str(tmp_path),
                     "--report", str(report)])
    assert code == errors.EXIT_FAULT
    assert errors.E_SUITE_VERSION in capsys.readouterr().err
    assert not report.exists()


def test_no_report_is_written_unless_asked_for(cases_dir, tmp_path, monkeypatch, capsys):
    cases = cases_dir(PASSING[0])
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    code = cli.main(["run", "--adapter", shlex.join(good()), "--suite", str(ROOT),
                     "--cases", str(cases)])
    assert code == errors.EXIT_CONFORMANT
    assert list(work.iterdir()) == []
    out = capsys.readouterr().out
    assert "verdict: conformant" in out
    assert "report:" not in out


def test_an_unwritable_report_is_a_runner_fault(cases_dir, tmp_path, capsys):
    cases = cases_dir(PASSING[0])
    code = cli.main(["run", "--adapter", shlex.join(good()), "--suite", str(ROOT),
                     "--cases", str(cases), "--report", str(tmp_path)])
    assert code == errors.EXIT_FAULT
    assert errors.E_REPORT_WRITE in capsys.readouterr().err


def test_a_changed_hello_on_restart_aborts(cases_dir, tmp_path, write_json, capsys, monkeypatch):
    # Every request gets a harness error, so the adapter is restarted before the second case; the
    # hello file is rewritten just before that restart.
    path = write_json("hello.json", HELLO)
    table = write_json("table.json", [{"match": {"op": "cesr.parse"},
                                       "error": {"kind": "harness", "message": "x"}}])
    real_start = session_module.AdapterSession._start
    starts = []

    def start(self):
        starts.append(1)
        if len(starts) == 2:
            write_json("hello.json", {**HELLO, "adapter": {"name": "y", "version": "2"}})
        return real_start(self)

    monkeypatch.setattr(session_module.AdapterSession, "_start", start)
    code, report = run(good("--hello", path, "--table", table),
                       cases_dir(PASSING[0], {**PASSING[0], "id": "CESR-0007"}), tmp_path)
    assert code == errors.EXIT_REFUSED
    assert report["verdict"] == "aborted"
    assert report["aborted"]["code"] == errors.E_ADAPTER_HELLO_CHANGED
    assert "differs" in report["aborted"]["reason"]
    assert [c["id"] for c in report["cases"]] == ["CESR-0001"]
    assert errors.E_ADAPTER_HELLO_CHANGED in capsys.readouterr().err


def test_a_refused_hello_on_restart_aborts_with_a_partial_report(cases_dir, tmp_path, write_json,
                                                                  capsys, monkeypatch):
    path = write_json("hello.json", HELLO)
    table = write_json("table.json", [{"match": {"op": "cesr.parse"},
                                       "error": {"kind": "harness", "message": "x"}}])
    real_start = session_module.AdapterSession._start
    starts = []

    def start(self):
        starts.append(1)
        if len(starts) == 2:
            write_json("hello.json", {"protocol": 1})
        return real_start(self)

    monkeypatch.setattr(session_module.AdapterSession, "_start", start)
    cases = cases_dir(PASSING[0], {**PASSING[0], "id": "CESR-0007"},
                      {**PASSING[0], "id": "CESR-0008"})
    code, report = run(good("--hello", path, "--table", table), cases, tmp_path)
    assert code == errors.EXIT_REFUSED
    assert report["verdict"] == "aborted"
    assert report["aborted"]["code"] == errors.E_ADAPTER_HELLO
    assert [c["id"] for c in report["cases"]] == ["CESR-0001"]
    assert '"features" is missing.' in capsys.readouterr().err


def test_an_aborted_run_without_report_still_exits_3(cases_dir, tmp_path, write_json, capsys,
                                                     monkeypatch):
    path = write_json("hello.json", HELLO)
    table = write_json("table.json", [{"match": {"op": "cesr.parse"},
                                       "error": {"kind": "harness", "message": "x"}}])
    real_start = session_module.AdapterSession._start
    starts = []

    def start(self):
        starts.append(1)
        if len(starts) == 2:
            write_json("hello.json", {**HELLO, "adapter": {"name": "y", "version": "2"}})
        return real_start(self)

    monkeypatch.setattr(session_module.AdapterSession, "_start", start)
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    code = cli.main(["run", "--adapter", shlex.join(good("--hello", path, "--table", table)),
                     "--suite", str(ROOT), "--cases",
                     str(cases_dir(PASSING[0], {**PASSING[0], "id": "CESR-0007"}))])
    assert code == errors.EXIT_REFUSED
    assert list(work.iterdir()) == []
    assert "verdict: aborted" in capsys.readouterr().out


@pytest.mark.parametrize("value", ["0", "-1", "x", "nan", "NaN", "inf", "-inf", "Infinity"])
def test_bad_limits_are_coded_usage_errors(value, capsys):
    code = cli.main(["run", "--adapter", "x", "--timeout", value])
    assert code == errors.EXIT_USAGE
    assert capsys.readouterr().err.startswith(f"{errors.E_USAGE_INVALID}: ")


def test_a_missing_adapter_option_is_a_coded_usage_error(capsys):
    code = cli.main(["run"])
    assert code == errors.EXIT_USAGE
    assert capsys.readouterr().err.startswith(f"{errors.E_USAGE_INVALID}: ")


def test_an_empty_adapter_command_is_a_usage_error(cases_dir, capsys):
    code = cli.main(["run", "--adapter", " ", "--suite", str(ROOT), "--cases",
                     str(cases_dir(PASSING[0]))])
    assert code == errors.EXIT_USAGE
    assert errors.E_USAGE_INVALID in capsys.readouterr().err


def test_help_documents_exit_codes(capsys):
    with pytest.raises(SystemExit):
        cli.main(["run", "--help"])
    out = capsys.readouterr().out
    for code in ("0", "1", "2", "3", "4", "5"):
        assert f"  {code}  " in out
    assert "incomplete" in out
    assert "no-evidence" in out
    assert "aborted" in out


def test_a_run_with_no_active_must_evidence_is_no_evidence(cases_dir, tmp_path, capsys):
    should_only = make_case("CESR-0020", "cesr.parse", {"stream": "2d4b"},
                            [assertion("rejected", level="SHOULD")])
    code, report = run(good(), cases_dir(should_only, NOT_SUPPORTED, DRAFT_FAIL), tmp_path)
    assert code == errors.EXIT_NO_EVIDENCE == 5
    assert report["verdict"] == "no-evidence"
    assert "verdict: no-evidence" in capsys.readouterr().out


def test_an_empty_cases_directory_is_no_evidence(cases_dir, tmp_path):
    code, report = run(good(), cases_dir(), tmp_path)
    assert code == errors.EXIT_NO_EVIDENCE
    assert report["cases"] == []


def test_the_skipped_statelessness_probe_is_reported(cases_dir, tmp_path):
    _code, report = run(good(), cases_dir(PASSING[0]), tmp_path)
    assert report["probes"] == {"statelessness": "not-yet-available"}


# --- the accepted summary -----------------------------------------------------------------------


def _summary_table(write_json, consumed):
    return write_json("summary.json", [{"match": {"op": "cesr.parse"},
                                        "result": {"accepted": {"consumed": consumed}}}])


def test_a_summary_fails_a_must_reject_case_with_evidence(cases_dir, tmp_path, write_json):
    # The stream 2d4b is two bytes; the implementation accepted all of it.
    code, report = run(good("--table", _summary_table(write_json, 2)), cases_dir(PASSING[0]),
                       tmp_path)
    case = report["cases"][0]
    assert code == errors.EXIT_FAILED
    assert report["verdict"] == "not-conformant"
    assert case["failure"] is None
    assert case["outcome"] == "fail"
    [record] = case["assertions"]
    assert record["outcome"] == "fail"
    assert record["actual"] == {"accepted": {"consumed": 2}}


def test_a_summary_consuming_part_of_the_stream_still_fails_a_must_reject(cases_dir, tmp_path,
                                                                         write_json):
    code, report = run(good("--table", _summary_table(write_json, 0)), cases_dir(PASSING[0]),
                       tmp_path)
    assert code == errors.EXIT_FAILED
    assert report["cases"][0]["failure"] is None
    assert report["cases"][0]["assertions"][0]["outcome"] == "fail"


def test_a_summary_consuming_more_than_the_stream_is_malformed(cases_dir, tmp_path, write_json):
    code, report = run(good("--table", _summary_table(write_json, 3)), cases_dir(PASSING[0]),
                       tmp_path)
    case = report["cases"][0]
    assert code == errors.EXIT_FAILED
    assert case["failure"]["kind"] == "malformed"
    assert "3 bytes" in case["failure"]["detail"] and "2-byte" in case["failure"]["detail"]
    assert [a["outcome"] for a in case["assertions"]] == ["fail"]


def test_a_summary_answering_a_decoded_case_is_malformed(cases_dir, tmp_path, write_json):
    # The runner sends a decoded case only to an adapter that declares cesr.item-extents, which
    # reports items; a summary there is out of protocol and fails the whole case as malformed.
    code, report = run(good("--table", _summary_table(write_json, 1)), cases_dir(PASSING[1]),
                       tmp_path)
    case = report["cases"][0]
    assert code == errors.EXIT_FAILED
    assert case["failure"]["kind"] == "malformed"
    assert "cesr.item-extents" in case["failure"]["detail"]
    assert [a["outcome"] for a in case["assertions"]] == ["fail"]


def test_a_summary_answering_a_decoded_case_restarts_the_adapter(cases_dir, tmp_path, write_json,
                                                                 monkeypatch):
    # Like every other out-of-protocol answer, it kills the adapter at once, so no state carries
    # into a later case: by the time the run closes the session, there is no process left.
    from keri_conformance import session as session_module

    alive_at_close = []
    real_close = session_module.AdapterSession.close

    def recording_close(self):
        alive_at_close.append(self._proc is not None)
        real_close(self)

    monkeypatch.setattr(session_module.AdapterSession, "close", recording_close)
    run(good("--table", _summary_table(write_json, 1)), cases_dir(PASSING[1]), tmp_path)
    assert alive_at_close == [False]
