"""`kcs check-adapter`: probes against fake adapters running as real subprocesses."""

import json
import shlex

import pytest
from conftest import ROOT, bad, good

from keri_conformance import cli, errors
from keri_conformance.check import PROBES, check_adapter
from keri_conformance.session import AdapterSession, Limits


def probes(argv, vocabulary, timeout=5.0):
    session = AdapterSession(argv, vocabulary, limits=Limits(timeout=timeout))
    with session:
        return {p.name: p for p in check_adapter(session)}


def test_probe_names_are_stable():
    assert PROBES == ("hello", "id-echo", "malformed-request", "unknown-op", "statelessness",
                      "quiescence")


def test_a_good_adapter_passes_every_available_probe(vocabulary):
    result = probes(good(), vocabulary)
    assert [result[n].status for n in PROBES] == ["pass", "pass", "pass", "pass",
                                                  "not-yet-available", "not-yet-available"]
    assert "error" in result["malformed-request"].reason
    assert all(p.reason for p in result.values())


def test_an_adapter_that_ignores_a_malformed_line_survives(vocabulary):
    result = probes(bad("silent-on-junk"), vocabulary)
    assert result["malformed-request"].status == "pass"
    assert "survived" in result["malformed-request"].reason


def test_an_adapter_that_crashes_on_a_malformed_line_fails(vocabulary):
    result = probes(bad("crash-on-junk"), vocabulary)
    assert result["malformed-request"].status == "fail"
    assert "exited" in result["malformed-request"].reason
    assert result["unknown-op"].status == "fail"  # crash-on-junk crashes on the next request too


def test_a_wrong_id_fails_the_echo_probe(vocabulary):
    result = probes(bad("wrong-id"), vocabulary)
    assert result["id-echo"].status == "fail"
    assert "id" in result["id-echo"].reason


@pytest.mark.parametrize("mode", ["junk", "hang"])
def test_an_unanswered_echo_probe_fails(vocabulary, mode):
    result = probes(bad(mode), vocabulary, timeout=0.5)
    assert result["id-echo"].status == "fail"


def test_an_error_reply_still_echoes_the_id(vocabulary):
    result = probes(bad("error-harness"), vocabulary)
    assert result["id-echo"].status == "pass"
    assert result["unknown-op"].status == "pass"


def test_answering_an_unknown_op_with_a_result_fails(vocabulary):
    result = probes(bad("answer-all"), vocabulary)
    assert result["unknown-op"].status == "fail"
    assert "result" in result["unknown-op"].reason
    assert result["id-echo"].status == "pass"  # the echo probe checks the id, not the shape


@pytest.mark.parametrize(
    ("first", "second", "status"),
    [
        (b'{"id": null, "error": {"kind": "harness", "message": "bad json"}}', None, "pass"),
        (b'{"id": 3, "error": {"kind": "harness", "message": "bad json"}}', None, "fail"),
        (b'{"id": null, "result": {}}', None, "fail"),
        (b"[]", None, "fail"),
        (b"garbage", None, "fail"),
        (b'{"id": null, "error": {"kind": "harness", "message": "bad json"}}', b"EXIT", "fail"),
        (b'{"id": null, "error": {"kind": "harness", "message": "bad json"}}', b"junk", "fail"),
    ],
)
def test_malformed_probe_reply_shapes(vocabulary, write_json, first, second, status):
    # A table-driven good adapter cannot answer a non-JSON line with these shapes, so the probe
    # is driven against a scripted adapter instead.
    lines = [first, second] if second else [first]
    script = write_json("lines.json", [line.decode() for line in lines])
    argv = [*good()[:1], str(ROOT / "tests" / "fakes" / "scripted.py"), str(script)]
    result = probes(argv, vocabulary, timeout=1.0)
    assert result["malformed-request"].status == status, result["malformed-request"].reason


def test_a_refused_hello_fails_and_skips_the_rest(vocabulary):
    result = probes(bad("hello-crash"), vocabulary)
    assert result["hello"].status == "fail"
    assert [result[n].status for n in PROBES[1:4]] == ["not-run"] * 3


def test_a_hello_that_changes_on_restart_fails_the_probe_that_restarted(vocabulary, monkeypatch):
    from keri_conformance import session as session_module

    real = session_module.AdapterSession._start
    starts = []

    def start(self):
        starts.append(1)
        hello = real(self)
        return {**hello, "adapter": {"name": "other", "version": "9"}} if len(starts) > 1 else hello

    monkeypatch.setattr(session_module.AdapterSession, "_start", start)
    result = probes(bad("wrong-id"), vocabulary)
    assert result["id-echo"].status == "fail"
    assert result["malformed-request"].status == "fail"
    assert errors.E_ADAPTER_HELLO_CHANGED in result["malformed-request"].reason


# --- the command --------------------------------------------------------------------------------


def check(argv, *extra):
    return cli.main(["check-adapter", shlex.join(argv), "--suite", str(ROOT), *extra])


def test_cli_exit_0_when_every_available_probe_passes(capsys):
    assert check(good()) == 0
    out = capsys.readouterr().out
    assert "pass  hello" in out
    assert "not-yet-available  statelessness" in out


def test_cli_exit_1_when_a_probe_fails(capsys):
    assert check(bad("wrong-id"), "--timeout", "2") == 1
    assert "fail  id-echo" in capsys.readouterr().out


def test_cli_runner_fault_when_the_adapter_cannot_start(tmp_path, capsys):
    assert check([str(tmp_path / "missing")]) == errors.EXIT_FAULT
    assert errors.E_ADAPTER_START in capsys.readouterr().err


def test_cli_passes_environment_through(tmp_path, monkeypatch):
    monkeypatch.setenv("KCS_CHECK_PASS", "1")
    dump = tmp_path / "env.json"
    assert check(good("--env-dump", dump), "--pass-env", "KCS_CHECK_PASS") == 0
    assert json.loads(dump.read_text())["KCS_CHECK_PASS"] == "1"


def test_cli_help_documents_exit_codes(capsys):
    with pytest.raises(SystemExit):
        cli.main(["check-adapter", "--help"])
    out = capsys.readouterr().out
    assert "  0  " in out and "  1  " in out and "  4  " in out
