"""`kcs check-adapter`: probes against fake adapters running as real subprocesses."""

import copy
import json
import shlex

import issued_world
import pytest
from conftest import ROOT, bad, good

from keri_conformance import cli, errors
from keri_conformance import session as session_module
from keri_conformance.check import _CONTEXT as CONTEXT
from keri_conformance.check import ISSUE_PROBE, PROBES, check_adapter
from keri_conformance.check import exit_code as check_exit_code
from keri_conformance.session import AdapterSession, Limits


def probes(argv, vocabulary, timeout=5.0):
    session = AdapterSession(argv, vocabulary, limits=Limits(timeout=timeout))
    with session:
        return {p.name: p for p in check_adapter(session)}


def test_probe_names_are_stable():
    assert PROBES == ("hello", "id-echo", "malformed-request", "unknown-op", "statelessness",
                      "quiescence", "issue-malformed", "present-malformed",
                      "presentation-malformed", "issue-repeatable", "present-independence")


def test_a_good_adapter_passes_every_available_probe(vocabulary):
    result = probes(good(), vocabulary)
    assert [result[n].status for n in PROBES] == ["pass", "pass", "pass", "pass",
                                                  "not-yet-available", "not-yet-available",
                                                  "not-applicable", "not-applicable",
                                                  "not-applicable", "not-applicable",
                                                  "not-applicable"]
    assert "acdc.issue" in result["issue-malformed"].reason
    assert "error" in result["malformed-request"].reason
    assert all(p.reason for p in result.values())


def test_an_adapter_that_silently_drops_a_malformed_line_fails(vocabulary):
    # Answering the next request is not enough: the unreadable line must get an error response
    # whose id is null, or the runner cannot tell a dropped line from a lost one.
    result = probes(bad("silent-on-junk"), vocabulary)
    assert result["malformed-request"].status == "fail"
    assert "null" in result["malformed-request"].reason


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


@pytest.mark.parametrize("mode", ["error-bad-kind", "error-not-object"])
def test_a_malformed_error_body_fails_the_echo_and_unknown_op_probes(vocabulary, mode):
    result = probes(bad(mode), vocabulary)
    assert result["id-echo"].status == "fail"
    assert result["unknown-op"].status == "fail"
    assert "error" in result["id-echo"].reason


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
        (b'{"id": null, "error": {"kind": "harness", "message": "bad json"}, "x": NaN}', None,
         "fail"),
        (b'{"id": null, "error": {"kind": "oops", "message": "bad json"}}', None, "fail"),
        (b'{"id": null, "error": {"kind": "harness"}}', None, "fail"),
        (b'{"id": null, "error": {"kind": "harness", "message": 3}}', None, "fail"),
        (b'{"id": null, "error": {"kind": "harness", "message": "m", "extra": 1}}', None, "fail"),
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
    assert [result[n].status for n in PROBES[6:10]] == ["not-run"] * 4
    assert [result[n].status for n in PROBES[10:]] == ["not-yet-available"]
    assert all(result[n].reason for n in PROBES)


# --- the issuer and holder probes (docs/adapter-protocol.md, acdc.issue and acdc.present) --------

ISSUER_HELLO = {
    "protocol": 1, "adapter": {"name": "issuer-adapter", "version": "1"},
    "implementation": {"name": "issuer", "version": "1", "commit": "c"},
    "operations": ["cesr.parse", "acdc.issue", "acdc.present", "acdc.verify"],
    "features": ["acdc.presentation"],
}
ECHO = {"match": {"op": "cesr.parse"}, "result": {"reject": {"class": "truncated"}}}
VERDICT = {"verdict": "invalid", "registry": None, "edges": []}
# The well-formed presentation context the probe sends first, which must get a result.
CONTROL = {"match": {"op": "acdc.verify", "presentation": CONTEXT}, "result": VERDICT}


# The repeatability probe's issuance, answered with one that verifies (tests/issued_world.py).
ISSUANCE = {"match": {"op": "acdc.issue", "credentials": ISSUE_PROBE["credentials"]},
            "result": issued_world.issuance()[1]}


def issuer(write_json, *entries, control=True, issuance=True):
    table = write_json("table.json", [ECHO, *([CONTROL] if control else []), *entries,
                                      *([ISSUANCE] if issuance else [])])
    return good("--table", table, "--hello", write_json("hello.json", ISSUER_HELLO))


def test_an_issuer_that_errors_on_malformed_requests_passes(vocabulary, write_json):
    result = probes(issuer(write_json), vocabulary)  # every unmatched request gets an error
    assert result["issue-malformed"].status == "pass"
    assert result["present-malformed"].status == "pass"
    assert result["presentation-malformed"].status == "pass"
    assert result["issue-repeatable"].status == "pass"
    assert result["present-independence"].status == "not-yet-available"
    assert check_exit_code(list(result.values())) == 0


@pytest.mark.parametrize(("op", "probe"), [("acdc.issue", "issue-malformed"),
                                           ("acdc.present", "present-malformed"),
                                           ("acdc.verify", "presentation-malformed")])
@pytest.mark.parametrize("answer", [
    {"result": {"refused": {"reason": "no template"}}},
    {"result": {"acdc": "7b7d", "registry": []}},
    {"result": {"presented": {"stream": "7b7d"}}},
])
def test_answering_a_malformed_issue_or_presentation_with_a_result_fails(
        vocabulary, write_json, op, probe, answer):
    # A request this protocol cannot read is an error, never a refusal: a refusal says the
    # implementation judged the inputs, which it cannot have done.
    result = probes(issuer(write_json, {"match": {"op": op}, **answer}), vocabulary)
    assert result[probe].status == "fail"
    assert "result" in result[probe].reason
    assert check_exit_code(list(result.values())) == 1


@pytest.mark.parametrize(("probe", "op"), [("issue-malformed", "acdc.issue"),
                                           ("present-malformed", "acdc.present")])
def test_an_issuer_that_crashes_on_a_malformed_request_fails(vocabulary, probe, op):
    result = probes(bad("crash-on-op", op), vocabulary, timeout=1.0)
    assert result[probe].status == "fail"
    assert "exited" in result[probe].reason
    other = "present-malformed" if probe == "issue-malformed" else "issue-malformed"
    assert result[other].status == "pass"  # the session restarts after the crash


@pytest.mark.parametrize(("mode", "needle"), [("hello-version", '"supported" list [1]'),
                                              ("hello-error", "the hello handler is broken")])
def test_the_hello_probe_follows_negotiation(vocabulary, mode, needle):
    result = probes(bad(mode), vocabulary)
    assert result["hello"].status == "fail"
    assert needle in result["hello"].reason


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
    code = check(good())
    assert code == 0
    out = capsys.readouterr().out
    assert "pass  hello" in out
    assert "not-yet-available  statelessness" in out


def test_cli_exit_1_when_a_probe_fails(capsys):
    code = check(bad("wrong-id"), "--timeout", "2")
    assert code == 1
    assert "fail  id-echo" in capsys.readouterr().out


def test_cli_runner_fault_when_the_adapter_cannot_start(tmp_path, capsys):
    code = check([str(tmp_path / "missing")])
    assert code == errors.EXIT_FAULT
    assert errors.E_ADAPTER_START in capsys.readouterr().err


def test_cli_refuses_off_posix(monkeypatch, capsys):
    monkeypatch.setattr(session_module, "is_posix", lambda: False)
    code = check(good())
    assert code == errors.EXIT_FAULT
    assert errors.E_PLATFORM in capsys.readouterr().err


def test_cli_passes_environment_through(tmp_path, monkeypatch):
    monkeypatch.setenv("KCS_CHECK_PASS", "1")
    dump = tmp_path / "env.json"
    code = check(good("--env-dump", dump), "--pass-env", "KCS_CHECK_PASS")
    assert code == 0
    assert json.loads(dump.read_text())["KCS_CHECK_PASS"] == "1"


def test_cli_help_documents_exit_codes(capsys):
    with pytest.raises(SystemExit):
        cli.main(["check-adapter", "--help"])
    out = capsys.readouterr().out
    assert "  0  " in out and "  1  " in out and "  4  " in out


def test_a_hello_that_changes_on_restart_fails_the_issuer_probe_that_restarted(vocabulary,
                                                                               monkeypatch):
    real = session_module.AdapterSession._start
    starts = []

    def start(self):
        starts.append(1)
        hello = real(self)
        return {**hello, "adapter": {"name": "other", "version": "9"}} if len(starts) > 1 else hello

    monkeypatch.setattr(session_module.AdapterSession, "_start", start)
    result = probes(bad("crash-on-op", "acdc.issue"), vocabulary, timeout=1.0)
    assert result["issue-malformed"].status == "fail"
    assert result["present-malformed"].status == "fail"
    assert errors.E_ADAPTER_HELLO_CHANGED in result["present-malformed"].reason


def test_the_presentation_probe_needs_the_feature_as_well_as_the_op(vocabulary, write_json):
    hello = write_json("hello.json", {**ISSUER_HELLO, "features": []})
    table = write_json("table.json", [ECHO])
    result = probes(good("--table", table, "--hello", hello), vocabulary)
    assert result["presentation-malformed"].status == "not-applicable"
    assert "acdc.presentation" in result["presentation-malformed"].reason


def test_an_adapter_that_errors_on_every_verification_fails_the_presentation_probe(
        vocabulary, write_json):
    # Its errors on the malformed contexts would show nothing, since it errors on a good one too.
    result = probes(issuer(write_json, control=False), vocabulary)
    assert result["presentation-malformed"].status == "fail"
    assert "well-formed" in result["presentation-malformed"].reason


@pytest.mark.parametrize("context", [{"messages": CONTEXT["messages"]},
                                     {**CONTEXT, "verifier": ""}])
def test_each_malformed_context_field_is_probed_on_its_own(vocabulary, write_json, context):
    answered = {"match": {"op": "acdc.verify", "presentation": context}, "result": VERDICT}
    result = probes(issuer(write_json, answered), vocabulary)
    assert result["presentation-malformed"].status == "fail"
    assert "variant" in result["presentation-malformed"].reason


def test_an_adapter_that_answers_only_once_fails_the_presentation_probe(vocabulary):
    # The control goes before every variant, so errors after the first answer show nothing.
    result = probes(bad("one-shot-verify"), vocabulary)
    assert result["presentation-malformed"].status == "fail"
    assert "well-formed" in result["presentation-malformed"].reason


def test_the_control_names_a_well_formed_verifier_aid():
    assert len(CONTEXT["verifier"]) == 44 and CONTEXT["verifier"][0] == "E"


@pytest.mark.parametrize(("answer", "words"), [
    (None, "did not answer issuance 1"),
    ({"result": {"refused": {"reason": "no"}}}, "refused issuance 1"),
    ({"result": {**issued_world.issuance()[1], "kels": {"issuer": "00", "holder": "00"}}},
     "does not verify"),
])
def test_an_issuer_whose_plain_issuance_does_not_verify_fails(vocabulary, write_json, answer,
                                                              words):
    entries = [] if answer is None else [{"match": ISSUANCE["match"], **answer}]
    result = probes(issuer(write_json, *entries, issuance=False), vocabulary)
    assert result["issue-repeatable"].status == "fail"
    assert words in result["issue-repeatable"].reason


def test_an_adapter_that_does_not_issue_skips_the_repeatability_probe(vocabulary):
    assert probes(good(), vocabulary)["issue-repeatable"].status == "not-applicable"


def test_an_issuer_that_crashes_on_the_plain_issuance_fails_it(vocabulary):
    result = probes(bad("crash-on-op", "acdc.issue"), vocabulary, timeout=1.0)
    assert result["issue-repeatable"].status == "fail"


def test_an_issuance_with_entries_not_asked_for_fails_the_probe(vocabulary, write_json):
    extra = copy.deepcopy(ISSUANCE["result"])
    extra["kels"]["stranger"] = extra["kels"]["issuer"]
    result = probes(issuer(write_json, {"match": ISSUANCE["match"], "result": extra},
                           issuance=False), vocabulary)
    assert result["issue-repeatable"].status == "fail"
    assert "does not answer the request" in result["issue-repeatable"].reason


def test_an_adapter_that_issues_only_into_1x_registries_is_probed_with_a_1x_issuance():
    from keri_conformance import check
    assert check._issue_probe({"features": ["acdc.ptel-1x"]}) is check.ISSUE_PROBE_1X
    assert check._issue_probe({"features": ["acdc.ptel-1x", "acdc.registry.bup"]}) is ISSUE_PROBE
    assert check._issue_probe({"features": []}) is ISSUE_PROBE
    asked = check.ISSUE_PROBE_1X["credentials"][0]
    # Every 1.x issuer adds a.dt, so the probe asks for one and grades an issuance that has it.
    assert asked["registry"] == "ptel-1x" and "dt" in asked["attributes"]
