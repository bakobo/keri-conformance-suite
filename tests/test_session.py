"""The adapter session: starting an untrusted adapter, bounding what it can do, and turning every
way it can misbehave into a typed failure instead of a hang or a crash of the runner."""

import json
import pathlib
import time

import pytest
from conftest import ROOT, bad, good

from keri_conformance import errors
from keri_conformance.session import (
    AdapterSession,
    Failure,
    Limits,
    Reply,
    adapter_argv,
    apply_limits,
    check_result_shape,
    load_vocabulary,
    parse_response,
    scrubbed_env,
    validate_hello,
)

FAST = Limits(timeout=5.0)


def session(argv, vocabulary, **kw):
    kw.setdefault("limits", FAST)
    return AdapterSession(argv, vocabulary, **kw)


# --- pure helpers -------------------------------------------------------------------------------


def test_adapter_argv_splits_a_string_without_a_shell():
    assert adapter_argv("python 'my adapter.py' --x") == ["python", "my adapter.py", "--x"]


def test_adapter_argv_refuses_unbalanced_quotes():
    with pytest.raises(errors.RunnerError) as info:
        adapter_argv("python 'unterminated")
    assert info.value.code == errors.E_USAGE_INVALID


def test_adapter_argv_passes_a_list_through():
    assert adapter_argv(["a", "b c"]) == ["a", "b c"]


def test_adapter_argv_refuses_an_empty_command():
    with pytest.raises(errors.RunnerError) as info:
        adapter_argv("   ")
    assert info.value.code == errors.E_USAGE_INVALID
    assert info.value.exit_code == errors.EXIT_USAGE


def test_scrubbed_env_keeps_only_the_safe_names_and_passthroughs():
    environ = {"PATH": "/bin", "HOME": "/h", "LANG": "C", "LC_ALL": "C", "TMPDIR": "/t",
               "SYSTEMROOT": "C:\\", "AWS_SECRET_ACCESS_KEY": "s", "GITHUB_TOKEN": "t", "MINE": "1"}
    env = scrubbed_env(environ, ["MINE", "ABSENT"])
    assert env == {"PATH": "/bin", "HOME": "/h", "LANG": "C", "LC_ALL": "C", "TMPDIR": "/t",
                   "SYSTEMROOT": "C:\\", "MINE": "1"}


class FakeResource:
    RLIMIT_AS = "AS"
    RLIMIT_CPU = "CPU"
    RLIM_INFINITY = -1

    def __init__(self, hard):
        self.hard = hard
        self.calls = []

    def getrlimit(self, which):
        return (self.hard[which], self.hard[which])

    def setrlimit(self, which, limits):
        self.calls.append((which, limits))


def test_apply_limits_sets_address_space_and_cpu_under_unlimited_hard_limits():
    res = FakeResource({"AS": -1, "CPU": -1})
    apply_limits(res, 1000, 10)
    assert res.calls == [("AS", (1000, 1000)), ("CPU", (10, 11))]


def test_apply_limits_never_asks_for_more_than_the_current_hard_limit():
    res = FakeResource({"AS": 500, "CPU": 5})
    apply_limits(res, 1000, 10)
    assert res.calls == [("AS", (500, 500)), ("CPU", (5, 5))]


def test_load_vocabulary_reads_features_and_composability():
    vocab = load_vocabulary(ROOT)
    assert vocab["keri.escrow"] is True
    assert vocab["kel.basic"] is False


def test_load_vocabulary_names_a_missing_file(tmp_path):
    with pytest.raises(errors.RunnerError) as info:
        load_vocabulary(tmp_path)
    assert info.value.code == errors.E_VOCABULARY
    assert "features.json" in str(info.value)


def test_load_vocabulary_bounds_its_read(tmp_path):
    (tmp_path / "profiles").mkdir()
    (tmp_path / "profiles" / "features.json").write_text('{"features": {}}' + " " * 100)
    with pytest.raises(errors.RunnerError) as info:
        load_vocabulary(tmp_path, max_bytes=50)
    assert info.value.code == errors.E_VOCABULARY
    assert "50 bytes" in str(info.value)


@pytest.mark.parametrize("content", [b"[" * 100_000, b"\xff\xfe"], ids=["deep", "not-utf8"])
def test_load_vocabulary_maps_deep_or_undecodable_json_to_its_code(tmp_path, content):
    (tmp_path / "profiles").mkdir()
    (tmp_path / "profiles" / "features.json").write_bytes(content)
    with pytest.raises(errors.RunnerError) as info:
        load_vocabulary(tmp_path)
    assert info.value.code == errors.E_VOCABULARY


def test_load_vocabulary_maps_an_unreadable_path_to_its_code(tmp_path):
    (tmp_path / "profiles" / "features.json").mkdir(parents=True)
    with pytest.raises(errors.RunnerError) as info:
        load_vocabulary(tmp_path)
    assert info.value.code == errors.E_VOCABULARY
    assert "could not be read" in str(info.value)


@pytest.mark.parametrize("text", ["not json", "[]", '{"features": []}',
                                  '{"features": {"a.b": {"composable": "yes"}}}',
                                  '{"features": {"a.b": 3}}'])
def test_load_vocabulary_refuses_a_malformed_file(tmp_path, text):
    (tmp_path / "profiles").mkdir()
    (tmp_path / "profiles" / "features.json").write_text(text, encoding="utf-8")
    with pytest.raises(errors.RunnerError) as info:
        load_vocabulary(tmp_path)
    assert info.value.code == errors.E_VOCABULARY


HELLO = {
    "protocol": 1,
    "adapter": {"name": "a", "version": "1"},
    "implementation": {"name": "i", "version": "1", "commit": "c"},
    "operations": ["cesr.parse"],
    "features": ["kel.basic", "keri.escrow"],
    "composes": ["keri.escrow"],
}


def test_a_good_hello_has_no_problems(vocabulary):
    assert validate_hello(HELLO, vocabulary) == []
    assert validate_hello({k: v for k, v in HELLO.items() if k != "composes"}, vocabulary) == []


@pytest.mark.parametrize(
    ("change", "needle"),
    [
        ({"protocol": 99}, '"protocol" is 99, which is not in the "supported" list [1]'),
        ({"protocol": True}, '"protocol"'),
        ({"protocol": None}, '"protocol" is missing'),
        ({"adapter": None}, '"adapter" is missing'),
        ({"adapter": "x"}, '"adapter"'),
        ({"adapter": {"name": "a"}}, '"adapter.version"'),
        ({"adapter": {"name": 1, "version": "1"}}, '"adapter.name"'),
        ({"implementation": {"name": "i", "version": "1"}}, '"implementation.commit"'),
        ({"operations": None}, '"operations" is missing'),
        ({"operations": []}, '"operations"'),
        ({"operations": "cesr.parse"}, '"operations"'),
        ({"operations": ["cesr.parse", "kel.fly"]}, '"kel.fly"'),
        ({"operations": [3]}, '"operations"'),
        ({"features": None}, '"features" is missing'),
        ({"features": "kel.basic"}, '"features"'),
        ({"features": ["kel.basic", "kel.teleport"]}, '"kel.teleport"'),
        ({"features": [7]}, '"features"'),
        ({"composes": "keri.escrow"}, '"composes"'),
        ({"composes": ["kel.basic"]}, '"kel.basic" is not composable'),
        ({"composes": ["kel.recovery"]}, 'which is not also listed in "features"'),
        ({"composes": ["keri.magic"]}, '"keri.magic"'),
        ({"composes": [None]}, '"composes"'),
        ({"extra": 1}, '"extra"'),
    ],
)
def test_each_bad_hello_field_is_named(vocabulary, change, needle):
    hello = {**HELLO, **change}
    hello = {k: v for k, v in hello.items() if v is not None}
    problems = validate_hello(hello, vocabulary)
    assert problems, change
    assert any(needle in p for p in problems), problems


def test_a_hello_that_is_not_an_object_is_one_problem(vocabulary):
    assert len(validate_hello(["x"], vocabulary)) == 1


@pytest.mark.parametrize(
    ("op", "result"),
    [
        ("hello", {}),
        ("cesr.parse", {"items": []}),
        ("cesr.parse", {"items": [{"kind": "counter", "start": 0, "end": 4, "code": "-K",
                                   "size": 1, "group_end": 4}]}),
        ("cesr.parse", {"items": [{"kind": "primitive", "start": 0, "end": 4, "code": "E",
                                   "raw": "00"}]}),
        ("cesr.parse", {"reject": {"class": "truncated"}}),
        ("cesr.encode", {"encoded": "0aff"}),
        ("keri.process", {"dispositions": [{"initial": "pending", "final": "accepted"}],
                          "key_states": {"E": {"sn": 0, "said": "E", "keys": [], "kt": "1",
                                               "ndigs": [], "nt": "1", "wits": [], "bt": "0",
                                               "delegator": None}}}),
        ("keri.emit", {"stream": "7b7d"}),
        ("kcs.unknown", {"anything": 1}),
    ],
)
def test_plausible_results_have_no_shape_problem(op, result):
    assert check_result_shape(op, result) is None


@pytest.mark.parametrize(
    ("op", "result"),
    [
        ("hello", []),
        ("cesr.parse", {}),
        ("cesr.parse", {"items": [], "reject": {"class": "x"}}),
        ("cesr.parse", {"items": "x"}),
        ("cesr.parse", {"items": [3]}),
        ("cesr.parse", {"items": [{"kind": 1, "start": 0, "end": 1}]}),
        ("cesr.parse", {"items": [{"kind": "counter", "start": True, "end": 1}]}),
        ("cesr.parse", {"items": [{"kind": "counter", "start": 0}]}),
        ("cesr.parse", {"items": [{"kind": "counter", "start": 0, "end": 4}]}),
        ("cesr.parse", {"items": [{"kind": "counter", "start": 0, "end": 4, "group_end": 4}]}),
        ("cesr.parse", {"items": [{"kind": "primitive", "start": 0, "end": 4}]}),
        ("keri.process", {"dispositions": [], "key_states": {"E": {}}}),
        ("cesr.parse", {"items": [{"kind": "counter", "start": 0, "end": 4, "group_end": "8"}]}),
        ("cesr.parse", {"reject": "truncated"}),
        ("cesr.parse", {"reject": {"class": 3}}),
        ("cesr.encode", {"encoded": 3}),
        ("cesr.encode", {"encoded": "xyz"}),
        ("cesr.encode", {"encoded": "abc"}),
        ("cesr.encode", {"encoded": "0a", "more": 1}),
        ("keri.process", {"dispositions": []}),
        ("keri.process", {"dispositions": "x", "key_states": {}}),
        ("keri.process", {"dispositions": [3], "key_states": {}}),
        ("keri.process", {"dispositions": [{"initial": "accepted"}], "key_states": {}}),
        ("keri.process", {"dispositions": [{"initial": "superseded", "final": "accepted"}],
                          "key_states": {}}),
        ("keri.process", {"dispositions": [{"initial": "accepted", "final": "great"}],
                          "key_states": {}}),
        ("keri.process", {"dispositions": [], "key_states": []}),
        ("keri.process", {"dispositions": [], "key_states": {"E": 3}}),
        ("keri.emit", {"stream": "zz"}),
        ("keri.emit", {}),
    ],
)
def test_implausible_results_are_described(op, result):
    assert isinstance(check_result_shape(op, result), str)


@pytest.mark.parametrize(
    ("line", "kind"),
    [
        (b"this is not json", "malformed"),
        (b"\xff\xfe", "malformed"),
        (b"[1]", "malformed"),
        (b"[" * 100000 + b"]" * 100000, "malformed"),
        (b'{"id": 2, "result": {"encoded": "0a"}}', "malformed"),
        (b'{"id": true, "result": {"encoded": "0a"}}', "malformed"),
        (b'{"result": {"encoded": "0a"}}', "malformed"),
        (b'{"id": 1}', "malformed"),
        (b'{"id": 1, "result": {}, "error": {}}', "malformed"),
        (b'{"id": 1, "result": {"encoded": "0a"}, "x": 1}', "malformed"),
        (b'{"id": 1, "result": {"encoded": 5}}', "malformed"),
        (b'{"id": 1, "error": "x"}', "malformed"),
        (b'{"id": 1, "error": {"kind": "oops", "message": "m"}}', "malformed"),
        (b'{"id": 1, "error": {"kind": "harness", "message": 3}}', "malformed"),
        (b'{"id": 1, "error": {"kind": "harness", "message": "m"}}', "error-harness"),
        (b'{"id": 1, "error": {"kind": "unsupported", "message": "m"}}', "error-unsupported"),
    ],
)
def test_parse_response_classifies_bad_lines(line, kind):
    outcome = parse_response(line, 1, "cesr.encode")
    assert isinstance(outcome, Failure)
    assert outcome.kind == kind
    assert outcome.detail


def test_parse_response_accepts_a_good_result():
    assert parse_response(b'{"id": 1, "result": {"encoded": "0a"}}', 1, "cesr.encode") == Reply(
        {"encoded": "0a"})


def test_wrong_id_detail_says_so():
    outcome = parse_response(b'{"id": 2, "result": {"encoded": "0a"}}', 1, "cesr.encode")
    assert "id" in outcome.detail and "2" in outcome.detail


def test_errors_render_code_then_sentence():
    err = errors.RunnerError("e.x.y.f", "It broke.")
    assert str(err) == "e.x.y.f: It broke."
    assert err.exit_code == errors.EXIT_FAULT


# --- real subprocesses --------------------------------------------------------------------------


def test_good_adapter_says_hello_and_answers(vocabulary):
    with session(good("--late-stderr"), vocabulary) as s:
        hello = s.open()
        assert hello["adapter"]["name"] == "fake-adapter"
        assert s.hello == hello
        reply = s.request("cesr.parse", {"stream": "2d4b"})
        assert reply == Reply({"reject": {"class": "truncated"}})
        time.sleep(0.5)  # "answered" comes 0.1 s after the response, so only a drain sees it
        tail = s.take_stderr()
        assert "handling cesr.parse" in tail
        assert "answered cesr.parse" in tail
        again = s.take_stderr()
        assert again == ""


def test_close_and_kill_are_idempotent_and_safe_before_open(vocabulary):
    s = session(good(), vocabulary)
    s.close()
    s.kill()
    s.open()
    s.close()
    s.close()
    s.kill()


def test_exchange_can_read_without_writing(vocabulary):
    with session(good(), vocabulary) as s:
        s.open()
        two = b'{"id": 7, "op": "cesr.parse", "stream": ""}\n{"id": 8, "op": "cesr.parse", "stream": ""}\n'
        first = s.exchange(two)
        second = s.exchange(b"")
        assert json.loads(first)["id"] == 7
        assert json.loads(second)["id"] == 8


def test_refuses_to_run_as_root(vocabulary):
    s = session(good(), vocabulary, geteuid=lambda: 0)
    with pytest.raises(errors.RunnerError) as info:
        s.open()
    assert info.value.code == errors.E_ROOT
    assert info.value.exit_code == errors.EXIT_FAULT


def test_refuses_to_run_off_posix(vocabulary):
    s = session(good(), vocabulary, posix=False)
    with pytest.raises(errors.RunnerError) as info:
        s.open()
    assert info.value.code == errors.E_PLATFORM
    assert info.value.exit_code == errors.EXIT_FAULT
    assert "POSIX" in str(info.value)
    assert s.pid is None


def test_an_executable_that_cannot_start_is_a_runner_fault_after_one_retry(vocabulary, tmp_path):
    missing = str(tmp_path / "no-such-adapter")
    s = session([missing], vocabulary)
    with pytest.raises(errors.RunnerError) as info:
        s.open()
    assert info.value.code == errors.E_ADAPTER_START
    assert info.value.exit_code == errors.EXIT_FAULT
    assert "2 attempts" in str(info.value)


def test_a_failed_first_start_is_retried(vocabulary, monkeypatch):
    import subprocess

    real = subprocess.Popen
    calls = []

    def flaky(*args, **kwargs):
        calls.append(1)
        if len(calls) == 1:
            raise OSError("transient")
        return real(*args, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", flaky)
    with session(good(), vocabulary) as s:
        s.open()
    assert len(calls) == 2


def test_environment_is_scrubbed_with_explicit_passthrough(vocabulary, tmp_path, monkeypatch):
    monkeypatch.setenv("KCS_TEST_SECRET", "hunter2")
    monkeypatch.setenv("KCS_TEST_PASS", "ok")
    dump = tmp_path / "env.json"
    with session(good("--env-dump", dump), vocabulary, pass_env=["KCS_TEST_PASS"]) as s:
        s.open()
    env = json.loads(dump.read_text())
    assert "KCS_TEST_SECRET" not in env
    assert env["KCS_TEST_PASS"] == "ok"


@pytest.mark.parametrize(("mode", "needle"), [("hello-crash", "exited"), ("hello-error", "error")])
def test_hello_failures_are_refusals(vocabulary, mode, needle):
    s = session(bad(mode), vocabulary)
    with pytest.raises(errors.HelloRefused) as info:
        s.open()
    assert info.value.code == errors.E_ADAPTER_HELLO
    assert info.value.exit_code == errors.EXIT_REFUSED
    assert needle in str(info.value)
    s.close()


def test_hello_offers_every_supported_version_and_asks_for_the_highest(vocabulary, tmp_path):
    from keri_conformance.protocol import SUPPORTED_PROTOCOLS

    dump = tmp_path / "hello.json"
    with session(good("--hello-dump", dump), vocabulary) as s:
        hello = s.open()
        assert hello["protocol"] == 1
    request = json.loads(dump.read_text())
    assert request == {"id": 0, "op": "hello", "protocol": max(SUPPORTED_PROTOCOLS),
                       "supported": sorted(SUPPORTED_PROTOCOLS)}


def test_a_version_outside_supported_is_refused(vocabulary):
    s = session(bad("hello-version"), vocabulary)
    with pytest.raises(errors.HelloRefused) as info:
        s.open()
    assert info.value.code == errors.E_ADAPTER_HELLO
    assert info.value.exit_code == errors.EXIT_REFUSED
    assert '"protocol" is 2, which is not in the "supported" list [1]' in str(info.value)
    s.close()


def test_a_hello_error_is_a_refusal_showing_its_message(vocabulary):
    s = session(bad("hello-error"), vocabulary)
    with pytest.raises(errors.HelloRefused) as info:
        s.open()
    assert "the hello handler is broken" in str(info.value)
    assert "the hello handler is broken" in info.value.problems[0]
    s.close()


def test_hello_timeout_is_a_refusal(vocabulary):
    s = session(bad("hello-hang"), vocabulary, limits=Limits(timeout=0.5))
    with pytest.raises(errors.HelloRefused) as info:
        s.open()
    assert "timeout" in str(info.value)
    s.close()


def test_a_bad_hello_field_is_refused_with_the_field_named(vocabulary, write_json):
    hello = {**HELLO, "features": ["kel.teleport"]}
    path = write_json("hello.json", hello)
    s = session(good("--hello", path), vocabulary)
    with pytest.raises(errors.HelloRefused) as info:
        s.open()
    assert "kel.teleport" in str(info.value)
    assert info.value.problems
    s.close()


@pytest.mark.parametrize(
    ("mode", "arg", "kind"),
    [
        ("crash", None, "exited"),
        ("wrong-id", None, "malformed"),
        ("bool-id", None, "malformed"),
        ("junk", None, "malformed"),
        ("not-utf8", None, "malformed"),
        ("not-object", None, "malformed"),
        ("both", None, "malformed"),
        ("neither", None, "malformed"),
        ("extra-key", None, "malformed"),
        ("error-harness", None, "error-harness"),
        ("error-unsupported", None, "error-unsupported"),
        ("error-bad-kind", None, "malformed"),
        ("error-not-object", None, "malformed"),
        ("oversize", 2000, "oversize"),
        ("flood", None, "oversize"),
    ],
)
def test_each_misbehaviour_is_a_typed_failure_and_the_adapter_is_restarted(
        vocabulary, mode, arg, kind):
    limits = Limits(timeout=5.0, max_response=1000)
    with session(bad(mode, arg), vocabulary, limits=limits) as s:
        s.open()
        first_pid = s.pid
        outcome = s.request("cesr.encode", {"code": "E", "raw": "00", "domain": "text"})
        assert isinstance(outcome, Failure), outcome
        assert outcome.kind == kind
        assert s.pid is None  # killed
        # The next request restarts the adapter with a fresh hello.
        s.request("cesr.encode", {"code": "E", "raw": "00", "domain": "text"})
        assert s.pid is None or s.pid != first_pid


def test_crash_stderr_is_captured(vocabulary):
    with session(bad("crash"), vocabulary) as s:
        s.open()
        s.request("cesr.parse", {"stream": ""})
        tail = s.take_stderr()
        assert "boom: the parser panicked" in tail


@pytest.mark.parametrize("mode", ["hang", "no-newline"])
def test_a_hang_is_a_timeout(vocabulary, mode):
    with session(bad(mode), vocabulary, limits=Limits(timeout=0.5)) as s:
        s.open()
        start = time.monotonic()
        outcome = s.request("cesr.parse", {"stream": ""})
        assert outcome.kind == "timeout"
        assert time.monotonic() - start < 3


def test_an_adapter_that_stops_reading_cannot_block_the_runner(vocabulary):
    with session(bad("no-read"), vocabulary, limits=Limits(timeout=0.5)) as s:
        s.open()
        outcome = s.request("cesr.parse", {"stream": "00" * 2_000_000})
        assert outcome.kind == "timeout"


def test_an_adapter_that_closes_its_input_is_an_exit(vocabulary):
    with session(bad("close-stdin"), vocabulary) as s:
        s.open()
        outcome = s.request("cesr.parse", {"stream": "00" * 1000})
        assert outcome.kind == "exited"
        assert "standard input" in outcome.detail


def test_an_adapter_that_closes_stderr_still_works(vocabulary):
    with session(bad("close-stderr"), vocabulary) as s:
        s.open()
        outcome = s.request("cesr.encode", {"code": "E", "raw": "", "domain": "text"})
        tail = s.take_stderr()
        assert outcome == Reply({"encoded": "10"})
        assert tail == ""


def test_an_answer_before_the_request_is_written_is_malformed(vocabulary):
    with session(bad("early-answer"), vocabulary) as s:
        s.open()
        outcome = s.request("cesr.parse", {"stream": "00" * 2_000_000})
        assert outcome.kind == "malformed"
        assert "before" in outcome.detail


def test_stderr_is_bounded_to_its_tail(vocabulary):
    with session(bad("stderr-flood"), vocabulary,
                 limits=Limits(timeout=5.0, stderr_tail=1000)) as s:
        s.open()
        outcome = s.request("cesr.encode", {"code": "E", "raw": "", "domain": "text"})
        assert isinstance(outcome, Reply)
        tail = s.take_stderr()
        assert len(tail) <= 1000
        assert tail.endswith("END")


def test_memory_limit_applies(vocabulary):
    limits = Limits(timeout=10.0, address_space=512 * 1024 * 1024)
    with session(bad("memory", 2 * 1024**3), vocabulary, limits=limits) as s:
        s.open()
        outcome = s.request("cesr.parse", {"stream": ""})
        assert outcome.kind == "exited"
        tail = s.take_stderr()
        assert "MemoryError" in tail


def test_cpu_limit_applies(vocabulary):
    limits = Limits(timeout=20.0, cpu_seconds=1)
    with session(bad("cpu"), vocabulary, limits=limits) as s:
        s.open()
        start = time.monotonic()
        outcome = s.request("cesr.parse", {"stream": ""})
        assert outcome.kind == "exited"
        assert time.monotonic() - start < 15


def _alive(pid):
    status = pathlib.Path(f"/proc/{pid}/status")
    try:
        text = status.read_text()
    except FileNotFoundError:
        return False
    return "\nState:\tZ" not in text


def test_the_whole_process_group_is_killed(vocabulary, tmp_path):
    pidfile = tmp_path / "grandchild.pid"
    with session(bad("grandchild", pidfile), vocabulary, limits=Limits(timeout=1.0)) as s:
        s.open()
        outcome = s.request("cesr.parse", {"stream": ""})
        assert outcome.kind == "timeout"
    grandchild = int(pidfile.read_text())
    deadline = time.monotonic() + 5
    while _alive(grandchild) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not _alive(grandchild)


def test_restart_with_a_different_hello_is_refused(vocabulary, tmp_path, write_json):
    hello_path = write_json("hello.json", HELLO)
    table = write_json("table.json", [])
    with session(good("--hello", hello_path, "--table", table), vocabulary) as s:
        s.open()
        write_json("hello.json", {**HELLO, "adapter": {"name": "other", "version": "2"}})
        s.kill()
        with pytest.raises(errors.HelloRefused) as info:
            s.request("cesr.parse", {"stream": ""})
        assert info.value.code == errors.E_ADAPTER_HELLO_CHANGED


def test_request_ids_increase(vocabulary):
    with session(good(), vocabulary) as s:
        s.open()
        first, second = s.next_id(), s.next_id()
        assert (first, second) == (1, 2)


def test_adapter_exits_cleanly_on_eof(vocabulary):
    s = session(good(), vocabulary)
    s.open()
    proc = s._proc
    s.close()
    assert proc.returncode == 0


def test_close_kills_an_adapter_that_ignores_eof(vocabulary):
    s = session(bad("no-read"), vocabulary, limits=Limits(timeout=5.0, close_grace=0.2))
    s.open()
    proc = s._proc
    start = time.monotonic()
    s.close()
    assert proc.returncode is not None
    assert time.monotonic() - start < 3
