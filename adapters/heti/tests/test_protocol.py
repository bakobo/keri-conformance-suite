"""The stdio protocol: one response line per request line, whatever the line holds."""

import io
import json

import pytest

from kcs_adapter_heti import main, protocol


def answer(request) -> dict:
    return json.loads(protocol.handle_line(json.dumps(request).encode()))


def test_hello_names_heti_and_declares_verify_and_issue():
    result = answer({"id": 0, "op": "hello", "protocol": 1, "supported": [1]})["result"]
    assert result["protocol"] == 1 and result["operations"] == ["acdc.verify", "acdc.issue"]
    assert result["implementation"]["name"] == "heti"
    assert len(result["implementation"]["commit"]) == 40
    assert "acdc.registry.upd" not in result["features"] and result["composes"] == []
    assert answer({"id": 0, "op": "hello", "protocol": 1})["result"]["protocol"] == 1


def test_hello_refuses_a_runner_offering_no_version_it_speaks():
    error = answer({"id": 0, "op": "hello", "protocol": 2, "supported": [2]})["error"]
    assert error["kind"] == "unsupported" and protocol.E_VERSION in error["message"]


def test_an_installation_without_a_direct_url_reports_an_unknown_commit(monkeypatch):
    class Dist:
        version = "9"

        def read_text(self, name):
            return None

    monkeypatch.setattr(protocol.importlib.metadata, "distribution", lambda name: Dist())
    assert protocol.implementation() == {"name": "heti", "version": "9", "commit": "unknown"}


@pytest.mark.parametrize("request_,kind,code", [
    ({"id": 1, "op": "keri.process"}, "unsupported", protocol.E_UNDECLARED_OP),
    ({"id": 1, "op": "frobnicate"}, "harness", protocol.E_UNKNOWN_OP),
    ({"id": 1, "op": 7}, "harness", protocol.E_MALFORMED),
    ({"id": 1, "op": "acdc.verify", "kels": 7}, "harness", protocol.E_MALFORMED),
])
def test_requests_the_adapter_cannot_answer(request_, kind, code):
    error = answer(request_)["error"]
    assert error["kind"] == kind and code in error["message"]


def test_an_adapter_bug_is_still_one_response(monkeypatch):
    monkeypatch.setitem(protocol.OPS, "acdc.verify", lambda request: 1 / 0)
    error = answer({"id": 3, "op": "acdc.verify"})["error"]
    assert error["kind"] == "harness" and "ZeroDivisionError" in error["message"]


@pytest.mark.parametrize("line", [b"not json\n", b"[1]\n", b'{"op": "hello"}\n',
                                  b'{"id": -1, "op": "hello"}\n', b"\xff\n"])
def test_lines_that_are_not_usable_requests_get_a_null_id(line):
    response = json.loads(protocol.handle_line(line))
    assert response["id"] is None and response["error"]["kind"] == "harness"


def test_an_oversize_line_is_answered_and_skipped(monkeypatch):
    monkeypatch.setattr(protocol, "MAX_REQUEST_LINE", 24)
    monkeypatch.setattr(protocol, "_DISCARD_CHUNK", 4)
    assert protocol.E_OVERSIZE in protocol.handle_line(b"x" * 25 + b"\n").decode()
    stdin = io.BytesIO(b"y" * 40 + b"\n" + b'{"id":1,"op":"no"}\n')
    stdout = io.BytesIO()
    protocol.serve(stdin, stdout)
    first, second = stdout.getvalue().splitlines()
    assert protocol.E_OVERSIZE in first.decode() and json.loads(second)["id"] == 1


def test_main_serves_stdin_and_keeps_stdout_for_responses(monkeypatch):
    stdin = io.TextIOWrapper(io.BytesIO(b'{"id":1,"op":"no"}\n'))
    stdout = io.TextIOWrapper(io.BytesIO())
    monkeypatch.setattr("sys.stdin", stdin)
    monkeypatch.setattr("sys.stdout", stdout)
    assert main.main() == 0
    assert json.loads(stdout.buffer.getvalue())["id"] == 1
