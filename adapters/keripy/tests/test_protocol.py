"""The adapter's protocol mechanics: hello negotiation, id echo, errors, and the stdio loop."""

import json

import pytest
from conftest import GENERATION, run_adapter

from kcs_adapter_keripy import protocol


def handle(message):
    return json.loads(protocol.handle_line(json.dumps(message).encode()))


def test_hello_answers_protocol_1_with_identity(keri_dist):
    response = handle({"id": 0, "op": "hello", "protocol": 1})
    assert response["id"] == 0
    result = response["result"]
    assert result["protocol"] == 1
    assert result["adapter"] == {"name": "kcs-adapter-keripy", "version": "0.1.0"}
    implementation = result["implementation"]
    assert implementation["name"] == "keripy"
    assert implementation["version"] == keri_dist.version
    commit = json.loads(keri_dist.read_text("direct_url.json"))["vcs_info"]["commit_id"]
    assert implementation["commit"] == commit
    assert len(commit) == 40
    assert result["operations"] == ["cesr.parse", "cesr.encode"]
    assert result["composes"] == []


def test_hello_features_follow_the_keripy_generation():
    features = handle({"id": 0, "op": "hello", "protocol": 1})["result"]["features"]
    common = {"cesr.domain.binary", "cesr.serialization.json", "cesr.serialization.cbor",
              "cesr.serialization.mgpk", "keri.version-1.x"}
    if GENERATION == "main":
        assert set(features) == common | {"cesr.genus-1.00", "cesr.genus-2.00",
                                          "keri.version-2.x"}
    else:
        assert set(features) == common | {"cesr.genus-1.00"}


def test_hello_negotiates_from_supported():
    response = handle({"id": 0, "op": "hello", "protocol": 3, "supported": [1, 2, 3]})
    assert response["result"]["protocol"] == 1


def test_hello_without_a_version_it_implements_is_an_error():
    response = handle({"id": 0, "op": "hello", "protocol": 3, "supported": [2, 3]})
    assert set(response) == {"id", "error"}
    assert response["error"]["kind"] == "unsupported"
    assert "e.protocol.version.unsupported.p" in response["error"]["message"]


def test_hello_with_protocol_above_ours_and_no_supported_list_is_an_error_not_a_crash():
    response = handle({"id": 0, "op": "hello", "protocol": 2})
    assert response["error"]["kind"] == "unsupported"


def test_unknown_request_fields_are_ignored():
    response = handle({"id": 4, "op": "cesr.encode", "code": "M", "raw": "0102",
                       "domain": "text", "future": {"x": 1}})
    assert response == {"id": 4, "result": {"encoded": "4d414543"}}


def test_a_line_that_is_not_json_gets_an_error_with_null_id():
    response = json.loads(protocol.handle_line(b"this is not json"))
    assert response["id"] is None
    assert response["error"]["kind"] == "harness"
    assert "e.request.malformed.p" in response["error"]["message"]


@pytest.mark.parametrize("line", [b"[1, 2]", b'"text"', b"\xff\xfe"])
def test_a_line_that_is_not_an_object_gets_an_error_with_null_id(line):
    response = json.loads(protocol.handle_line(line))
    assert response["id"] is None
    assert response["error"]["kind"] == "harness"


def test_unknown_op_is_a_harness_error_echoing_the_id():
    response = handle({"id": 9, "op": "kcs.probe.no-such-op"})
    assert response == {"id": 9, "error": {"kind": "harness", "message": response["error"]["message"]}}
    assert "e.request.op.unknown.p" in response["error"]["message"]


@pytest.mark.parametrize("op", ["keri.process", "keri.emit"])
def test_undeclared_protocol_ops_are_unsupported(op):
    response = handle({"id": 2, "op": op})
    assert response["error"]["kind"] == "unsupported"


@pytest.mark.parametrize("message", [
    {"id": 1, "op": "cesr.parse"},
    {"id": 1, "op": "cesr.parse", "stream": "abc"},
    {"id": 1, "op": "cesr.parse", "stream": "ZZ"},
    {"id": 1, "op": "cesr.parse", "stream": 7},
    {"id": 1, "op": "cesr.encode", "code": "M", "raw": "0102"},
    {"id": 1, "op": "cesr.encode", "code": "M", "raw": "0102", "domain": "octal"},
    {"id": 1, "op": "cesr.encode", "code": "", "raw": "0102", "domain": "text"},
    {"id": 1, "op": "cesr.encode", "code": "M", "raw": "0g", "domain": "text"},
    {"id": 1},
])
def test_malformed_requests_are_harness_errors_echoing_the_id(message):
    response = handle(message)
    assert response["id"] == 1
    assert response["error"]["kind"] == "harness"
    assert "e.request.malformed.p" in response["error"]["message"]


def test_an_adapter_bug_is_a_harness_error(monkeypatch):
    def boom(stream):
        raise RuntimeError("adapter bug")

    monkeypatch.setattr(protocol.cesr, "parse", boom)
    response = handle({"id": 5, "op": "cesr.parse", "stream": "2d4b"})
    assert response["error"]["kind"] == "harness"
    assert "e.adapter.internal.p" in response["error"]["message"]
    assert "RuntimeError" in response["error"]["message"]


def test_the_stdio_loop_answers_in_order_and_exits_zero_at_eof(entry_point):
    lines = [b'{"id":0,"op":"hello","protocol":1}\n',
             b"not json\n",
             b'{"id":1,"op":"cesr.encode","code":"M","raw":"0102","domain":"text"}\n',
             b"\n",
             b'{"id":2,"op":"cesr.parse","stream":"2d4b"}\n']
    out, rc, _ = run_adapter(entry_point, lines)
    assert rc == 0
    responses = [json.loads(line) for line in out]
    assert [r["id"] for r in responses] == [0, None, 1, 2]
    assert responses[2]["result"] == {"encoded": "4d414543"}
    assert "reject" in responses[3]["result"]

