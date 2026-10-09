"""The adapter's protocol mechanics: hello negotiation, id echo, errors, and the stdio loop."""

import json

import pytest
from conftest import GENERATION, run_adapter

from kcs_adapter_keripy import kel, protocol


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
    assert result["operations"][:2] == ["cesr.parse", "cesr.encode"]
    assert result["operations"][2:] == (["keri.process", "acdc.verify", "exn.verify"]
                                        if GENERATION == "main" else [])
    assert result["composes"] == []


def test_hello_features_follow_the_keripy_generation():
    features = handle({"id": 0, "op": "hello", "protocol": 1})["result"]["features"]
    common = {"cesr.domain.binary", "cesr.serialization.json", "cesr.serialization.cbor",
              "cesr.serialization.mgpk", "keri.version-1.x"}
    if GENERATION == "main":
        # keripy main itemizes every stream it accepts, except native bodies (cesr.native,
        # which it does not declare), so it keeps cesr.item-extents.
        assert set(features) == common | {"cesr.genus-1.00", "cesr.genus-2.00",
                                          "cesr.item-extents", "keri.version-2.x",
                                          *kel.FEATURES}
    else:
        # keripy 1.2.14 cannot itemize -H and -J groups, so it does not promise items.
        assert set(features) == common | {"cesr.genus-1.00"}


def test_cesr_item_extents_is_declared_only_where_every_gap_is_an_undeclared_feature():
    from kcs_adapter_keripy import keripy_api, measure
    main, onex = keripy_api.Main, keripy_api.OneX
    # keripy main's only path to an unsupported cesr.parse is a native body (E_NATIVE), and it
    # does not declare cesr.native; it has no unmeasurable groups.
    assert main.UNMEASURABLE == ()
    assert "cesr.native" not in main.features and "cesr.item-extents" in main.features
    assert measure.E_NATIVE.startswith("e.feature.unsupported.")
    # keripy 1.2.14 has groups it cannot measure (-H, -J) and so must not declare it.
    assert onex.UNMEASURABLE and "cesr.item-extents" not in onex.features


def test_hello_negotiates_from_supported():
    response = handle({"id": 0, "op": "hello", "protocol": 3, "supported": [1, 2, 3]})
    assert response["result"]["protocol"] == 1


def test_hello_without_a_version_it_implements_is_an_error():
    response = handle({"id": 0, "op": "hello", "protocol": 3, "supported": [2, 3]})
    assert set(response) == {"id", "error"}
    assert response["error"]["kind"] == "unsupported"
    assert "e.feature.unsupported.protocol-version.f" in response["error"]["message"]


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
    assert "e.input.format.request.f" in response["error"]["message"]


@pytest.mark.parametrize("line", [b"[1, 2]", b'"text"', b"\xff\xfe"])
def test_a_line_that_is_not_an_object_gets_an_error_with_null_id(line):
    response = json.loads(protocol.handle_line(line))
    assert response["id"] is None
    assert response["error"]["kind"] == "harness"


def test_unknown_op_is_a_harness_error_echoing_the_id():
    response = handle({"id": 9, "op": "kcs.probe.no-such-op"})
    assert response == {"id": 9, "error": {"kind": "harness", "message": response["error"]["message"]}}
    assert "e.input.range.unknown-op.f" in response["error"]["message"]


@pytest.mark.parametrize("op", ["keri.emit"] + (["keri.process", "acdc.verify", "exn.verify"]
                                                if GENERATION == "1.x" else []))
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
    assert "e.input.format.request.f" in response["error"]["message"]


def test_an_adapter_bug_is_a_harness_error(monkeypatch):
    def boom(stream):
        raise RuntimeError("adapter bug")

    monkeypatch.setattr(protocol.cesr, "parse", boom)
    response = handle({"id": 5, "op": "cesr.parse", "stream": "2d4b"})
    assert response["error"]["kind"] == "harness"
    assert "e.self.unknown.f" in response["error"]["message"]
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
    assert [r["id"] for r in responses] == [0, None, 1, None, 2]  # a blank line is not JSON
    assert responses[2]["result"] == {"encoded": "4d414543"}
    assert "reject" in responses[4]["result"]



# -- the request-line bound

def test_the_request_line_bound_is_64_mib():
    assert protocol.MAX_REQUEST_LINE == 64 * 1024 * 1024


def _serve(monkeypatch, data, limit):
    import io
    monkeypatch.setattr(protocol, "MAX_REQUEST_LINE", limit)
    stdout = io.BytesIO()
    protocol.serve(io.BytesIO(data), stdout)
    return [json.loads(line) for line in stdout.getvalue().splitlines()]


def _padded(rid, length):
    """A valid cesr.parse request padded with spaces to exactly length bytes."""
    line = json.dumps({"id": rid, "op": "cesr.parse", "stream": ""}).encode()
    return line + b" " * (length - len(line))


def test_a_request_line_of_exactly_the_bound_is_answered(monkeypatch):
    responses = _serve(monkeypatch, _padded(1, 200) + b"\n", 200)
    assert responses == [{"id": 1, "result": {"items": []}}]


def test_a_final_line_without_a_newline_at_the_bound_is_answered(monkeypatch):
    assert _serve(monkeypatch, _padded(1, 200), 200) == [{"id": 1, "result": {"items": []}}]


@pytest.mark.parametrize("extra", [1, 5000])
def test_an_oversize_line_gets_a_null_id_error_and_the_adapter_keeps_running(monkeypatch, extra):
    data = _padded(1, 200 + extra) + b"\n" + _padded(2, 60) + b"\n"
    responses = _serve(monkeypatch, data, 200)
    assert responses[0]["id"] is None
    assert responses[0]["error"]["kind"] == "harness"
    assert "e.input.range.request-size.f" in responses[0]["error"]["message"]
    assert responses[1] == {"id": 2, "result": {"items": []}}


def test_an_oversize_final_line_without_a_newline_gets_a_null_id_error(monkeypatch):
    responses = _serve(monkeypatch, _padded(1, 300), 200)
    assert len(responses) == 1 and responses[0]["id"] is None


def test_handle_line_also_refuses_an_oversize_line(monkeypatch):
    monkeypatch.setattr(protocol, "MAX_REQUEST_LINE", 10)
    response = json.loads(protocol.handle_line(b'{"id": 1, "op": "hello"}'))
    assert response["id"] is None
    assert "e.input.range.request-size.f" in response["error"]["message"]


@pytest.mark.parametrize("op", [[], {}, 7, None])
def test_a_non_string_op_is_the_malformed_request_error(op):
    response = handle({"id": 3, "op": op})
    assert response["id"] == 3 and response["error"]["kind"] == "harness"
    assert response["error"]["message"].startswith("e.input.format.request.f")
