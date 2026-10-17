"""acdc.verify on keripy 1.2.14 (acdc1x.py): a 1.x ACDC judged by keripy 1.x's own Verifier, on
the sedi-1x-interop cases (cases/sedi1x), whose expected verdicts are keripy 1.2.14's."""

import json
import pathlib

import pytest

from kcs_adapter_keripy import protocol

pytestmark = pytest.mark.onex

CASES = pathlib.Path(__file__).resolve().parents[3] / "cases" / "sedi1x"


def case(case_id):
    return json.loads((CASES / f"{case_id}.json").read_text())


def verify(request):
    response = json.loads(protocol.handle_line(json.dumps(
        {"id": 1, "op": "acdc.verify", **request}).encode()))
    return response.get("result", response)


@pytest.mark.parametrize("path", sorted(CASES.glob("*.json")), ids=lambda p: p.stem)
def test_every_companion_case_gets_keripys_own_verdict(path):
    c = json.loads(path.read_text())
    result = verify(c["input"])
    assert result["verdict"] == c["assertions"][0]["expected"]
    assert result["registry"] is None and result["edges"] == []


def test_a_bundle_without_the_registry_is_held_for_it():
    request = {**case("ACDC-0201")["input"], "registry": []}
    result = verify(request)
    assert (result["verdict"], result["reason"]) == (
        "incomplete", "keripy 1.2.14's Verifier holds it for a missing registry or issuance")


def test_a_bundle_without_the_schema_is_held_for_it():
    result = verify({**case("ACDC-0201")["input"], "schemas": []})
    assert (result["verdict"], result["reason"]) == (
        "incomplete", "keripy 1.2.14's Verifier holds it for a missing schema")


def test_a_bundle_without_the_far_credential_is_held_for_it():
    result = verify({**case("ACDC-0207")["input"], "acdcs": []})
    assert (result["verdict"], result["reason"]) == (
        "incomplete", "keripy 1.2.14's Verifier holds it for a missing chained credential")


def test_a_presented_stream_keripy_cannot_read_is_invalid():
    result = verify({**case("ACDC-0201")["input"], "presented": {"stream": "7b7d"}})
    assert result == {"verdict": "invalid", "reason": "keripy 1.2.14 cannot read the presented "
                      "stream as a 1.x ACDC", "registry": None, "edges": []}


def test_a_schema_keripy_cannot_index_is_one_the_bundle_does_not_have():
    request = case("ACDC-0201")["input"]
    junk = [b"not json".hex(), json.dumps({"$id": 7}).encode().hex(), b"[]".hex()]
    assert verify({**request, "schemas": junk + request["schemas"]})["verdict"] == "valid"


@pytest.mark.parametrize("change", [
    {"presented": "x"},
    {"schemas": "x"},
    {"schemas": [7]},
    {"kels": "x"},
])
def test_a_malformed_request_is_an_error(change):
    result = verify({**case("ACDC-0201")["input"], **change})
    assert result["error"]["kind"] == "harness"
    assert result["error"]["message"].startswith("e.input.format.request.f")


def test_nothing_keripy_prints_reaches_the_protocol_channel(capsys):
    verify(case("ACDC-0203")["input"])  # keripy prints its schema refusal
    assert capsys.readouterr().out == ""
