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
    # None of them is revoked; each names its 1.x registry in ri.
    acdc = json.loads(bytes.fromhex(c["input"]["presented"]["stream"]).split(b"-IAB")[0])
    assert result["registry"]["rd"] == acdc["ri"] and result["registry"]["td"] == acdc["d"]
    assert (result["registry"]["n"], result["registry"]["ts"]) == (0, "issued")
    assert result["edges"] == []


def test_a_bundle_without_the_registry_is_held_for_it():
    request = {**case("ACDC-0201")["input"], "registry": []}
    result = verify(request)
    assert (result["verdict"], result["reason"]) == (
        "incomplete", "keripy 1.2.14's Verifier holds it for a missing registry or issuance")
    assert result["registry"] is None


def test_a_revocation_is_reported_in_registry_since_keripy_still_saves_the_credential():
    fixture = json.loads((pathlib.Path(__file__).parent / "fixtures/onex-revoked.json")
                         .read_text())
    result = verify(fixture["request"])
    assert result["verdict"] == "valid"
    assert (result["registry"]["n"], result["registry"]["ts"]) == (1, "revoked")


def test_the_expected_schema_is_held_to():
    request = case("ACDC-0201")["input"]
    acdc = json.loads(bytes.fromhex(request["presented"]["stream"]).split(b"-IAB")[0])
    assert verify({**request, "expect_schema": acdc["s"]})["verdict"] == "valid"
    other = verify({**request, "expect_schema": "E" + "A" * 43})
    assert (other["verdict"], other["reason"]) == (
        "invalid", "the credential's schema is not the one the validator expects")
    # An expectation never turns a refusal or a hold into anything else.
    held = verify({**request, "registry": [], "expect_schema": "E" + "A" * 43})
    assert held["verdict"] == "incomplete"


def test_a_truncated_or_refused_stream_ends_its_delivery_without_waiting():
    request = case("ACDC-0201")["input"]
    kels = request["kels"]
    cut = {**request, "kels": [{**kels[0], "stream": kels[0]["stream"][:40]}, *kels[1:]]}
    assert verify(cut)["verdict"] == "incomplete"  # the issuer's inception never arrives
    junk = {**request, "kels": [{"stream": "00" * 8}, *kels]}
    assert verify(junk)["verdict"] == "valid"


def test_a_message_keripy_finishes_without_taking_a_byte_stops_delivery(monkeypatch):
    from keri.core import parsing

    from kcs_adapter_keripy import acdc1x

    def takes_nothing(self, **kwargs):
        return
        yield  # a generator that finishes at once

    calls = []
    monkeypatch.setattr(parsing.Parser, "msgParsator",
                        lambda self, **kw: calls.append(1) or takes_nothing(self, **kw))
    acdc1x._deliver(parsing.Parser(), type("H", (), {"kvy": None})(),
                    type("V", (), {"tvy": None})(), b"abc")
    assert calls == [1]


def test_a_schema_keripys_resolver_refuses_is_one_the_bundle_does_not_have():
    request = case("ACDC-0201")["input"]
    tampered = json.loads(bytes.fromhex(request["schemas"][0]))
    tampered["title"] = "changed after its $id was computed"
    schemas = [json.dumps(tampered).encode().hex(), *request["schemas"]]
    assert verify({**request, "schemas": schemas})["verdict"] == "valid"


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
    {"expect_schema": ""},
])
def test_a_malformed_request_is_an_error(change):
    result = verify({**case("ACDC-0201")["input"], **change})
    assert result["error"]["kind"] == "harness"
    assert result["error"]["message"].startswith("e.input.format.request.f")


def test_nothing_keripy_prints_reaches_the_protocol_channel(capsys):
    verify(case("ACDC-0203")["input"])  # keripy prints its schema refusal
    assert capsys.readouterr().out == ""


def test_a_presented_stream_must_be_one_acdc_taken_whole():
    request = case("ACDC-0201")["input"]
    stream = request["presented"]["stream"]
    for tail in (stream[:80], stream):  # a truncated second ACDC, or a whole second one
        result = verify({**request, "presented": {"stream": stream + tail}})
        assert (result["verdict"], result["reason"]) == (
            "invalid", "keripy 1.2.14 cannot read the presented stream as a 1.x ACDC")


def refusing(error):
    """A parser that takes one byte per message and refuses the second message with error."""
    def one_byte(self, ims, **kwargs):
        del ims[:1]
        if len(ims) == 2:
            raise error
        return
        yield
    return one_byte


@pytest.mark.parametrize("error,result", [
    (ValueError("a judgement"), (4, True, False)),  # skipped, as keripy's loop skips it
    ("sized", (4, True, True)),  # keripy flushed the group itself and resumes
    ("extraction", (1, False, True)),  # keripy discards the rest of the stream
    ("cold", (1, False, True)),
])
def test_delivery_follows_keripys_own_parse_loop(monkeypatch, error, result):
    from keri import kering
    from keri.core import parsing

    from kcs_adapter_keripy import acdc1x

    error = {"sized": kering.SizedGroupError("group"),
             "extraction": kering.ExtractionError("extraction"),
             "cold": kering.ColdStartError("cold")}.get(error, error)
    monkeypatch.setattr(parsing.Parser, "msgParsator", refusing(error))
    hby, vry = type("H", (), {"kvy": None})(), type("V", (), {"tvy": None})()
    assert acdc1x._deliver(parsing.Parser(), hby, vry, b"abcd") == result


@pytest.mark.parametrize("seal", [b"-IAA", b"-AAA"])
def test_a_copy_of_the_presented_credential_among_the_far_nodes_stands_in_for_nothing(seal):
    # A presentation with no commitment to its issuance, beside a sealed copy of the same
    # credential: keripy keys what it saved by SAID, so the copy must never be delivered.
    request = case("ACDC-0201")["input"]
    stream = request["presented"]["stream"]
    body = bytes.fromhex(stream).split(b"-IAB")[0]
    result = verify({**request, "acdcs": [{"stream": stream}],
                     "presented": {"stream": (body + seal).hex()}})
    assert result["verdict"] != "valid"


def test_a_refused_presentation_is_unreadable_even_when_the_credential_was_saved_elsewhere():
    request = case("ACDC-0201")["input"]
    stream = request["presented"]["stream"]
    body = bytes.fromhex(stream).split(b"-IAB")[0]
    refused = (body + b"-KAA").hex()  # an attachment counter keripy refuses after taking it
    result = verify({**request, "acdcs": [{"stream": stream}],
                     "presented": {"stream": refused}})
    assert (result["verdict"], result["reason"]) == (
        "invalid", "keripy 1.2.14 cannot read the presented stream as a 1.x ACDC")

