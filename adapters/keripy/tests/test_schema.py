"""Every response the adapter writes validates against the suite's own message schema,
schema/adapter-protocol.schema.json, which the runner mirrors and enforces."""

import json
from pathlib import Path

import pytest
import test_parse as tp
from conftest import GENERATION
from jsonschema import Draft202012Validator

from kcs_adapter_keripy import protocol

SCHEMA_PATH = Path(__file__).resolve().parents[3] / "schema" / "adapter-protocol.schema.json"
ROOT = json.loads(SCHEMA_PATH.read_text())
RESPONSE = Draft202012Validator({**ROOT, "$ref": "#/$defs/response"})


def respond(message):
    return json.loads(protocol.handle_line(json.dumps(message).encode()))


def valid(response):
    errors = sorted(RESPONSE.iter_errors(response), key=str)
    assert errors == [], [e.message for e in errors]
    return response


def streams():
    """Streams that exercise every item kind keripy reports on this generation."""
    if GENERATION == "main":
        serder = tp.event(tp.V2, 2)
        inner = tp.genus(b"BAA") + tp.ctr("-A", 1, tp.V1) + tp.sigs(serder, 1)
        cig = tp.WITNESS.sign(serder.raw)
        couples = tp.ctr("-M", 33, tp.V2) + bytes(tp.WITNESS.verfer.qb64b) + bytes(cig.qb64b)
        big = bytes(tp.Indexer(raw=bytes(64), code="2A", index=65, ondex=70).qb64b)
        k = tp.ctr("-K", 23, tp.V2) + big
        return [
            tp.genus() + serder.raw + tp.main_frame(serder, 2),
            tp.genus() + serder.raw + tp.ctr("-C", len(inner) // 4, tp.V2) + inner,
            tp.genus() + serder.raw + tp.ctr("-C", (len(k) + len(couples)) // 4, tp.V2) + k
            + couples,
        ]
    serder = tp.event(tp.V1)
    cig = tp.WITNESS.sign(serder.raw)
    return [serder.raw + tp.ctr("-A", 1, tp.V1) + tp.sigs(serder, 1) + tp.ctr("-C", 1, tp.V1)
            + bytes(tp.WITNESS.verfer.qb64b) + bytes(cig.qb64b)]


def test_the_schema_is_the_suites():
    assert ROOT["title"].startswith("Adapter protocol")


@pytest.mark.xfail(GENERATION == "main", strict=True, reason=(
    "schema/adapter-protocol.schema.json lists only cesr.parse, cesr.encode, keri.process and "
    "keri.emit in hello's operations, while the protocol and the runner (session.OPERATIONS) "
    "also accept acdc.verify and exn.verify, which keripy main lists. Remove this mark when the "
    "schema's enum gains them."))
def test_hello_result_validates():
    response = valid(respond({"id": 0, "op": "hello", "protocol": 1, "supported": [1]}))
    assert response["result"]["protocol"] == 1


@pytest.mark.parametrize("n", range(3))
def test_decoded_results_validate_and_cover_every_kind(n):
    cases = streams()
    if n >= len(cases):
        pytest.skip("this generation has fewer sample streams")
    response = valid(respond({"id": 1, "op": "cesr.parse", "stream": cases[n].hex()}))
    assert "items" in response["result"]


def test_every_item_kind_keripy_reports_is_covered():
    kinds = set()
    for stream in streams():
        kinds.update(i["kind"] for i in respond(
            {"id": 1, "op": "cesr.parse", "stream": stream.hex()})["result"]["items"])
    expected = {"message", "counter", "indexed", "primitive"}
    if GENERATION == "main":
        expected.add("genus")
    assert kinds == expected


def test_rejection_validates():
    response = valid(respond({"id": 2, "op": "cesr.parse", "stream": "2d4b"}))
    assert set(response["result"]) == {"reject"}


def test_encoding_validates():
    valid(respond({"id": 3, "op": "cesr.encode", "code": "M", "raw": "0102", "domain": "text"}))


@pytest.mark.parametrize("message", [
    {"id": 4, "op": "kcs.no-such-op"},
    {"id": 4, "op": "keri.process"},
    {"id": 4, "op": "cesr.encode", "code": "#", "raw": "00", "domain": "text"},
    {"id": 4, "op": "hello", "protocol": 9, "supported": [9]},
])
def test_error_responses_validate(message):
    response = valid(respond(message))
    assert set(response) == {"id", "error"}


@pytest.mark.parametrize("line", [
    b"{not json",
    b'{"op": "hello", "protocol": 1}',
    b'{"id": "seven", "op": "cesr.parse", "stream": ""}',
    b'{"id": -1, "op": "cesr.parse", "stream": ""}',
    b'{"id": true, "op": "cesr.parse", "stream": ""}',
    b'{"id": 1.5, "op": "cesr.parse", "stream": ""}',
])
def test_a_request_without_a_usable_id_gets_an_error_with_a_null_id(line):
    response = valid(json.loads(protocol.handle_line(line)))
    assert response["id"] is None
    assert response["error"]["kind"] == "harness"


@pytest.mark.main
def test_keri_process_results_validate():
    import test_kel as tk

    i = tk.icp(keys=[tk.A0, tk.B0], isith=["1/2", "1/2"], nxt=[tk.A1, tk.B1],
               nsith=["1/2", "1/2"], wits=[tk.W1], toad=1)
    x1 = tk.ixn(i, 1)
    message = {"id": 5, "op": "keri.process", "perspective": {"role": "validator"},
               "messages": [{"stream": s.hex(), "source": "t"} for s in (
                   tk.signed(i, [tk.A0, tk.B0], wits=[(0, tk.W1)]), tk.signed(x1, [tk.A0]),
                   tk.receipt(i, [(0, tk.W1)]), b"junk")]}
    response = valid(respond(message))
    state = next(iter(response["result"]["key_states"].values()))
    assert state["kt"] == ["1/2", "1/2"] and state["wits"] == [tk.W1.verfer.qb64]


@pytest.mark.main
def test_acdc_verify_results_validate():
    import test_acdc as ta

    world = ta.World()
    for registry in ([world.rip_stream(), world.bup_stream()],
                     [world.rip_stream(), world.bup_stream(disclose=False)], []):
        valid(world.verify(registry=registry))
    valid(world.verify(presented=b"junk"))


@pytest.mark.main
def test_exn_verify_results_validate():
    import bundles as b

    issuer = b.Issuer(1, 2)
    message = b.exn_signed(b.exn(issuer.pre), issuer.key, issuer.icp)
    response = valid(b.exchange(issuer.kel(), [message, b"junk"]))
    assert len(response["result"]["verdicts"]) == 2
