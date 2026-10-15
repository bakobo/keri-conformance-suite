"""keri.process through heti: each message is asked about by its own SAID, and heti's answer or
refusal becomes the message's reading."""

import json
import pathlib

import pytest

from kcs_adapter_heti import process, protocol

KELS = json.loads((pathlib.Path(__file__).parent / "fixtures" / "kels.json").read_text())


def request(name=None, messages=None, **over):
    streams = KELS[name] if name else messages
    return {"id": 1, "op": "keri.process", "perspective": {"role": "validator"},
            "messages": [{"stream": s, "source": "controller"} for s in streams], **over}


def readings(result):
    return [(d["initial"], d["final"], d["trunk"]) for d in result["dispositions"]]


def test_an_in_order_kel_is_seen_on_the_trunk_and_its_key_state_reported():
    result = process.process(request("in-order"))
    assert readings(result) == [("seen", "seen", True)] * 4
    state, = result["key_states"].values()
    assert state["sn"] == 3 and state["kt"] == "1" and state["nt"] == "1"
    assert state["bt"] == "0" and state["wits"] == [] and state["delegator"] is None
    assert state["said"].startswith("E") and len(state["keys"]) == len(state["ndigs"]) == 1


def test_an_early_event_is_pending_until_the_gap_is_filled():
    assert readings(process.process(request("early"))) == [
        ("seen", "seen", True), ("pending", "seen", True), ("seen", "seen", True)]


def test_copies_with_one_body_combine_their_signatures():
    assert readings(process.process(request("second-copy"))) == [
        ("pending", "seen", True), ("seen", "seen", True)]


def test_a_corrupt_copy_is_not_seen_because_a_valid_copy_of_its_said_is():
    result = process.process(request("corrupt-copy"))
    assert readings(result)[2] == ("pending", "pending", False)
    assert readings(result)[3] == ("seen", "seen", True)
    assert result["dispositions"][2]["reason"].startswith("e.state.missing.kel")


def test_a_forged_inception_is_rejected_and_no_key_state_is_reported():
    result = process.process(request("forged"))
    assert readings(result) == [("rejected", "rejected", False)]
    assert result["dispositions"][0]["reason"].startswith("e.proof.")
    assert result["key_states"] == {}


def test_a_duplicitous_identifier_keeps_its_seen_events_but_has_no_key_state():
    result = process.process(request("conflict"))
    assert readings(result) == [("seen", "seen", True), ("seen", "seen", True),
                                ("pending", "pending", False)]
    assert result["key_states"] == {}


def test_a_receipt_is_rejected_because_heti_reports_none():
    result = process.process(request("receipts"))
    assert readings(result)[0] == ("pending", "seen", True)
    for receipt in result["dispositions"][1:]:
        assert (receipt["initial"], receipt["final"], receipt["trunk"]) == (
            "rejected", "rejected", False)
        assert receipt["reason"] == process.NOT_A_KEY_EVENT


def test_a_delegated_identifier_reports_its_delegator():
    result = process.process(request("delegated"))
    assert readings(result) == [("seen", "seen", True)] * 3
    delegates = [s for s in result["key_states"].values() if s["delegator"]]
    assert len(result["key_states"]) == 2 and len(delegates) == 1
    assert delegates[0]["delegator"] in result["key_states"]


def test_a_weighted_threshold_is_reported_as_lists_of_fractions():
    state, = process.process(request("weighted"))["key_states"].values()
    assert isinstance(state["kt"], list) and all(isinstance(c, (list, str)) for c in state["kt"])


def test_witnesses_and_their_threshold_are_reported():
    state, = process.process(request("witnessed"))["key_states"].values()
    assert state["wits"] and state["bt"] == f"{int(state['bt'], 16):x}"


def test_a_non_transferable_identifier_is_rejected_by_heti_by_name():
    result = process.process(request("nontransferable"))
    assert all(d["final"] == "rejected" for d in result["dispositions"])
    assert "e.feature.unsupported" in result["dispositions"][0]["reason"]


def test_a_stream_heti_cannot_frame_is_rejected():
    result = process.process(request("malformed"))
    assert readings(result) == [("rejected", "rejected", False)]


@pytest.mark.parametrize("stream", ["", "00ff", KELS["in-order"][0][:60]])
def test_a_message_naming_no_event_is_rejected_without_asking_heti(stream):
    result = process.process(request(messages=[stream]))
    assert readings(result) == [("rejected", "rejected", False)]
    assert result["dispositions"][0]["reason"] == process.NO_EVENT
    assert result["key_states"] == {}


def test_a_message_heti_refuses_as_evidence_does_not_spoil_the_others():
    stream = bytes.fromhex(KELS["in-order"][0])
    unpinned = stream.removeprefix(process.verify.GENUS).hex()
    result = process.process(request(messages=[KELS["in-order"][0], "00", unpinned]))
    assert readings(result) == [("seen", "seen", True), ("rejected", "rejected", False),
                                ("rejected", "rejected", False)]
    assert "e.input.missing" in result["dispositions"][2]["reason"]
    assert len(result["key_states"]) == 1


def test_a_body_nested_too_deeply_to_read_names_no_event():
    tail = b'","t":"icp","x":' + b"[" * 100000 + b"]" * 100000 + b"}"
    size = len(b'{"v":"KERICAACAAJSONAAAA.') + len(tail)
    digits = "".join(process.verify.B64[size >> 6 * n & 63] for n in (3, 2, 1, 0)).encode()
    body = b'{"v":"KERICAACAAJSON' + digits + b"." + tail
    result = process.process(request(messages=[(process.verify.GENUS + body).hex()]))
    assert readings(result) == [("rejected", "rejected", False)]


def test_more_messages_than_the_adapter_replays_is_refused():
    response = json.loads(protocol.handle_line(json.dumps(
        request(messages=KELS["in-order"][:1] * (process.MAX_MESSAGES + 1))).encode()))
    assert response["error"]["kind"] == "unsupported"
    assert process.E_TOO_MANY in response["error"]["message"]


def test_an_identifier_heti_cannot_parse_is_rejected():
    stream = bytes.fromhex(KELS["in-order"][0])
    sad = process.verify.split(stream)[0]
    forged = stream.replace(sad["i"].encode(), b"X" * len(sad["i"]))
    result = process.process(request(messages=[forged.hex()]))
    assert readings(result) == [("rejected", "rejected", False)]
    assert "not a qualified KERI identifier" in result["dispositions"][0]["reason"]


def test_an_uncoded_failure_inside_heti_is_an_adapter_error(monkeypatch):
    def broken(**kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(process, "resolve_key_state", broken)
    with pytest.raises(RuntimeError):
        process.process(request("in-order"))


def test_an_uncoded_failure_resolving_a_key_state_is_an_adapter_error(monkeypatch):
    real = process.resolve_key_state

    def broken(**kwargs):
        if kwargs.get("as_of") is None:
            raise RuntimeError("boom")
        return real(**kwargs)

    monkeypatch.setattr(process, "resolve_key_state", broken)
    with pytest.raises(RuntimeError):
        process.process(request("in-order"))


@pytest.mark.parametrize("over", [
    {"messages": 7}, {"messages": [7]}, {"messages": [{"stream": "XY"}]},
    {"perspective": 7}, {"perspective": None},
])
def test_a_malformed_request_is_a_harness_error(over):
    response = json.loads(protocol.handle_line(json.dumps(request("in-order") | over).encode()))
    assert response["error"]["kind"] == "harness"
    assert process.E_MALFORMED in response["error"]["message"]


def test_a_perspective_other_than_a_validator_is_unsupported():
    response = json.loads(protocol.handle_line(json.dumps(
        request("in-order", perspective={"role": "witness"})).encode()))
    assert response["error"]["kind"] == "unsupported"
    assert process.E_PERSPECTIVE in response["error"]["message"]


def test_keri_process_is_declared_with_what_heti_does_itself():
    result = protocol.hello({"supported": [1]})
    assert "keri.process" in result["operations"] and result["composes"] == []
    for feature in process.FEATURES:
        assert feature in result["features"]
    for absent in ("keri.routing", "kel.recovery", "kel.nontransferable", "keri.duplicity",
                   "keri.version-1.x"):
        assert absent not in result["features"]
