"""keri.process through a fresh keripy Kevery: every reading comes from keripy's own state.

Streams are built with keripy's own eventing helpers (incept, rotate, interact, receipt,
messagize) and signed with fixed seeds, so these tests check that the adapter reports what keripy
did with them, never what a case expects. keripy 1.2.14 implements only KERI 1.x bodies and the
adapter does not declare keri.process there; the tests marked ``main`` run on keripy main only.
"""

import json

import pytest
from conftest import GENERATION

from kcs_adapter_keripy import kel, protocol

pytestmark = pytest.mark.main

if GENERATION == "main":
    from keri.core import coring, eventing, signing
    from keri.core.coring import MtrDex
    from keri.kering import Kinds, Vrsn_2_0

    def signer(n, transferable=True):
        return signing.Signer(raw=bytes([n]) * 32, transferable=transferable)

    A0, A1, A2, X = signer(1), signer(2), signer(3), signer(4)
    B0, B1 = signer(5), signer(6)
    W1, W2 = signer(11, False), signer(12, False)
    D0, D1, E0, E1 = signer(21), signer(22), signer(31), signer(32)

    def dig(s):
        return coring.Diger(ser=s.verfer.qb64b).qb64

    def common():
        return {"pvrsn": Vrsn_2_0, "kind": Kinds.json}


def icp(keys=None, nxt=None, isith="1", nsith="1", wits=(), toad=0, cnfg=None, data=None,
        delpre=None):
    keys = keys or [A0]
    nxt = [A1] if nxt is None else nxt
    kwa = dict(isith=isith, ndigs=[dig(s) for s in nxt], nsith=nsith if nxt else "0",
               wits=[w.verfer.qb64 for w in wits], toad=toad, cnfg=cnfg or [], data=data or [],
               code=MtrDex.Blake3_256, **common())
    if delpre:
        return eventing.delcept(keys=[s.verfer.qb64 for s in keys], delpre=delpre, **kwa)
    return eventing.incept(keys=[s.verfer.qb64 for s in keys], **kwa)


def rot(prior, sn, keys, nxt, ilk="rot"):
    return eventing.rotate(pre=prior.pre, keys=[s.verfer.qb64 for s in keys], dig=prior.said,
                           ilk=ilk, sn=sn, ndigs=[dig(s) for s in nxt], **common())


def ixn(prior, sn, data=None):
    return eventing.interact(pre=prior.pre, dig=prior.said, sn=sn, data=data or [], **common())


def signed(serder, signers, wits=(), seal=None):
    sigers = [s.sign(serder.raw, index=i) for i, s in enumerate(signers) if s is not None]
    wigers = [w.sign(serder.raw, index=i) for i, w in wits]
    return bytes(eventing.messagize(serder, sigers=sigers, wigers=wigers or None, bonds=seal))


def receipt(serder, wits):
    rct = eventing.receipt(pre=serder.pre, sn=serder.sn, said=serder.said, **common())
    wigers = [w.sign(serder.raw, index=i) for i, w in wits]
    return bytes(eventing.messagize(rct, wigers=wigers))


def process(*messages, perspective=None):
    request = {"id": 5, "op": "keri.process",
               "perspective": perspective or {"role": "validator"},
               "messages": [{"stream": m.hex(), "source": "test"} for m in messages]}
    return json.loads(protocol.handle_line(json.dumps(request).encode()))


def readings(response):
    return [(d["initial"], d["final"], d["trunk"]) for d in response["result"]["dispositions"]]


SEEN = ("seen", "seen", True)


def test_hello_declares_keri_process_and_the_kel_features():
    hello = json.loads(protocol.handle_line(b'{"id":0,"op":"hello","protocol":1}'))["result"]
    assert hello["operations"] == ["cesr.parse", "cesr.encode", "keri.process"]
    assert set(kel.FEATURES) <= set(hello["features"])
    assert hello["composes"] == []


def test_an_inception_is_seen_on_the_trunk_with_keripys_key_state():
    serder = icp()
    response = process(signed(serder, [A0]))
    assert readings(response) == [SEEN]
    state = response["result"]["key_states"][serder.pre]
    assert state == {"sn": 0, "said": serder.said, "keys": [A0.verfer.qb64], "kt": "1",
                     "ndigs": [dig(A1)], "nt": "1", "wits": [], "bt": "0", "delegator": None}


def test_an_in_order_kel_ends_at_its_last_event():
    i = icp()
    x1 = ixn(i, 1)
    r2 = rot(x1, 2, [A1], [A2])
    response = process(signed(i, [A0]), signed(x1, [A0]), signed(r2, [A1]))
    assert readings(response) == [SEEN] * 3
    state = response["result"]["key_states"][i.pre]
    assert (state["sn"], state["said"], state["keys"]) == (2, r2.said, [A1.verfer.qb64])


def test_a_forged_or_unsigned_inception_is_rejected():
    serder = icp()
    forged = signed(serder, [X])
    unsigned = bytes(serder.raw)
    response = process(forged, unsigned)
    assert readings(response) == [("rejected", "rejected", False)] * 2
    assert response["result"]["key_states"] == {}


def test_an_unparseable_stream_is_rejected():
    assert readings(process(b"not a key event")) == [("rejected", "rejected", False)]


def test_an_early_event_is_pending_then_seen_once_quiescence_drains_the_escrow():
    i = icp()
    x1 = ixn(i, 1)
    x2 = ixn(x1, 2)
    response = process(signed(i, [A0]), signed(x2, [A0]), signed(x1, [A0]))
    assert readings(response) == [SEEN, ("pending", "seen", True), SEEN]


def test_an_event_under_its_threshold_is_pending():
    serder = icp(keys=[A0, B0], isith="2", nxt=[A1, B1], nsith="2")
    assert readings(process(signed(serder, [A0, None]))) == [("pending", "pending", False)]


def test_a_conflicting_interaction_is_duplicitous():
    i = icp()
    x1 = ixn(i, 1)
    x1b = ixn(i, 1, data=[{"i": i.pre, "s": "0", "d": i.said}])
    response = process(signed(i, [A0]), signed(x1, [A0]), signed(x1b, [A0]))
    assert readings(response)[2] == ("duplicitous", "duplicitous", False)


def test_a_superseded_interaction_stays_seen_and_leaves_the_trunk():
    i = icp()
    x1 = ixn(i, 1)
    r1 = rot(i, 1, [A1], [A2])
    response = process(signed(i, [A0]), signed(x1, [A0]), signed(r1, [A1]))
    assert readings(response) == [SEEN, ("seen", "seen", False), SEEN]
    assert response["result"]["key_states"][i.pre]["said"] == r1.said


def test_receipts_are_reported_by_what_keripy_did_with_their_signatures():
    serder = icp(wits=[W1, W2], toad=2)
    good = receipt(serder, [(0, W1)])
    forged = receipt(serder, [(1, W1)])  # indexed to W2, signed by W1
    late = receipt(serder, [(1, W2)])
    response = process(signed(serder, [A0]), good, forged, late)
    got = readings(response)
    # keripy attaches a witness signature to its copy of an event it holds in escrow, so the
    # first receipt is seen on arrival although its event is not accepted until the third.
    assert got[0] == ("pending", "seen", True)
    assert got[1] == ("seen", "seen", False)
    assert got[2] == ("rejected", "rejected", False)
    assert got[3] == ("seen", "seen", False)
    assert response["result"]["key_states"][serder.pre]["wits"] == [W1.verfer.qb64,
                                                                    W2.verfer.qb64]
    assert response["result"]["key_states"][serder.pre]["bt"] == "2"


def test_a_receipt_for_an_event_keripy_never_received_is_held_as_pending():
    serder = icp(wits=[W1], toad=1)
    assert readings(process(receipt(serder, [(0, W1)]))) == [("pending", "pending", False)]


def test_a_delegated_inception_reports_its_delegator():
    d = icp(keys=[D0], nxt=[D1])
    e = icp(keys=[E0], nxt=[E1], delpre=d.pre)
    dx = ixn(d, 1, data=[{"i": e.pre, "s": "0", "d": e.said}])
    seal = eventing.SealSource(s=f"{dx.sn:x}", d=dx.said)
    response = process(signed(d, [D0]), signed(dx, [D0]), signed(e, [E0], seal=seal))
    assert readings(response) == [SEEN] * 3
    assert response["result"]["key_states"][e.pre]["delegator"] == d.pre


def test_requests_are_independent():
    serder = icp()
    first = process(signed(serder, [A0]))
    second = process(signed(ixn(serder, 1), [A0]))
    assert readings(first) == [SEEN]
    assert readings(second) == [("pending", "pending", False)]
    assert second["result"]["key_states"] == {}


@pytest.mark.parametrize("request_fields,match", [
    ({"messages": "x"}, '"messages"'),
    ({"messages": [{"stream": "zz", "source": "s"}]}, '"stream"'),
    ({"messages": ["x"]}, '"messages"'),
    ({"messages": [{"stream": "00"}], "perspective": "validator"}, '"perspective"'),
])
def test_malformed_requests_are_harness_errors(request_fields, match):
    request = {"id": 6, "op": "keri.process", "perspective": {"role": "validator"},
               **request_fields}
    response = json.loads(protocol.handle_line(json.dumps(request).encode()))
    assert response["error"]["kind"] == "harness"
    assert match in response["error"]["message"]


def test_a_perspective_other_than_validator_is_unsupported():
    response = process(signed(icp(), [A0]), perspective={"role": "witness"})
    assert response["error"]["kind"] == "unsupported"
    assert kel.E_PERSPECTIVE in response["error"]["message"]


def test_an_implementation_that_never_quiesces_is_an_error_not_a_reading(monkeypatch):
    counter = iter(range(10**6))
    monkeypatch.setattr(kel, "fingerprint", lambda db: next(counter))
    response = process(signed(icp(), [A0]))
    assert response["error"]["kind"] == "harness"
    assert kel.E_QUIESCENCE in response["error"]["message"]


def test_a_keripy_exception_while_delivering_is_logged_and_the_message_reported(monkeypatch,
                                                                              capsys):
    def refuse(self, ims):
        raise ValueError("refused")

    monkeypatch.setattr(kel.parsing.Parser, "parse", refuse)
    response = process(signed(icp(), [A0]))
    assert readings(response) == [("rejected", "rejected", False)]
    assert "keripy refused a message: ValueError" in capsys.readouterr().err


def test_an_empty_message_list_is_an_empty_result():
    assert process()["result"] == {"dispositions": [], "key_states": {}}

