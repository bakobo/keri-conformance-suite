"""exn.verify through one fresh keripy Exchanger: each reading is whether keripy logged the message
as an accepted exchange (db.exns), at quiescence after its own delivery and after the last message.

keripy main only; keripy 1.2.14 does not declare the operation (test_exchange_onex.py).
"""

import pytest
from conftest import GENERATION

pytestmark = pytest.mark.main

if GENERATION == "main":
    import bundles as b
    from keri.core import eventing

    from kcs_adapter_keripy import exchange, kel

    A, B = b.Issuer(1, 2), b.Issuer(5, 6)


def readings(response):
    return [(v["on_delivery"], v["verdict"]) for v in response["result"]["verdicts"]]


ACCEPTED = ("accepted", "accepted")
REJECTED = ("rejected", "rejected")


def test_an_exchange_message_signed_by_its_sender_is_accepted():
    message = b.exn_signed(b.exn(A.pre), A.key, A.icp)
    assert readings(b.exchange(A.kel(), [message])) == [ACCEPTED]


def test_a_non_transferable_sender_signing_with_its_own_key_is_accepted():
    nontrans = b.signer(41, transferable=False)
    message = b.exn_cigned(b.exn(nontrans.verfer.qb64), nontrans)
    assert readings(b.exchange([], [message])) == [ACCEPTED]


def test_a_valid_signature_by_another_aid_is_not_the_senders():
    message = b.exn_signed(b.exn(A.pre), B.key, B.icp)
    assert readings(b.exchange(A.kel() + B.kel(), [message])) == [REJECTED]


def test_a_forged_signature_is_rejected():
    message = b.exn_signed(b.exn(A.pre), B.key, A.icp)
    assert readings(b.exchange(A.kel(), [message])) == [REJECTED]


def test_a_message_from_a_sender_whose_kel_is_absent_is_rejected_though_keripy_holds_it():
    # keripy escrows it as partially signed (db.epse); held is not accepted.
    message = b.exn_signed(b.exn(A.pre), A.key, A.icp)
    assert readings(b.exchange([], [message])) == [REJECTED]


def test_an_unsigned_message_and_an_unparseable_stream_are_rejected():
    unsigned = b.attached(b.exn(A.pre))
    assert readings(b.exchange(A.kel(), [unsigned, b"not a message"])) == [REJECTED] * 2


def test_a_tampered_body_is_rejected():
    message = bytearray(b.exn_signed(b.exn(A.pre), A.key, A.icp))
    at = message.index(b"hello")
    message[at:at + 5] = b"HELLO"
    assert readings(b.exchange(A.kel(), [bytes(message)])) == [REJECTED]


def test_an_exchange_inception_is_rejected_because_keripy_does_not_process_one():
    # keripy main's Kevery.processXip is a stub: it neither verifies nor keeps an xip.
    xip = eventing.exchept(sender=A.pre, route="/test", nonce=b.UUID0, stamp=b.STAMP0,
                           **b.common())
    following = b.exn(A.pre, prior=xip.said, xid=xip.said)
    response = b.exchange(A.kel(), [b.exn_signed(xip, A.key, A.icp),
                                    b.exn_signed(following, A.key, A.icp)])
    # keripy's Exchanger does not check p or x for a route it has no handler for.
    assert readings(response) == [REJECTED, ACCEPTED]


def test_a_message_is_read_on_delivery_and_after_the_last_message():
    first = b.exn_signed(b.exn(A.pre), A.key, A.icp)
    second = b.exn_signed(b.exn(A.pre, route="/test/again"), A.key, A.icp)
    assert readings(b.exchange(A.kel(), [first, second])) == [ACCEPTED, ACCEPTED]


def test_the_on_delivery_reading_is_taken_before_later_messages(monkeypatch):
    # A message keripy accepts only later must read rejected on delivery and accepted at the end.
    calls = []
    real = exchange.accepted

    def late(db, ident):
        calls.append(ident)
        return real(db, ident) and len(calls) > 1

    monkeypatch.setattr(exchange, "accepted", late)
    message = b.exn_signed(b.exn(A.pre), A.key, A.icp)
    assert readings(b.exchange(A.kel(), [message])) == [("rejected", "accepted")]


def test_requests_are_independent():
    message = b.exn_signed(b.exn(A.pre), A.key, A.icp)
    assert readings(b.exchange(A.kel(), [message])) == [ACCEPTED]
    assert readings(b.exchange([], [message])) == [REJECTED]


def test_an_empty_message_list_is_an_empty_result():
    assert b.exchange(A.kel(), [])["result"] == {"verdicts": []}


@pytest.mark.parametrize("fields,match", [
    ({"messages": "x"}, '"messages"'),
    ({"kels": [{"stream": "zz", "source": "s"}]}, '"stream"'),
    ({"kels": None}, '"kels"'),
    ({"perspective": "validator"}, '"perspective"'),
])
def test_malformed_requests_are_harness_errors(fields, match):
    response = b.handle({"id": 8, "op": "exn.verify", "perspective": {"role": "validator"},
                         "kels": [], "messages": [], **fields})
    assert response["error"]["kind"] == "harness"
    assert match in response["error"]["message"]


def test_a_perspective_other_than_validator_is_unsupported():
    response = b.exchange(perspective={"role": "witness"})
    assert response["error"]["kind"] == "unsupported"
    assert kel.E_PERSPECTIVE in response["error"]["message"]


def test_a_keripy_exception_while_delivering_is_logged_and_the_message_reported(monkeypatch,
                                                                              capsys):
    def refuse(self, ims):
        raise ValueError("refused")

    monkeypatch.setattr(kel.parsing.Parser, "parse", refuse)
    message = b.exn_signed(b.exn(A.pre), A.key, A.icp)
    assert readings(b.exchange([], [message])) == [REJECTED]
    assert "keripy refused a message: ValueError" in capsys.readouterr().err


def test_a_copy_of_an_accepted_message_reads_accepted_whatever_its_attachments():
    # Readings are keyed by SAID, as keri.process keys an event: keripy holds the message as
    # accepted, although it refused the forged copy's own signatures.
    body = b.exn(A.pre)
    genuine, forged = b.exn_signed(body, A.key, A.icp), b.exn_signed(body, B.key, A.icp)
    assert readings(b.exchange(A.kel(), [forged, genuine, forged])) == [
        ("rejected", "accepted"), ACCEPTED, ACCEPTED]
