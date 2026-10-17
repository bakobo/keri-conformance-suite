"""A holder's answer to acdc.present, as the runner grades it (this.i 37ehqmh4): the body byte for
byte, the attachments by their shape, the secrets the disclosure hides by their absence in any
encoding, and a refusal by its shape."""

import base64
import json

import pytest

from keri_conformance.assertions import evaluate

GENUS = b"-_AAACAA"
B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def body(rest: bytes = b'"x":1') -> bytes:
    """An ACDC body whose version string declares its own size."""
    size = len(b'{"v":"ACDCCAACAAJSONAAAA.","d":"E",' + rest + b"}")
    digits = "".join(B64[(size >> shift) & 63] for shift in (18, 12, 6, 0))
    return b'{"v":"ACDCCAACAAJSON' + digits.encode() + b'.","d":"E",' + rest + b"}"


BODY = body()


def stream(body=BODY, attachments=b"") -> dict:
    return {"presented": {"stream": (GENUS + body + attachments).hex()}}


def presented(body=BODY):
    return {"id": "a1", "check": "presented", "level": "INTEROP",
            "expected": {"body": body.hex()}}


def secrets(*values):
    return {"id": "a2", "check": "secrets_absent", "level": "INTEROP", "expected": list(values)}


def test_the_body_must_match_byte_for_byte():
    assert evaluate(presented(), stream()).outcome == "pass"
    other = body(b'"x":2')
    assert evaluate(presented(), stream(other)).outcome == "fail"


@pytest.mark.parametrize("attachments,outcome", [
    (b"", "pass"),
    (b"-CAA", "pass"),
    (b"-CAB-SAA", "pass"),
    (b"--CAAAAB-SAA", "pass"),
    (b"-CAC-SAA", "fail"),  # the count measures more than follows
    (b"junk", "fail"),
])
def test_attachments_need_only_be_well_formed(attachments, outcome):
    assert evaluate(presented(), stream(attachments=attachments)).outcome == outcome


@pytest.mark.parametrize("result", [
    {"refused": {"reason": "no"}},
    {"presented": {"stream": "zz"}},
    {"presented": {"stream": BODY.hex()}},  # not genus-pinned
    {"presented": {"stream": (GENUS + b'{"v":"KERI').hex()}},
    {"presented": "x"},
])
def test_a_refusal_or_an_unreadable_presentation_fails(result):
    assert evaluate(presented(), result).outcome == "fail"


SECRET = "Salt Lake City"


@pytest.mark.parametrize("leak", [
    SECRET.encode(),
    SECRET.encode().hex().encode(),
    json.dumps(SECRET)[1:-1].encode(),
    base64.b64encode(b"x" + SECRET.encode()),
    base64.urlsafe_b64encode(b"xy" + SECRET.encode()),
])
def test_a_secret_leaked_in_any_encoding_fails(leak):
    leaky = body(b'"x":1,"y":"' + leak + b'"')
    assert evaluate(secrets("other secret", SECRET), stream(leaky)).outcome == "fail"


def test_a_short_secret_has_no_empty_base64_form_that_would_match_anything():
    from keri_conformance.assertions import _encodings
    assert b"" not in _encodings("ab") and all(len(form) >= 2 for form in _encodings("ab"))


def test_a_secret_in_the_response_outside_the_stream_fails():
    result = {**stream(), "extra": SECRET}
    assert evaluate(secrets(SECRET), result).outcome == "fail"


def test_absent_secrets_pass_and_a_refusal_carries_none():
    assert evaluate(secrets(SECRET), stream()).outcome == "pass"
    assert evaluate(secrets(SECRET), {"refused": {"reason": "no"}}).outcome == "pass"
    assert evaluate(secrets(SECRET), {"presented": {"stream": "zz"}}).outcome == "pass"


def test_a_refusal_is_graded_by_its_shape():
    refused = {"id": "a1", "check": "present_refused", "level": "INTEROP"}
    assert evaluate(refused, {"refused": {"reason": "no"}}).outcome == "pass"
    assert evaluate(refused, stream()).outcome == "fail"
