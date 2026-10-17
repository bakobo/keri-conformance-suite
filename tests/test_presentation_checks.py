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


COUPLE = b"0A" + b"A" * 22 + b"E" + b"B" * 43  # 68 characters, 17 quadlets


@pytest.mark.parametrize("attachments,outcome", [
    (b"", "pass"),
    (b"-CAA", "pass"),
    (b"-CAS-SAR" + COUPLE, "pass"),
    (b"--CAAAAS-SAR" + COUPLE, "pass"),
    (b"-CAB-SAA", "fail"),  # an empty couple group
    (b"-CAT-SAR" + COUPLE, "fail"),  # the count measures more than follows
    (b"-CAB-!AA", "fail"),  # not in the text domain
    (b"-CAB-\xc3\xa9A", "fail"),
    (b"-CAC-KABAAAA", "fail"),  # a group a presentation does not carry
    (b"-CAS-SAR" + COUPLE[:-1] + b"!", "fail"),
    (b"-CAS-SAR" + b"0A" + b"A" * 22 + b"E" + b"_" * 43, "fail"),  # not canonical
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
    SECRET.encode().hex().upper().encode(),
    "".join(c.upper() if i % 2 else c for i, c in enumerate(SECRET.encode().hex())).encode(),
    "".join(f"\\u{ord(c):04x}" for c in SECRET).encode(),
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


def test_a_secret_escaped_in_a_refusal_reason_fails():
    reason = {"refused": {"reason": "".join(f"\\u{ord(c):04X}" for c in SECRET)}}
    assert evaluate(secrets(SECRET), reason).outcome == "fail"


def test_a_character_beyond_the_bmp_escaped_as_a_surrogate_pair_fails():
    hidden = "Grinning \U0001F600 holder"
    units = hidden.encode("utf-16-be")
    escaped = "".join(f"\\u{int.from_bytes(units[i:i + 2], 'big'):04x}"
                      for i in range(0, len(units), 2))
    assert evaluate(secrets(hidden), {"refused": {"reason": escaped}}).outcome == "fail"


def test_escaped_uppercase_hex_fails():
    escaped = "".join(f"\\u{ord(c):04x}" for c in SECRET.encode().hex().upper())
    assert evaluate(secrets(SECRET), {"refused": {"reason": escaped}}).outcome == "fail"


def test_an_unpaired_surrogate_in_a_reason_is_read_not_raised():
    assert evaluate(secrets(SECRET), {"refused": {"reason": "\ud800"}}).outcome == "pass"


def test_a_presentation_longer_than_a_stream_may_be_fails():
    huge = {"presented": {"stream": "00" * (1024 * 1024 + 1)}}
    assert evaluate(presented(), huge).outcome == "fail"


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
