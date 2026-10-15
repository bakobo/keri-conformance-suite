"""Reading an issuer's anchoring event, as the acdc.issue checks need it (docs/adapter-protocol.md,
acdc.issue).

The anchoring event comes back as a stream: an optional genus/version code, a KERI 2.00 JSON body
framed by its version string, and attachments. The runner checks the body byte for byte and that
the attachments carry a signature by each signing key the case names, at its index. It does that
without parsing the attachments: Ed25519 signing is deterministic, so it computes each signature
the case's own seed makes over the body and looks for its CESR encoding, text or binary, among the
attachments. The work is therefore bounded by the case, never by what the adapter returned: the
body is refused above a size bound before anything is signed, and the number of signatures is the
number of signers the case names.
"""

import base64

from keri_conformance import ed25519

GENUS = b"-_AAACAA"  # the genus/version code of CESR 2.00
BODY_START = b'{"v":"KERI'
# A KERI 2.00 version string: protocol (4), protocol version (3), genus version (3),
# serialization (4), size (4), "." (1), as in KERICAACAAJSONAAFb.
VERSION_LEN = 19
KIND_AT = 10
SIZE_AT = 14
# A generous bound on an anchoring event's body: one interaction event with a few seals.
MAX_BODY = 64 * 1024
B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


class Unframed(Exception):
    """The stream does not hold one KERI 2.00 JSON body the runner can frame."""


def _b64_int(text: bytes) -> int:
    value = 0
    for byte in text:
        if chr(byte) not in B64:
            raise Unframed(f"the version string's size {text!r} is not Base64")
        value = value * 64 + B64.index(chr(byte))
    return value


def frame(stream: bytes) -> tuple[bytes, bytes]:
    """The body and the attachments of an anchoring event's stream."""
    rest = stream.removeprefix(GENUS)
    if not rest.startswith(BODY_START):
        raise Unframed("it does not begin with a KERI JSON body, after any genus/version code")
    start = len(b'{"v":"')
    version = rest[start:start + VERSION_LEN]
    if (len(version) < VERSION_LEN or version[-1:] != b"."
            or version[KIND_AT:KIND_AT + 4] != b"JSON"):
        raise Unframed("its version string is not a KERI 2.00 JSON version string")
    size = _b64_int(version[SIZE_AT:SIZE_AT + 4])
    if size > MAX_BODY:
        raise Unframed(f"its body declares {size} bytes, more than the {MAX_BODY} the runner "
                       "reads for an anchoring event")
    if size > len(rest):
        raise Unframed(f"its body declares {size} bytes, but only {len(rest)} follow")
    return rest[:size], rest[size:]


def indexed_signature(index: int, signature: bytes) -> str:
    """The CESR text encoding of an Ed25519 indexed signature (code A, one index character)."""
    if not 0 <= index < 64 or len(signature) != 64:
        raise ValueError("an Ed25519 indexed signature has an index below 64 and 64 bytes")
    return "A" + B64[index] + base64.urlsafe_b64encode(b"\x00\x00" + signature).decode()[2:]


def missing_signatures(body: bytes, attachments: bytes, signers: list[str],
                       seeds: dict[str, str]) -> list[str]:
    """The signers, by public key, whose signature over ``body`` at their index the attachments
    do not carry in either domain."""
    missing = []
    for index, key in enumerate(signers):
        signature = ed25519.sign(bytes.fromhex(seeds[key]), body)
        text = indexed_signature(index, signature)
        binary = base64.urlsafe_b64decode(text)
        if text.encode() not in attachments and binary not in attachments:
            missing.append(key)
    return missing
