"""Qualified digests, with the algorithm selected by CESR derivation code.

A SAID "MUST include a pre-pended derivation code that specifies the cryptographic algorithm used
to generate the digest" (CESR line 1186), "each serialization may use a different cryptographic
digest algorithm as indicated by its derivation code", and the SAID verification protocol computes
the digest "with the digest algorithm specified by the CESR derivation code of the copied SAID"
(CESR line 1194). A next-key digest names its function the same way (KERI line 1713). So every
digest the generators make or check, whatever the serialization around it, goes through this one
table, keyed by code:

- ``E`` Blake3-256, with the suite's own BLAKE3 (``blake3.py``);
- ``F`` Blake2b-256 and ``G`` Blake2s-256, the BLAKE2 parameter block with a 32-byte digest length
  (RFC 7693, section 2.5), which is not a truncated 512-bit digest; the CESR table names the
  algorithms without saying which, and this is the reading keripy also uses (~2ojl);
- ``H`` SHA3-256 and ``I`` SHA2-256.

The 512-bit digest codes are not computed, because no case uses one. Building with a code outside
the table is a scenario error; checking a digest whose code is outside it fails, which is failing
closed.
"""

import hashlib

from . import blake3, encoding
from .errors import ScenarioError
from .tables import Tables

ALGORITHMS = {
    "E": blake3.digest,
    "F": lambda data: hashlib.blake2b(data, digest_size=32).digest(),
    "G": lambda data: hashlib.blake2s(data, digest_size=32).digest(),
    "H": lambda data: hashlib.sha3_256(data).digest(),
    "I": lambda data: hashlib.sha256(data).digest(),
}
DEFAULT = "E"


def algorithm(code: str):
    """The digest function ``code`` names; a scenario naming any other code is refused."""
    try:
        return ALGORITHMS[code]
    except KeyError:
        raise ScenarioError(f"The code {code!r} names no digest algorithm the generators compute; "
                            f"they compute {sorted(ALGORITHMS)}.") from None


def raw(code: str, data: bytes) -> bytes:
    """The raw digest of ``data`` by the algorithm ``code`` names."""
    return algorithm(code)(data)


def qualified(t: Tables, code: str = DEFAULT, data: bytes = b"") -> str:
    """The digest of ``data`` by the algorithm ``code`` names, qualified with that code."""
    return encoding.primitive(t, code, raw(code, data))


def code_of(text: str) -> str:
    """The derivation code of a qualified primitive, by the master table's selector rules."""
    return text[:2] if text[:1].isdigit() else text[:1]


def verifies(t: Tables, claimed: str, data: bytes) -> bool:
    """Whether ``claimed`` is the digest of ``data`` by the algorithm its own code names."""
    code = code_of(claimed)
    if code not in ALGORITHMS:
        return False
    return qualified(t, code, data) == claimed
