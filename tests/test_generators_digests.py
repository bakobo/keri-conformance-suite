"""Qualified digests selected by CESR derivation code (generators/spec_tables/digests.py).

The CESR SAID verification protocol computes the digest "with the digest algorithm specified by the
CESR derivation code of the copied SAID" (CESR line 1194), so every digest the generators make or
check goes through one table keyed by code. Each algorithm is checked against a published test
vector for the input "abc"."""

import hashlib
import os
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from generators.spec_tables import blake3, digests, encoding, spec_source, tables
from generators.spec_tables.errors import ScenarioError

try:
    CESR_TEXT = spec_source.load_spec()
except spec_source.SpecUnavailable as e:
    if os.environ.get("KCS_REQUIRE_SPEC") == "1":
        raise
    pytest.skip(f"a pinned specification text is unavailable: {e}", allow_module_level=True)

T = tables.load(CESR_TEXT)

# Published digests of b"abc": SHA2-256 from FIPS 180-2 (appendix B.1), SHA3-256 from the NIST
# FIPS 202 examples, Blake2s-256 from RFC 7693 (appendix B), and Blake2b-256, the BLAKE2b
# parameter block with a 32-byte digest length (RFC 7693, section 2.5), as
# GNU coreutils' b2sum -l 256 prints it.
ABC = {
    "F": "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",
    "G": "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
    "H": "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
    "I": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
}


@pytest.mark.parametrize("code", sorted(ABC))
def test_each_algorithm_matches_its_published_vector(code):
    assert digests.raw(code, b"abc").hex() == ABC[code]


def test_blake3_is_the_suites_own_implementation():
    assert digests.raw("E", b"abc") == blake3.digest(b"abc")


def test_blake2b_256_is_not_a_truncated_blake2b_512():
    # RFC 7693 appendix A gives BLAKE2b-512("abc"); its first 32 bytes are a different value, and
    # a validator that truncates would compute other SAIDs.
    assert hashlib.blake2b(b"abc").hexdigest().startswith("ba80a53f981c4d0d")
    assert digests.raw("F", b"abc") != hashlib.blake2b(b"abc").digest()[:32]


def test_every_computable_code_is_a_32_byte_digest_in_the_master_table():
    for code in digests.ALGORITHMS:
        assert "Digest" in T.primitives[code].description
        assert T.raw_size(code) == 32


def test_qualified_prepends_the_code():
    q = digests.qualified(T, "I", b"abc")
    assert q == encoding.primitive(T, "I", bytes.fromhex(ABC["I"]))
    assert q.startswith("I") and len(q) == 44


def test_qualified_defaults_to_blake3():
    assert digests.qualified(T, data=b"abc") == encoding.primitive(T, "E", blake3.digest(b"abc"))


def test_a_code_with_no_algorithm_is_refused_when_building():
    with pytest.raises(ScenarioError, match="0D"):
        digests.raw("0D", b"abc")
    with pytest.raises(ScenarioError, match="'D'"):
        digests.qualified(T, "D", b"abc")


def test_code_of_follows_the_selector_rules():
    assert digests.code_of("IABC") == "I"
    assert digests.code_of("0DABC") == "0D"


@pytest.mark.parametrize("code", ["E", "F", "I"])
def test_verifies_recomputes_with_the_claimed_code(code):
    q = digests.qualified(T, code, b"content")
    assert digests.verifies(T, q, b"content")
    assert not digests.verifies(T, q, b"other content")


def test_a_value_computed_with_another_algorithm_does_not_verify():
    mislabelled = encoding.primitive(T, "I", blake3.digest(b"content"))
    assert not digests.verifies(T, mislabelled, b"content")


def test_a_code_the_model_cannot_compute_does_not_verify():
    # Fail closed: a 512-bit digest code, a key code and text that is no primitive all fail.
    assert not digests.verifies(T, "0D" + "A" * 86, b"content")
    assert not digests.verifies(T, "D" + "A" * 43, b"content")
    assert not digests.verifies(T, "", b"content")
