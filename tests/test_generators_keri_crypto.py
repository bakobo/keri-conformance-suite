"""The KERI generator's standard-library cryptography: BLAKE3 over inputs longer than one chunk,
and Ed25519 signing and verification. Both are checked against published test vectors, so the
cases' SAIDs and signatures do not rest on the generator's own word."""

import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from generators.spec_tables import blake3, ed25519

# The official BLAKE3 test vectors (BLAKE3-team/BLAKE3, test_vectors/test_vectors.json): the input
# is the bytes 0, 1, ..., 250, 0, 1, ... of the given length; the hash is the first 32 bytes.
BLAKE3_VECTORS = {
    0: "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
    1023: "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11",
    1024: "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7",
    1025: "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444",
    2048: "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a",
    2049: "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b6879522563030",
    3072: "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd2",
    3073: "7124b49501012f81cc7f11ca069ec9226cecb8a2c850cfe644e327d22d3e1cd3",
    4096: "015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e969",
    5121: "628bd2cb2004694adaab7bbd778a25df25c47b9d4155a55f8fbd79f2fe154cff",
}


@pytest.mark.parametrize("length", sorted(BLAKE3_VECTORS))
def test_blake3_matches_the_official_vectors_across_chunk_boundaries(length):
    data = bytes(i % 251 for i in range(length))
    assert blake3.digest(data).hex() == BLAKE3_VECTORS[length]


# RFC 8032, section 7.1, TEST 1 to TEST 3: secret key (seed), public key, message, signature.
RFC8032 = [
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
     ("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e3970"
      "1cf9b46bd25bf5f0595bbe24655141438e7a100b")),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
     ("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613"
      "d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")),
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
     "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
     ("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760"
      "984dc6594a7c15e9716ed28dc027beceea1ec40a")),
]


@pytest.mark.parametrize("seed,public,message,signature", RFC8032)
def test_ed25519_matches_rfc8032(seed, public, message, signature):
    seed, message = bytes.fromhex(seed), bytes.fromhex(message)
    assert ed25519.public_key(seed).hex() == public
    assert ed25519.sign(seed, message).hex() == signature
    assert ed25519.verify(bytes.fromhex(public), message, bytes.fromhex(signature))


def test_ed25519_refuses_a_signature_over_other_bytes():
    _, public, _, signature = RFC8032[1]
    assert not ed25519.verify(bytes.fromhex(public), b"\x73", bytes.fromhex(signature))


def test_ed25519_refuses_a_signature_by_another_key():
    _, _, message, signature = RFC8032[1]
    other = bytes.fromhex(RFC8032[0][1])
    assert not ed25519.verify(other, bytes.fromhex(message), bytes.fromhex(signature))


@pytest.mark.parametrize("public,signature", [
    (bytes(31), bytes(64)),  # a public key of the wrong length
    (bytes.fromhex(RFC8032[0][1]), bytes(63)),  # a signature of the wrong length
    (bytes.fromhex(RFC8032[0][1]), bytes(32) + b"\xff" * 32),  # S not below the group order
    (b"\xff" * 32, bytes(64)),  # a public key that encodes no curve point
    (bytes.fromhex(RFC8032[0][1]), (2).to_bytes(32, "little") + bytes(32)),  # R is no point
])
def test_ed25519_refuses_malformed_inputs_without_raising(public, signature):
    assert not ed25519.verify(public, b"", signature)


def test_ed25519_refuses_a_point_whose_x_cannot_be_recovered():
    # y = 2 gives an x^2 with no square root modulo p.
    assert ed25519._decode_point((2).to_bytes(32, "little")) is None


def test_ed25519_refuses_a_negative_zero_x():
    # y = 1 decodes to x = 0, which must not carry the sign bit.
    assert ed25519._decode_point(((1 << 255) | 1).to_bytes(32, "little")) is None


def test_ed25519_refuses_a_negative_zero_x_at_y_equal_p_minus_1():
    # y = P - 1 also gives x**2 == 0, but only once x**2 is reduced modulo P; the sign bit must
    # still be refused, not decode to x = P.
    assert ed25519._decode_point(((1 << 255) | (ed25519.P - 1)).to_bytes(32, "little")) is None


def test_ed25519_seeds_are_32_bytes():
    with pytest.raises(ValueError, match="32 bytes"):
        ed25519.public_key(bytes(31))
