"""Base64 as CESR uses it: the RFC 4648 URL- and filename-safe alphabet, never with `=` padding,
and base 64 integers written big-endian with `A` as zero."""

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
_INDEX = {c: i for i, c in enumerate(ALPHABET)}


def int_to_b64(value: int, length: int) -> str:
    """Write ``value`` as exactly ``length`` base 64 digits."""
    if value < 0:
        raise ValueError(f"A base 64 integer cannot be negative; got {value}.")
    if value >= 64**length:
        raise ValueError(f"The value {value} does not fit in {length} base 64 digits.")
    digits = []
    for _ in range(length):
        digits.append(ALPHABET[value % 64])
        value //= 64
    return "".join(reversed(digits))


def b64_to_int(text: str) -> int:
    """Read base 64 digits as a big-endian integer."""
    value = 0
    for c in text:
        if c not in _INDEX:
            raise ValueError(f"{c!r} is not a Base64 URL-safe character.")
        value = value * 64 + _INDEX[c]
    return value


def encode(data: bytes) -> str:
    """Naive Base64 conversion of ``data`` with any trailing pad characters removed."""
    bits = int.from_bytes(data, "big") if data else 0
    nbits = 8 * len(data)
    nchars = -(-nbits // 6)
    bits <<= 6 * nchars - nbits
    return int_to_b64(bits, nchars)


def decode(text: str) -> bytes:
    """Naive Base64 conversion of whole quadlets back to bytes."""
    if len(text) % 4:
        raise ValueError(f"Text of length {len(text)} is not a multiple of 4 characters.")
    return b64_to_int(text).to_bytes(len(text) * 3 // 4, "big") if text else b""
