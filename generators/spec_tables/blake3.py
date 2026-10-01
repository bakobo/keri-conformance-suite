"""BLAKE3 with a 32-byte output, in pure Python, for inputs of at most one chunk (1024 bytes).

The CESR specification's SAID examples use Blake3-256 (code `E`), and the generators may use only
the standard library, which has no BLAKE3. One chunk is all a single message body here needs;
longer input is refused rather than hashed wrongly. The implementation follows the BLAKE3
reference (https://github.com/BLAKE3-team/BLAKE3/blob/master/reference_impl/reference_impl.rs)
and is checked against the CESR specification's own worked SAID example.
"""

IV = (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
      0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)
PERMUTATION = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)
CHUNK_START, CHUNK_END, ROOT = 1, 2, 8
BLOCK_LEN, CHUNK_LEN = 64, 1024
MASK = 0xFFFFFFFF


def _rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & MASK


def _g(s, a, b, c, d, mx, my):
    s[a] = (s[a] + s[b] + mx) & MASK
    s[d] = _rotr(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & MASK
    s[b] = _rotr(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b] + my) & MASK
    s[d] = _rotr(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & MASK
    s[b] = _rotr(s[b] ^ s[c], 7)


def _compress(cv, block, block_len, flags):
    s = list(cv) + list(IV[:4]) + [0, 0, block_len, flags]
    m = list(block)
    for r in range(7):
        _g(s, 0, 4, 8, 12, m[0], m[1])
        _g(s, 1, 5, 9, 13, m[2], m[3])
        _g(s, 2, 6, 10, 14, m[4], m[5])
        _g(s, 3, 7, 11, 15, m[6], m[7])
        _g(s, 0, 5, 10, 15, m[8], m[9])
        _g(s, 1, 6, 11, 12, m[10], m[11])
        _g(s, 2, 7, 8, 13, m[12], m[13])
        _g(s, 3, 4, 9, 14, m[14], m[15])
        if r < 6:
            m = [m[i] for i in PERMUTATION]
    return [s[i] ^ s[i + 8] for i in range(8)]


def digest(data: bytes) -> bytes:
    """The 32-byte BLAKE3 hash of ``data``, which must fit in one 1024-byte chunk."""
    if len(data) > CHUNK_LEN:
        raise ValueError(f"This BLAKE3 hashes at most {CHUNK_LEN} bytes; got {len(data)}.")
    blocks = [data[i:i + BLOCK_LEN] for i in range(0, len(data), BLOCK_LEN)] or [b""]
    cv = IV
    for n, block in enumerate(blocks):
        flags = (CHUNK_START if n == 0 else 0)
        if n == len(blocks) - 1:
            flags |= CHUNK_END | ROOT
        padded = block.ljust(BLOCK_LEN, b"\0")
        words = [int.from_bytes(padded[i:i + 4], "little") for i in range(0, BLOCK_LEN, 4)]
        cv = _compress(cv, words, len(block), flags)
    return b"".join(w.to_bytes(4, "little") for w in cv)
