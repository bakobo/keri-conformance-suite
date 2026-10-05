"""BLAKE3 with a 32-byte output, in pure Python.

The CESR specification's SAID examples use Blake3-256 (code `E`), and the generators may use only
the standard library, which has no BLAKE3. KERI event bodies with many keys or seals exceed one
1024-byte chunk, so inputs of any length are hashed with the reference's chunk tree. The
implementation follows the BLAKE3 reference
(https://github.com/BLAKE3-team/BLAKE3/blob/master/reference_impl/reference_impl.rs) and is
checked against the CESR specification's own worked SAID example and the official test vectors.
"""

IV = (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
      0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)
PERMUTATION = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)
CHUNK_START, CHUNK_END, PARENT, ROOT = 1, 2, 4, 8
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


def _compress(cv, block, counter, block_len, flags):
    s = list(cv) + list(IV[:4]) + [counter & MASK, (counter >> 32) & MASK, block_len, flags]
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


def _words(block: bytes) -> list[int]:
    padded = block.ljust(BLOCK_LEN, b"\0")
    return [int.from_bytes(padded[i:i + 4], "little") for i in range(0, BLOCK_LEN, 4)]


def _chunk(data: bytes, counter: int, root: bool) -> list[int]:
    """The chaining value of one chunk, finalized as the root when it is the only chunk."""
    blocks = [data[i:i + BLOCK_LEN] for i in range(0, len(data), BLOCK_LEN)] or [b""]
    cv = IV
    for n, block in enumerate(blocks):
        flags = (CHUNK_START if n == 0 else 0)
        if n == len(blocks) - 1:
            flags |= CHUNK_END | (ROOT if root else 0)
        cv = _compress(cv, _words(block), counter, len(block), flags)
    return cv


def _parent(left: list[int], right: list[int], root: bool) -> list[int]:
    return _compress(IV, left + right, 0, BLOCK_LEN, PARENT | (ROOT if root else 0))


def digest(data: bytes) -> bytes:
    """The 32-byte BLAKE3 hash of ``data``."""
    chunks = [data[i:i + CHUNK_LEN] for i in range(0, len(data), CHUNK_LEN)] or [b""]
    if len(chunks) == 1:
        cv = _chunk(chunks[0], 0, root=True)
    else:
        # The reference's incremental tree: merge completed subtrees as the chunk count's binary
        # representation dictates, then fold the stack from the right, the last merge as root.
        stack: list[list[int]] = []
        for counter, chunk in enumerate(chunks[:-1]):
            cv = _chunk(chunk, counter, root=False)
            total = counter + 1
            while total & 1 == 0:
                cv = _parent(stack.pop(), cv, root=False)
                total >>= 1
            stack.append(cv)
        cv = _chunk(chunks[-1], len(chunks) - 1, root=False)
        while len(stack) > 1:
            cv = _parent(stack.pop(), cv, root=False)
        cv = _parent(stack.pop(), cv, root=True)
    return b"".join(w.to_bytes(4, "little") for w in cv)
