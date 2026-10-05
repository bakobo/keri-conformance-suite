"""Ed25519 signing and verification in pure Python, following RFC 8032, section 5.1.

The KERI cases carry real signatures, and the generators may use only the standard library, which
has no Ed25519. Signing is deterministic, so every signature is fixed by its seed and message.
This is a generator's tool, never a production signer: it makes no attempt at constant time.
The implementation is the RFC's own (sections 5.1.2 to 5.1.7, in extended coordinates) and is
checked against the RFC's test vectors.
"""

import hashlib

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493  # the group order
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _point_add(a, b):
    """Addition in extended homogeneous coordinates (RFC 8032, 5.1.4)."""
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    aa = (y1 - x1) * (y2 - x2) % P
    bb = (y1 + x1) * (y2 + x2) % P
    cc = 2 * t1 * t2 * D % P
    dd = 2 * z1 * z2 % P
    e, f, g, h = bb - aa, dd - cc, dd + cc, bb + aa
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _scalar_mult(s, point):
    q = (0, 1, 1, 0)  # the neutral element
    while s > 0:
        if s & 1:
            q = _point_add(q, point)
        point = _point_add(point, point)
        s >>= 1
    return q


def _recover_x(y, sign):
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


G_Y = 4 * pow(5, P - 2, P) % P
G_X = _recover_x(G_Y, 0)
G = (G_X, G_Y, 1, G_X * G_Y % P)


def _encode_point(point) -> bytes:
    x, y, z, _ = point
    zinv = pow(z, P - 2, P)
    x, y = x * zinv % P, y * zinv % P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decode_point(data: bytes):
    """The point a 32-byte encoding names, or None if it names none."""
    y = int.from_bytes(data, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


def _points_equal(a, b) -> bool:
    x1, y1, z1, _ = a
    x2, y2, z2, _ = b
    return (x1 * z2 - x2 * z1) % P == 0 and (y1 * z2 - y2 * z1) % P == 0


def _sha512_int(data: bytes) -> int:
    return int.from_bytes(hashlib.sha512(data).digest(), "little")


def _expand(seed: bytes) -> tuple[int, bytes]:
    if len(seed) != 32:
        raise ValueError(f"An Ed25519 seed is 32 bytes, not {len(seed)}.")
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


def public_key(seed: bytes) -> bytes:
    a, _ = _expand(seed)
    return _encode_point(_scalar_mult(a, G))


def sign(seed: bytes, message: bytes) -> bytes:
    a, prefix = _expand(seed)
    public = _encode_point(_scalar_mult(a, G))
    r = _sha512_int(prefix + message) % L
    rs = _encode_point(_scalar_mult(r, G))
    k = _sha512_int(rs + public + message) % L
    s = (r + k * a) % L
    return rs + int.to_bytes(s, 32, "little")


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    """Whether ``signature`` is a valid signature of ``message`` by ``public``. Malformed keys
    and signatures are simply invalid; this never raises for them."""
    if len(public) != 32 or len(signature) != 64:
        return False
    a = _decode_point(public)
    if a is None:
        return False
    r = _decode_point(signature[:32])
    if r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False
    k = _sha512_int(signature[:32] + public + message) % L
    return _points_equal(_scalar_mult(s, G), _point_add(r, _scalar_mult(k, a)))
