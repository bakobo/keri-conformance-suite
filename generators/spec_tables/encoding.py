"""Encoding into the CESR text domain, and conversion from text to binary.

The rule, from "Text Code Size" and "Code characters and lead bytes": prepend the code's lead
bytes and then `ps` zero pad bytes to the raw value, where ``ps = (3 - (N mod 3)) mod 3`` for the
padded length N; convert to Base64; replace the first `ps` characters, which carry only zero bits,
with the text code, whose length must therefore be congruent to `ps` modulo 4. A code with no pad
characters to replace is a whole number of quadlets and is simply prepended. The binary domain is
the naive Base64 decoding of the text domain.
"""

from . import b64
from .tables import Tables


def _assemble(code_text: str, raw: bytes, ls: int) -> str:
    ps = (3 - ((len(raw) + ls) % 3)) % 3
    if len(code_text) % 4 != ps:
        raise ValueError(
            f"A code of {len(code_text)} characters cannot carry {len(raw)} raw bytes with "
            f"{ls} lead bytes: the pad size is {ps}."
        )
    return code_text + b64.encode(bytes(ps + ls) + raw)[ps:]


def primitive(t: Tables, code: str, raw: bytes) -> str:
    """A fixed-size primitive from the master table."""
    if code not in t.primitives:
        raise KeyError(f"The code {code!r} is not in the master table for genus 2.00.")
    if t.primitives[code].fs is None:
        raise ValueError(f"The code {code!r} is variable-size; use variable().")
    rs = t.raw_size(code)
    if len(raw) != rs:
        raise ValueError(f"The code {code!r} has raw size {rs}, not {len(raw)}.")
    return _assemble(code, raw, t.scheme_for_code(code).ls)


def variable_code(t: Tables, type_char: str, size_raw: int) -> tuple[str, str]:
    """The (hard code, full text code) of the variable-size code of ``type_char`` for a raw
    value of ``size_raw`` bytes: the small table if the size in triplets fits two digits, the
    large table otherwise, with the selector giving the lead size."""
    ls = (3 - size_raw % 3) % 3
    size = (size_raw + ls) // 3
    if size < 64**2:
        hard, digits = f"{4 + ls}{type_char}", 2
    else:
        hard, digits = f"{7 + ls}AA{type_char}", 4
    if hard not in t.primitives:
        raise KeyError(f"The type {type_char!r} has no variable-size code {hard!r}.")
    return hard, hard + b64.int_to_b64(size, digits)


def variable(t: Tables, type_char: str, raw: bytes) -> str:
    hard, code_text = variable_code(t, type_char, len(raw))
    return _assemble(code_text, raw, t.scheme_for_code(hard).ls)


def counter(t: Tables, code: str, size: int) -> str:
    if code not in t.count_codes:
        raise KeyError(f"The code {code!r} is not a genus 2.00 count code.")
    return code + b64.int_to_b64(size, t.count_scheme(code).ss)


def genus_version(genus: str, major: int, minor: int) -> str:
    """`-_GGGVVV`: genus in three characters, then the major version in one base 64 digit and
    the minor version in two."""
    return "-_" + genus + b64.int_to_b64(major, 1) + b64.int_to_b64(minor, 2)


def indexed(t: Tables, code: str, raw: bytes, index: int, ondex: int | None = None) -> str:
    if code not in t.indexed:
        raise KeyError(f"The code {code!r} is not in the indexed code table for genus 2.00.")
    entry = t.indexed[code]
    if entry.os == 0 and ondex is not None:
        raise ValueError(f"The indexed code {code!r} has no ondex field.")
    if entry.os and ondex is None:
        raise ValueError(f"The indexed code {code!r} needs an ondex.")
    rs = (entry.fs - entry.cs) * 3 // 4
    if len(raw) != rs:
        raise ValueError(f"The indexed code {code!r} has raw size {rs}, not {len(raw)}.")
    code_text = code + b64.int_to_b64(index, entry.ms)
    if entry.os:
        code_text += b64.int_to_b64(ondex, entry.os)
    return _assemble(code_text, raw, 0)


def to_binary(text: str) -> bytes:
    return b64.decode(text)
