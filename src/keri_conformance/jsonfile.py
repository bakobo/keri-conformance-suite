"""Reading a JSON file the runner depends on: size first, then parsing, never unbounded.

Callers map a `JsonFileError` to their own error code by its `kind` (missing, io, size or parse);
`transient` says whether an I/O failure is one that retrying could clear.
"""

import errno
import json
import math
from decimal import Decimal
from pathlib import Path

TRANSIENT_ERRNOS = frozenset({errno.EIO, errno.EAGAIN, errno.EINTR, errno.EBUSY, errno.ENFILE,
                              errno.EMFILE, errno.ETIMEDOUT, errno.ESTALE})


def _refuse_constant(name: str):
    raise ValueError(f"{name} is not a JSON number")


def _number(text: str):
    # Range is judged as a float, so huge exponents are refused before anything is expanded;
    # integrality is judged on the exact decimal text, so 9007199254740993.0 stays exact.
    value = float(text)
    if not math.isfinite(value):
        raise ValueError(f"the number {text} is out of range")
    exact = Decimal(text)
    return int(exact) if exact == exact.to_integral_value() else value


def loads(text: str | bytes):
    """Decode JSON as the suite's schemas read it, for files and protocol lines alike: NaN,
    Infinity and -Infinity (which Python's json accepts but JSON does not) and numbers too large
    for a float are refused with ValueError, and an integral number such as 1.0 or 4e0 becomes
    an int, because JSON Schema's "integer" type admits it. Integrality is decided on the exact
    decimal text, so a large integral number keeps every digit."""
    return json.loads(text, parse_constant=_refuse_constant, parse_float=_number)


class JsonFileError(Exception):
    """`sentence` completes "The file <path> ..."; `kind` and `transient` classify it."""

    def __init__(self, sentence: str, kind: str, transient: bool = False):
        super().__init__(sentence)
        self.sentence = sentence
        self.kind = kind
        self.transient = transient


def read_json(path: Path, max_bytes: int):
    """Parse the JSON in `path`, refusing to read more than `max_bytes`."""
    try:
        with path.open("rb") as f:
            data = f.read(max_bytes + 1)
    except OSError as exc:
        kind = "missing" if isinstance(exc, FileNotFoundError) else "io"
        raise JsonFileError(f"could not be read: {exc.strerror or exc}", kind,
                            exc.errno in TRANSIENT_ERRNOS) from exc
    if len(data) > max_bytes:
        raise JsonFileError(f"is larger than the {max_bytes} bytes the runner will read", "size")
    try:
        return loads(data.decode("utf-8"))
    except (ValueError, RecursionError) as exc:
        raise JsonFileError(f"is not UTF-8 JSON, or is nested too deeply: {exc}", "parse") from exc
