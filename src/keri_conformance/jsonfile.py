"""Reading a JSON file the runner depends on: size first, then parsing, never unbounded.

Callers map a `JsonFileError` to their own error code by its `kind` (missing, io, size or parse);
`transient` says whether an I/O failure is one that retrying could clear.
"""

import errno
import json
from pathlib import Path

TRANSIENT_ERRNOS = frozenset({errno.EIO, errno.EAGAIN, errno.EINTR, errno.EBUSY, errno.ENFILE,
                              errno.EMFILE, errno.ETIMEDOUT, errno.ESTALE})


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
        return json.loads(data.decode("utf-8"))
    except (ValueError, RecursionError) as exc:
        raise JsonFileError(f"is not UTF-8 JSON, or is nested too deeply: {exc}", "parse") from exc
