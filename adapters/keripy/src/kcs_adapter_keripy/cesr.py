"""cesr.parse and cesr.encode.

parse hands the stream to keripy's own Parser.msgParsator and reports what keripy consumed, as
measure.py measures it. encode is keripy's Matter.
"""

import sys

from kcs_adapter_keripy import keripy_api, measure
from kcs_adapter_keripy.errors import Rejection, Unsupported, keri

__all__ = ["Unsupported", "encode", "parse"]

E_ENCODE_REFUSED = "e.input.format.encode-refused.f"

_API = None


def api():
    global _API
    if _API is None:
        _API = keripy_api.load()
    return _API


def parse(stream: bytes) -> dict:
    """The cesr.parse result for these bytes: decoded items, or keripy's rejection."""
    try:
        # A fresh keripy Parser for every request: nothing carries over from an earlier
        # request, including the code-table version a genus code selected.
        return {"items": measure.parse(keripy_api.load(), stream)}
    except Rejection as rejection:
        print(f"keripy rejected the stream: {rejection.klass}: {rejection}", file=sys.stderr)
        return {"reject": {"class": rejection.klass}}


def encode(code: str, raw_hex: str, domain: str) -> dict:
    """The cesr.encode result: keripy's Matter encoding of raw under code, as hex."""
    matter_class = api().Matter
    try:
        matter = keri(matter_class, raw=bytes.fromhex(raw_hex), code=code)
        encoded = keri(lambda: matter.qb64b if domain == "text" else matter.qb2)
    except Rejection as rejection:
        raise Unsupported(f"{E_ENCODE_REFUSED}: keripy raised {rejection.klass} encoding raw "
                          f"bytes under code {code!r}: {rejection}") from rejection
    return {"encoded": bytes(encoded).hex()}
