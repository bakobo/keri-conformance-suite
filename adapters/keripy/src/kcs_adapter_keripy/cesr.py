"""cesr.parse and cesr.encode.

parse walks the stream frame by frame. At each top-level frame keripy's sniff says what starts
there: a version-string body (framed by keripy's smell) or a count code (extracted by keripy's
Counter through keripy's Parser._extractor). Inside a group, each item is extracted by its keripy
class from a copy of the stream that ends where the group ends, so an item can never be reported
past its group's end; its end offset is how many bytes keripy stripped. Where a group ends comes
from keripy as keripy_api describes. Nothing is reported that keripy did not produce.
"""

import sys

from kcs_adapter_keripy import keripy_api
from kcs_adapter_keripy.errors import Rejection, Unsupported, keri

__all__ = ["Unsupported", "encode", "parse"]

E_ENCODE_REFUSED = "e.encode.refused.p"

_API = None


def api():
    global _API
    if _API is None:
        _API = keripy_api.load()
    return _API


class Walk:
    """One cesr.parse request: the stream, the items found so far, and the code table in force."""

    def __init__(self, keripy, stream: bytes):
        self.keripy = keripy
        self.stream = stream
        self.items = []
        self.version = keripy.default_version()

    def run(self):
        pos = 0
        while pos < len(self.stream):
            cold = self.keripy.sniff(bytearray(self.stream[pos:]))
            if cold == "msg":
                pos = self.message(pos)
            else:
                pos = self.counter(pos, len(self.stream), cold)
        return self.items

    def message(self, pos):
        proto, pvrsn, kind, size = self.keripy.smell(bytearray(self.stream[pos:]))
        if size > len(self.stream) - pos:
            raise self.keripy.shortage(f"The body at {pos} declares {size} bytes but only "
                                       f"{len(self.stream) - pos} remain.")
        self.items.append({"kind": "message", "start": pos, "end": pos + size, "proto": proto,
                           "version": f"{pvrsn.major}.{pvrsn.minor}", "serialization": kind,
                           "size": size})
        return pos + size

    def extract(self, pos, limit, klas, cold):
        buf = bytearray(self.stream[pos:limit])
        before = len(buf)
        instance = self.keripy.extract(buf, klas, cold, self.version)
        return instance, pos + before - len(buf)

    def counter(self, pos, limit, cold):
        """Extract the counter at pos and everything its group holds; return the group's end."""
        ctr, end = self.extract(pos, limit, self.keripy.Counter, cold)
        item = {"kind": "counter", "start": pos, "end": end, "code": ctr.code}
        self.items.append(item)
        if self.keripy.is_genus_version(ctr):
            genus, gvrsn = self.keripy.genus_version(ctr)
            item.update(size=0, group_end=end, genus=genus, gvrsn=gvrsn)
            self.version = self.keripy.after_genus_version(self.version, ctr)
            return end
        item["size"] = ctr.count
        outer = self.version
        group_end = self.keripy.group(self, ctr, end, limit, cold)
        self.version = outer  # a genus counter inside a group does not outlive the group
        self.keripy.set_version(outer)
        item["group_end"] = group_end
        return group_end

    def item(self, pos, limit, klas, cold):
        """Extract one primitive or indexed signature of class klas; return its end."""
        instance, end = self.extract(pos, limit, klas, cold)
        entry = {"kind": "primitive", "start": pos, "end": end, "code": instance.code,
                 "raw": bytes(instance.raw).hex()}
        if isinstance(instance, self.keripy.Indexer):
            entry["kind"] = "indexed"
            entry["index"] = instance.index
            ondex = self.keripy.ondex_field(instance)
            if ondex is not None:
                entry["ondex"] = ondex
        self.items.append(entry)
        return end

    def contents(self, start, group_end, cold, indexed):
        """Walk a group's contents item by item. An item is a nested group if its first code
        character is '-' (keripy's own test, keri.core.mapping); otherwise an indexed signature
        when the group holds signatures, else a primitive."""
        klas = self.keripy.Siger if indexed else self.keripy.Matter
        pos = start
        while pos < group_end:
            if self.keripy.first_code_char(self.stream[pos:group_end], cold) == "-":
                pos = self.counter(pos, group_end, cold)
            else:
                pos = self.item(pos, group_end, klas, cold)


def parse(stream: bytes) -> dict:
    """The cesr.parse result for these bytes: decoded items, or keripy's rejection."""
    try:
        # A fresh keripy API object (and so a fresh keripy Parser) for every request: nothing
        # carries over from an earlier request, including the code-table version.
        return {"items": Walk(keripy_api.load(), stream).run()}
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
