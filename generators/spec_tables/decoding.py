"""A reference parser over the spec tables, used to check the generator against itself.

The builder computes each case's expected items while it assembles the stream. This parser reads
the assembled stream back from nothing but its bytes and the tables, and ``scripts/regenerate``
refuses to write a case unless the two agree: a positive case must parse to exactly its expected
items, and a must-reject case must be rejected. It is not an implementation under test and makes
no claim beyond the cases the scenarios describe; in particular it does not strip annotations and
does not frame CBOR or MessagePack bodies.

Rejection classes are informative, as in the design: ``truncated``, ``count-overrun``,
``group-boundary``, ``unknown-code``, ``nonzero-pad``, ``bad-frame-start``, ``malformed-message``
and ``unsupported``.
"""

import json
import re
from dataclasses import dataclass

from . import b64
from .tables import Tables

VERSION_2 = re.compile(
    rb'^\{"v":"([A-Z]{4})([A-Za-z0-9_-])([A-Za-z0-9_-]{2})([A-Za-z0-9_-]{3})'
    rb"(JSON|CBOR|MGPK|CESR)([A-Za-z0-9_-]{4})\."
)
VERSION_1 = re.compile(rb'^\{"v":"([A-Z]{4})([0-9a-f])([0-9a-f])(JSON|CBOR|MGPK|CESR)([0-9a-f]{6})_"')


class Rejected(Exception):
    def __init__(self, cls: str, message: str):
        super().__init__(f"{cls}: {message}")
        self.cls = cls


@dataclass(frozen=True)
class Legacy:
    """A count-code table that is not genus 2.00: for each code, what its size counts. ``unit``
    is ``"quadlets"``, or the kind of item counted (``"indexed"`` or ``"primitive"``) with
    ``per`` items per counted unit."""

    hs: int
    ss: int
    unit: str
    per: int = 1


OVERRIDEABLE = ("A", "B", "C")  # -A/-B/-C and their large forms: universal, allow override


class Parser:
    def __init__(self, t: Tables, legacy: dict[str, Legacy] | None = None,
                 one_x: dict[str, Legacy] | None = None):
        self.t = t
        self.legacy = legacy  # when set, count codes are read from this table, not genus 2.00
        self.one_x = one_x  # the table a genus/version code selecting 1.00 switches to, if any
        self.genus_seen = legacy is not None

    # -- element text ------------------------------------------------------------------------

    def _text(self, s: bytes, i: int, n_chars: int, binary: bool, limit: int) -> str:
        """``n_chars`` characters of element text starting at offset ``i``."""
        n = n_chars * 3 // 4 if binary else n_chars
        if i + n > len(s):
            raise Rejected("truncated", f"the stream ends inside an element at offset {i}.")
        if i + n > limit:
            raise Rejected("group-boundary", f"an element at offset {i} crosses its group's end.")
        chunk = s[i:i + n]
        if binary:
            return b64.encode(chunk)
        try:
            text = chunk.decode("ascii")
            b64.b64_to_int(text)
        except (UnicodeDecodeError, ValueError):
            raise Rejected("bad-frame-start", f"non-Base64 text at offset {i}.") from None
        return text

    def _width(self, n_chars: int, binary: bool) -> int:
        return n_chars * 3 // 4 if binary else n_chars

    # -- counters ----------------------------------------------------------------------------

    def _counter_scheme(self, s, i, binary, limit):
        head = self._text(s, i, 4, binary, limit)
        if head[0] != "-":
            raise Rejected("bad-frame-start", f"expected a count code at offset {i}.")
        if head.startswith("-_"):
            scheme = self.t.count_scheme("-_")
            return None, scheme.hs, scheme.ss, None
        if self.legacy is not None:
            for hard, entry in self.legacy.items():
                if head.startswith(hard):
                    return hard, entry.hs, entry.ss, entry
            raise Rejected("unknown-code", f"unknown count code {head!r} at offset {i}.")
        second = head[1]
        if second.isdigit():
            raise Rejected("unknown-code", f"count code {head!r} selects no defined table.")
        hs = self.t.count_scheme(head).hs
        ss = self.t.count_scheme(head).ss
        return None, hs, ss, None

    def counter(self, s: bytes, i: int, binary: bool, limit: int, top: bool):
        hard, hs, ss, entry = self._counter_scheme(s, i, binary, limit)
        text = self._text(s, i, hs + ss, binary, limit)
        hard = text[:hs]
        start, after = i, i + self._width(hs + ss, binary)
        if hard.startswith("-_"):
            if not top:
                raise Rejected("unsupported", "a genus/version code where it carries no override.")
            return [self.genus(text, start, after)], after
        if not self.genus_seen:
            raise Rejected("unsupported", "a count code before any genus/version code.")
        if entry is None and hard not in self.t.count_codes:
            raise Rejected("unknown-code", f"{hard!r} is not a genus 2.00 count code.")
        size = b64.b64_to_int(text[hs:])
        item = {"kind": "counter", "start": start, "end": after, "code": hard, "size": size}
        if entry is None or entry.unit == "quadlets":
            end = after + size * (3 if binary else 4)
            if end > len(s):
                raise Rejected("count-overrun", f"{hard} counts past the end of the stream.")
            if end > limit:
                raise Rejected("group-boundary", f"{hard} counts past its enclosing group.")
            item["group_end"] = end
            items, pos = self._group_contents(s, after, end, binary, hard)
            return [item, *items], end
        items: list[dict] = []
        pos = after
        for _ in range(size * entry.per):
            if pos >= len(s):
                raise Rejected("count-overrun", f"{hard} counts past the end of the stream.")
            one, pos = (self.indexed if entry.unit == "indexed" else self.primitive)(s, pos, binary, limit)
            items.append(one)
        item["group_end"] = pos
        return [item, *items], pos

    def genus(self, text: str, start: int, after: int) -> dict:
        """Switch the count-code table to the one a genus/version code selects."""
        genus, major, minor = text[2:5], b64.b64_to_int(text[5]), b64.b64_to_int(text[6:8])
        if (genus, major, minor) == ("AAA", 2, 0):
            self.legacy = None
        elif (genus, major, minor) == ("AAA", 1, 0) and self.one_x is not None:
            self.legacy = self.one_x
        else:
            raise Rejected("unsupported", f"genus/version {text!r} is not a supported table.")
        self.genus_seen = True
        return {"kind": "genus", "start": start, "end": after, "code": text, "genus": genus,
                "version": f"{major}.{minor:02d}"}

    def _group_contents(self, s, i, end, binary, hard):
        items = []
        bare = hard.lstrip("-")
        outer = self.legacy
        overrideable = bare in OVERRIDEABLE and outer is None
        first = True
        while i < end:
            if (first and overrideable and self._starts_counter(s, i, binary)
                    and self._text(s, i, 4, binary, end).startswith("-_")):
                head = self._text(s, i, 8, binary, end)
                after = i + self._width(8, binary)
                items.append(self.genus(head, i, after))
                i, first = after, False
                continue
            first = False
            if bare in OVERRIDEABLE and self.legacy is None:
                got, i = self.frame(s, i, end, top=False)
            elif bare in ("K", "L") and self.legacy is None:
                got, i = self.indexed(s, i, binary, end)
                got = [got]
            elif self._starts_counter(s, i, binary):
                got, i = self.counter(s, i, binary, end, top=False)
            else:
                got, i = self.primitive(s, i, binary, end)
                got = [got]
            items.extend(got)
        self.legacy = outer  # an override ends with its group
        return items, i

    def _starts_counter(self, s, i, binary):
        return s[i] >= 0xF8 if binary else s[i:i + 1] == b"-"

    # -- primitives --------------------------------------------------------------------------

    def _unpad(self, text: str, cs: int, fs: int, ls: int, i: int) -> bytes:
        ps = cs % 4
        decoded = b64.decode("A" * ps + text[cs:fs])
        if any(decoded[: ps + ls]):
            raise Rejected("nonzero-pad", f"nonzero pad bits or lead bytes at offset {i}.")
        return decoded[ps + ls:]

    def primitive(self, s, i, binary, limit):
        head = self._text(s, i, 1, binary, limit) if not binary else self._text(s, i, 4, binary, limit)
        try:
            scheme = self.t.scheme_for_code(head[0])
        except KeyError:
            raise Rejected("unknown-code", f"no primitive table for {head[0]!r} at {i}.") from None
        text = self._text(s, i, max(4, scheme.hs + scheme.ss), binary, limit)
        hard = text[: scheme.hs]
        prim = self.t.primitives.get(hard)
        if prim is None:
            raise Rejected("unknown-code", f"{hard!r} is not a genus 2.00 primitive code.")
        cs = scheme.hs + scheme.ss
        fs = prim.fs if prim.fs is not None else cs + 4 * b64.b64_to_int(text[scheme.hs:cs])
        text = self._text(s, i, fs, binary, limit)
        raw = self._unpad(text, cs, fs, scheme.ls, i)
        end = i + self._width(fs, binary)
        return {"kind": "primitive", "start": i, "end": end, "code": hard, "raw": raw.hex()}, end

    def indexed(self, s, i, binary, limit):
        head = self._text(s, i, 4, binary, limit)
        entry = self.t.indexed.get(head[0]) or self.t.indexed.get(head[:2])
        if entry is None:
            raise Rejected("unknown-code", f"{head!r} is not a genus 2.00 indexed code at {i}.")
        text = self._text(s, i, entry.fs, binary, limit)
        hs = len(entry.code)
        item = {"kind": "indexed", "start": i, "code": entry.code,
                "index": b64.b64_to_int(text[hs:hs + entry.ms])}
        if entry.os:
            item["ondex"] = b64.b64_to_int(text[hs + entry.ms:entry.cs])
        item["raw"] = self._unpad(text, entry.cs, entry.fs, 0, i).hex()
        end = i + self._width(entry.fs, binary)
        item["end"] = end
        return item, end

    # -- frames ------------------------------------------------------------------------------

    def message(self, s, i, limit):
        head = s[i:i + 64]
        m2, m1 = VERSION_2.match(head), VERSION_1.match(head)
        if m2:
            proto, major, minor, kind = m2.group(1), m2.group(2), m2.group(3), m2.group(5)
            version = f"{b64.b64_to_int(major.decode())}.{b64.b64_to_int(minor.decode())}"
            size = b64.b64_to_int(m2.group(6).decode())
        elif m1:
            proto, kind = m1.group(1), m1.group(4)
            version = f"{int(m1.group(2), 16)}.{int(m1.group(3), 16)}"
            size = int(m1.group(5), 16)
        else:
            raise Rejected("malformed-message", f"no version string at offset {i}.")
        if kind != b"JSON":
            raise Rejected("unsupported", f"{kind.decode()} bodies are not framed here.")
        end = i + size
        if end > len(s):
            raise Rejected("truncated", f"the message at {i} declares {size} bytes.")
        if end > limit:
            raise Rejected("group-boundary", f"the message at {i} crosses its group's end.")
        try:
            json.loads(s[i:end])
        except ValueError:
            raise Rejected("malformed-message", f"the body at {i} is not JSON.") from None
        item = {"kind": "message", "start": i, "end": end, "proto": proto.decode(),
                "version": version, "serialization": "JSON", "size": size}
        return [item], end

    def frame(self, s, i, limit, top):
        tritet = s[i] >> 5
        if tritet == 0b011:
            return self.message(s, i, limit)
        if tritet == 0b001:
            return self.counter(s, i, False, limit, top)
        if tritet == 0b111:
            if s[i] >> 2 != 62:
                raise Rejected("unsupported", f"a binary op code at offset {i}.")
            return self.counter(s, i, True, limit, top)
        raise Rejected("bad-frame-start", f"byte {s[i]:#04x} at offset {i} starts no frame.")

    def parse(self, s: bytes) -> list[dict]:
        items, i = [], 0
        while i < len(s):
            got, i = self.frame(s, i, len(s), top=True)
            items.extend(got)
        return items
