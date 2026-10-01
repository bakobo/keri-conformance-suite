"""Turn CESR scenario files into case files.

A scenario names its cases without their bytes. Each case gives an operation and either an
encoding request (`code`, `raw`, `domain`) or a stream, built from frames:

- ``{"genus": "AAA", "major": 2, "minor": 0}``: a genus/version code;
- ``{"group": "-J", "items": [...], "domain": "text"|"binary", "size": n}``: a count code and its
  group, with an optional size override for tampering; groups nest;
- ``{"primitive": "D", "raw": "<label>", "tamper": "pad"}``: a fixed-size primitive;
- ``{"variable": "B", "raw": "<label>", "length": n}``: a variable-size primitive;
- ``{"indexed": "A", "raw": "<label>", "index": i, "ondex": j}``: an indexed signature;
- ``{"literal": "-0AB"}``: text inserted as is, for codes the tables do not define;
- ``{"message": {...}}``: a JSON body framed by a version string;
- ``{"bare": {primitive}, "domain": "binary"}``: a primitive at top level with no count code.

A stream may also say ``"truncate": n`` to drop its last n bytes. Raw values are the first n
bytes of SHAKE-256 over the label, so every value is fixed by the scenario text.

The builder computes the expected items as it assembles the stream, and ``check_case`` then
parses the stream back with the reference parser and requires the two to agree.
"""

import hashlib
import json

from . import GENERATOR_NAME, GENERATOR_VERSION, b64, encoding, spec_source
from .decoding import Legacy, Parser, Rejected
from .tables import Tables

SCHEMA_VERSION = 1
LEVELS = ("MUST", "SHOULD", "MAY")


class ScenarioError(Exception):
    pass


def raw_bytes(label: str, size: int) -> bytes:
    return hashlib.shake_256(label.encode("utf-8")).digest(size)


# -- clauses ---------------------------------------------------------------------------------


def resolve_clauses(registry: dict, spec_text: str) -> dict:
    """Check every clause in the registry against the pinned text and return the case-file form
    of each, with its level. A quote must appear verbatim exactly once, under the heading the
    registry names, and must itself state the level the registry gives."""
    out = {}
    for key, c in sorted(registry.items()):
        if c["level"] not in LEVELS:
            raise ScenarioError(f"Clause {key!r} has level {c['level']!r}.")
        line = spec_source.find_quote(spec_text, c["quote"])
        heading = spec_source.section_of_line(spec_text, line)
        if heading.text != c["section"]:
            raise ScenarioError(
                f"Clause {key!r} quotes line {line}, which is under {heading.text!r}, "
                f"not {c['section']!r}."
            )
        if c["level"] not in c["quote"]:
            raise ScenarioError(f"Clause {key!r} is {c['level']} but its quote does not say so.")
        out[key] = (
            c["level"],
            {
                "spec": "cesr",
                "section": heading.text,
                "url": spec_source.file_url(heading.anchor),
                "commit": spec_source.SPEC_COMMIT,
                "quote": c["quote"],
            },
        )
    return out


# -- streams ---------------------------------------------------------------------------------


class StreamBuilder:
    def __init__(self, t: Tables, legacy: dict[str, Legacy] | None = None):
        self.t = t
        self.legacy = legacy
        self.features: set[str] = set()
        self.wire: set[str] = set()

    def _raw(self, node: dict, size: int) -> bytes:
        if "hex" in node:
            return bytes.fromhex(node["hex"])
        return raw_bytes(node["raw"], size)

    def _tamper(self, text: str, cs: int, how: str | None) -> str:
        if how is None:
            return text
        if how != "pad":
            raise ScenarioError(f"Unknown tamper {how!r}.")
        # The character after the code carries the pad bits (or the first lead bits) in its
        # most significant bit; setting it makes the padding nonzero without touching the raw.
        idx = b64.b64_to_int(text[cs]) | 32
        return text[:cs] + b64.ALPHABET[idx] + text[cs + 1:]

    def node(self, n: dict) -> tuple[str, list[dict]]:
        """Text of one element and its items, with offsets in characters from its start."""
        if "primitive" in n:
            code = n["primitive"]
            raw = self._raw(n, self.t.raw_size(code))
            text = encoding.primitive(self.t, code, raw)
            scheme = self.t.scheme_for_code(code)
            text = self._tamper(text, scheme.hs + scheme.ss, n.get("tamper"))
            return text, [{"kind": "primitive", "start": 0, "end": len(text), "code": code,
                           "raw": raw.hex()}]
        if "variable" in n:
            raw = self._raw(n, n["length"])
            hard, code_text = encoding.variable_code(self.t, n["variable"], len(raw))
            text = encoding.variable(self.t, n["variable"], raw)
            text = self._tamper(text, len(code_text), n.get("tamper"))
            return text, [{"kind": "primitive", "start": 0, "end": len(text), "code": hard,
                           "raw": raw.hex()}]
        if "indexed" in n:
            code = n["indexed"]
            entry = self.t.indexed[code]
            raw = self._raw(n, (entry.fs - entry.cs) * 3 // 4)
            text = encoding.indexed(self.t, code, raw, n["index"], n.get("ondex"))
            text = self._tamper(text, entry.cs, n.get("tamper"))
            item = {"kind": "indexed", "start": 0, "end": len(text), "code": code,
                    "index": n["index"], "raw": raw.hex()}
            if entry.os:
                item["ondex"] = n["ondex"]
            return text, [item]
        if "literal" in n:
            return n["literal"], []
        if "genus" in n:
            text = encoding.genus_version(n["genus"], n["major"], n["minor"])
            gvrsn = f"{n['major']}.{n['minor']:02d}"
            self.features.add(f"cesr.genus-{gvrsn}")
            self.wire.add(f"CESR-{gvrsn}")
            return text, [{"kind": "counter", "start": 0, "end": len(text), "code": "-_" + n["genus"],
                           "size": 0, "group_end": len(text), "genus": n["genus"], "gvrsn": gvrsn}]
        if "group" in n:
            return self.group(n)
        raise ScenarioError(f"Unknown stream element {sorted(n)}.")

    def group(self, n: dict) -> tuple[str, list[dict]]:
        code = n["group"]
        body, items, units = "", [], 0
        for child in n["items"]:
            text, child_items = self.node(child)
            for it in child_items:
                items.append(_shift(it, len(body)))
            if child_items:
                units += 1
            body += text
        if self.legacy is None:
            quadlets, natural = True, len(body) // 4
            self.features.add("cesr.genus-2.00")
            self.wire.add("CESR-2.00")
            head = encoding.counter(self.t, code, n.get("size", natural))
        else:
            entry = self.legacy[code]
            quadlets = entry.unit == "quadlets"
            natural = len(body) // 4 if quadlets else units // entry.per
            self.features.add("cesr.genus-1.00")
            self.wire.add("CESR-1.00")
            head = code + b64.int_to_b64(n.get("size", natural), entry.ss)
        size = n.get("size", natural)
        shift = len(head)
        end = shift + (size * 4 if quadlets else len(body))
        counter = {"kind": "counter", "start": 0, "end": shift, "code": code, "size": size,
                   "group_end": end}
        return head + body, [counter] + [_shift(it, shift) for it in items]

    def message(self, m: dict) -> tuple[bytes, dict]:
        fields = {"v": ""}
        fields.update(m["fields"])
        major, minor = m["version"]
        if m.get("legacy"):
            def vs(size):
                return f"{m['proto']}{major:x}{minor:x}JSON{size:06x}_"
            self.features.add("keri.version-1.x")
        else:
            gmajor, gminor = m["genus_version"]

            def vs(size):
                return (f"{m['proto']}{b64.int_to_b64(major, 1)}{b64.int_to_b64(minor, 2)}"
                        f"{b64.int_to_b64(gmajor, 1)}{b64.int_to_b64(gminor, 2)}JSON"
                        f"{b64.int_to_b64(size, 4)}.")
            self.features.add("keri.version-2.x")
        self.features.add("cesr.serialization.json")
        fields["v"] = vs(0)
        size = len(json.dumps(fields, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
        fields["v"] = vs(size)
        body = json.dumps(fields, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self.wire.add(_wire_of(fields["v"], bool(m.get("legacy"))))
        item = {"kind": "message", "start": 0, "end": len(body), "proto": m["proto"],
                "version": f"{major}.{minor}", "serialization": "JSON", "size": len(body)}
        return body, item

    def stream(self, frames: list[dict], truncate: int = 0) -> tuple[bytes, list[dict]]:
        out, items = b"", []
        for f in frames:
            if "message" in f:
                data, item = self.message(f["message"])
                found = [item]
            else:
                binary = f.get("domain", "text") == "binary"
                text, found = self.node(f.get("bare", f))
                if binary:
                    self.features.add("cesr.domain.binary")
                    data = encoding.to_binary(text)
                    found = [_scale(it) for it in found]
                else:
                    data = text.encode("ascii")
            items.extend(_shift(it, len(out)) for it in found)
            out += data
        if truncate:
            out = out[:-truncate]
        return out, items


OFFSETS = ("start", "end", "group_end")


def _shift(item: dict, by: int) -> dict:
    return {k: v + by if k in OFFSETS else v for k, v in item.items()}


def _scale(item: dict) -> dict:
    """Character offsets in a text-domain rendering to byte offsets in the binary domain."""
    return {k: v * 3 // 4 if k in OFFSETS else v for k, v in item.items()}


def _wire_of(version_string: str, legacy: bool) -> str:
    """The wire identifier of a message: its version string up to and including the
    serialization kind, e.g. ``KERI10JSON`` or ``KERICAACAAJSON``."""
    return version_string[:10] if legacy else version_string[:14]


# -- cases -----------------------------------------------------------------------------------


def build_case(t: Tables, scenario_path: str, case: dict, clauses: dict,
               legacy: dict[str, Legacy] | None, reference: dict | None) -> dict:
    sb = StreamBuilder(t, legacy)
    op = case["operation"]
    if op == "cesr.encode":
        code, domain = case["code"], case["domain"]
        raw = bytes.fromhex(case["hex"]) if "hex" in case else raw_bytes(case["raw"], t.raw_size(code))
        text = encoding.primitive(t, code, raw)
        encoded = text.encode("ascii") if domain == "text" else encoding.to_binary(text)
        if domain == "binary":
            sb.features.add("cesr.domain.binary")
        sb.features.add("cesr.genus-2.00")
        sb.wire.add("CESR-2.00")
        inp = {"code": code, "raw": raw.hex(), "domain": domain}
        expected = {"encoded": encoded.hex()}
    elif op == "cesr.parse":
        stream, items = sb.stream(case["stream"], case.get("truncate", 0))
        inp = {"stream": stream.hex()}
        expected = {"decoded": items}
    else:
        raise ScenarioError(f"Unsupported operation {op!r}.")

    assertions = []
    for n, a in enumerate(case["assertions"], start=1):
        out = {"id": f"a{n}", "check": a["check"]}
        if "clause" in a:
            level, clause = clauses[a["clause"]]
            out["level"] = level
            out["clause"] = clause
        else:
            out["level"] = "INTEROP"
            out["basis"] = a["basis"]
        if a["check"] in expected:
            out["expected"] = expected[a["check"]]
        elif a["check"] != "rejected":
            raise ScenarioError(f"{case['id']}: check {a['check']!r} does not fit {op}.")
        if "note" in a:
            out["note"] = a["note"]
        assertions.append(out)

    result = {
        "schema_version": SCHEMA_VERSION,
        "id": case["id"],
        "title": case["title"],
        "description": case["description"],
        "status": case.get("status", "active"),
        "profile": case["profile"],
        "targets": {"wire": sorted(sb.wire), "features": sorted(sb.features)},
        "operation": op,
        "input": inp,
        "assertions": assertions,
        "provenance": {
            "scenario": f"{scenario_path}#{case['key']}",
            "generator": {"name": GENERATOR_NAME, "version": GENERATOR_VERSION},
            "reference": reference,
        },
    }
    if "dispute" in case:
        d = case["dispute"]
        result["dispute"] = {
            "clauses": [clauses[k][1] for k in d["clauses"]],
            "summary": d["summary"],
            "raised_at": d["raised_at"],
        }
    check_case(t, result, legacy)
    return result


def check_case(t: Tables, case: dict, legacy: dict[str, Legacy] | None) -> None:
    """Parse a built parse case back from its bytes and require agreement with its assertions."""
    if case["operation"] != "cesr.parse":
        return
    stream = bytes.fromhex(case["input"]["stream"])
    try:
        got = Parser(t, legacy).parse(stream)
        outcome = ("decoded", got)
    except Rejected as e:
        outcome = ("rejected", e.cls)
    for a in case["assertions"]:
        if a["check"] == "rejected" and outcome[0] != "rejected":
            raise ScenarioError(f"{case['id']}: expected a rejection, but the stream parses.")
        if a["check"] == "decoded" and outcome != ("decoded", a["expected"]):
            raise ScenarioError(
                f"{case['id']}: the reference parser disagrees with the builder: {outcome}"
            )
