"""SAIDs for ACDCs, computed from the ACDC specification v1.0 (``spec_source.ACDC``) and the CESR
code tables, with the generator's own BLAKE3.

- **The SAID protocol** (CESR line 1194): the SAID field of a field map holds 44 ``#`` while the
  Blake3-256 digest of its serialization is taken, and the digest's qualified text (code ``E``)
  then replaces it. A top-level map with a version string first gets ``v`` sized to its own
  serialization (ACDC line 62).
- **The most compact form** (lines 134 to 147): a block whose ``d`` is a string is a SAIDed block.
  Its SAID is taken over its block-level expanded form, in which every SAIDed subblock, at any
  depth below maps that are not SAIDed, is replaced by its own SAID, computed the same way, and
  every other field stays expanded. A list is not a block, so by default it is left as it is. At the top level, a schema section given as a map compacts to
  its ``$id`` SAID without entering it (a schema is a SAD of its own, and its property maps may
  have ``d`` keys), and an aggregate section ``A`` given as a list compacts to its AGID.
- **The aggregate** (lines 714 and 720, with the worked example at lines 951 to 956): the AGID is
  the digest of the list of the blinded attribute blocks' SAIDs with a dummied first entry,
  serialized as the enclosing ACDC is.
- **The BLID** (lines 2058, 2066, 2141, worked examples at 2160 to 2231 and 2347): the digest of
  the text-domain concatenation of the dummied BLID and the qualified ``u``, ``td`` and ``ts``.

The text leaves some bytes open (generators/SPEC-ISSUES.md). Each choice is a field of
``Readings``, whose defaults are the readings docs/design.md fixes ("Construction properties"),
so that the keripy cross-check can show which choice explains any disagreement:

- ``compact_v`` (A-B1): the most compact form's version string gives the compact serialization's
  own size (``own``), or keeps the size of the form presented (``presented``);
- ``ascii`` (A-B1): JSON with non-ASCII characters unescaped (``False``) or escaped;
- ``schema`` (A-B2): a schema's SAID is over its compact re-serialization (``compact``) or over
  the bytes received (``received``);
- ``ts_code`` (A-B3): a state value is a Tag primitive (``tag``), a Base64 string (``strb64``)
  or a byte string (``bytes``);
- ``aggregate`` (A-C1): the AGID's pre-image is the serialized list (``list``) or the bare
  concatenation of the SAIDs that line 110 describes (``concat``);
- ``lists``: a SAIDed block inside a list (other than an aggregate) is left expanded
  (``opaque``), as lines 140 to 147, which speak only of fields whose values are blocks, read
  literally, or compacted like a field's block (``traverse``). The design names no reading for
  this; no first-batch scenario puts a block in a list.
"""

import json
import math
from dataclasses import dataclass

from . import b64, blake3, encoding
from .errors import ScenarioError
from .tables import Tables

PROTOCOL = (2, 0)
GENUS = (2, 0)
KIND = "JSON"
DUMMY = "#" * 44
EMPTY = "1AAP"  # the Empty primitive, line 2087

# A reading of unpinned bytes that is not one of the candidates, or that cannot be applied.
E_READING = "e.input.format.kcs-acdc-reading.f"
# A transaction SAID or state value the blinded state block cannot carry.
E_STATE = "e.input.format.kcs-acdc-state.f"

CANDIDATES = {
    "compact_v": ("own", "presented"),
    "ascii": (False, True),
    "schema": ("compact", "received"),
    "ts_code": ("tag", "strb64", "bytes"),
    "aggregate": ("list", "concat"),
    "lists": ("opaque", "traverse"),
}

# Tag codes by the number of characters they carry (CESR master table). Tags of 1, 5 and 9
# characters carry a pre-pad character the CESR text does not name, so they are refused.
TAGS = {2: "0K", 3: "X", 4: "1AAF", 6: "0M", 7: "Y", 8: "1AAN", 10: "0O", 11: "Z"}
PREPADDED_TAGS = {1: "0J", 5: "0L", 9: "0N"}


@dataclass(frozen=True)
class Readings:
    compact_v: str = "own"
    ascii: bool = False
    schema: str = "compact"
    ts_code: str = "tag"
    aggregate: str = "list"
    lists: str = "opaque"

    def __post_init__(self):
        for name, allowed in CANDIDATES.items():
            value = getattr(self, name)
            if not any(value is a if isinstance(a, bool) else value == a for a in allowed):
                raise ScenarioError(f"{value!r} is not a candidate reading of {name}; the "
                                    f"candidates are {allowed}.", E_READING)


DEFAULT = Readings()


def version_string(size: int) -> str:
    return (f"ACDC{b64.int_to_b64(PROTOCOL[0], 1)}{b64.int_to_b64(PROTOCOL[1], 2)}"
            f"{b64.int_to_b64(GENUS[0], 1)}{b64.int_to_b64(GENUS[1], 2)}{KIND}"
            f"{b64.int_to_b64(size, 4)}.")


def serialize(value, readings: Readings = DEFAULT) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=readings.ascii).encode("utf-8")


def digest(t: Tables, data: bytes) -> str:
    return encoding.primitive(t, "E", blake3.digest(data))


def sized(sad: dict, readings: Readings = DEFAULT) -> dict:
    """A copy with ``v`` sized to the copy's own serialization, if it has a ``v``."""
    out = dict(sad)
    if "v" in out:
        out["v"] = version_string(0)
        out["v"] = version_string(len(serialize(out, readings)))
    return out


def said(t: Tables, sad: dict, label: str = "d", readings: Readings = DEFAULT) -> str:
    """The SAID of ``sad`` as it stands: no compaction, ``v`` (if present) sized to the dummied
    serialization."""
    return digest(t, serialize(sized({**sad, label: DUMMY}, readings), readings))


def saidify(t: Tables, sad: dict, label: str = "d", readings: Readings = DEFAULT) -> dict:
    """A copy of ``sad`` with its SAID (and ``v``) filled in."""
    return sized({**sad, label: said(t, sad, label, readings)}, readings)


def expanded_said(t: Tables, acdc: dict, readings: Readings = DEFAULT) -> str:
    """The SAID over an ACDC as presented, without compaction: keripy 1.x's rule, which the
    2.00 rule replaces (A-C3)."""
    return said(t, acdc, readings=readings)


def schema_said(t: Tables, schema: dict, readings: Readings = DEFAULT,
                raw: bytes | None = None) -> str:
    """A schema's ``$id`` SAID: over its compact re-serialization, or over ``raw``, the bytes
    received, with the ``$id`` value dummied in place (A-B2)."""
    if readings.schema == "compact":
        return said(t, schema, "$id", readings)
    if raw is None:
        raise ScenarioError("The received-bytes reading of a schema SAID needs the bytes.",
                            E_READING)
    at, end = _root_id_token(raw)
    return digest(t, raw[:at] + f'"{DUMMY}"'.encode() + raw[end:])


def _root_id_token(raw: bytes) -> tuple[int, int]:
    """The byte span of the root map's ``$id`` value token, quotes included, found by walking the
    document's top-level structure, so that the same text in a string or a subschema is not it."""
    def refuse(why):
        return ScenarioError(f"The schema bytes {why}, so the received-bytes reading has no "
                             f"$id to dummy.", E_READING)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise refuse("are not UTF-8") from None
    def not_json(constant):
        raise refuse(f"hold {constant}, which Python's json reads and JSON does not have")

    def finite(literal):
        value = float(literal)
        if math.isinf(value):
            raise refuse(f"hold the number {literal}, which is too large for a float")
        return value

    decoder = json.JSONDecoder(parse_constant=not_json, parse_float=finite)
    ws = json.decoder.WHITESPACE.match
    i = ws(text, 0).end()
    if text[i:i + 1] != "{":
        raise refuse("are not a JSON object")
    found = None
    i = ws(text, i + 1).end()
    try:
        while text[i:i + 1] != "}":
            key, i = decoder.raw_decode(text, i)
            i = ws(text, i).end()
            if not isinstance(key, str) or text[i:i + 1] != ":":
                raise ValueError
            start = ws(text, i + 1).end()
            value, i = decoder.raw_decode(text, start)
            if key == "$id":
                if found is not None:
                    raise refuse("name $id twice at the top level")
                if not isinstance(value, str):
                    raise refuse("hold a top-level $id that is not a string")
                found = (start, i)
            i = ws(text, i).end()
            if text[i:i + 1] == ",":
                i = ws(text, i + 1).end()
                if text[i:i + 1] == "}":
                    raise ValueError
            elif text[i:i + 1] != "}":
                raise ValueError
    except ValueError:
        raise refuse("are not well-formed JSON") from None
    if ws(text, i + 1).end() != len(text):
        raise refuse("carry text after the JSON object")
    if found is None:
        raise refuse("have no top-level $id")
    return len(text[:found[0]].encode()), len(text[:found[1]].encode())


def is_saided(value) -> bool:
    return isinstance(value, dict) and isinstance(value.get("d"), str)


def compact_value(t: Tables, value, readings: Readings = DEFAULT):
    """A field value in block-level expanded form: a SAIDed block becomes its SAID, a map that is
    not a SAIDed block keeps its shape with its contents compacted, and a list is compacted
    inside only under the ``traverse`` reading."""
    if is_saided(value):
        return block_said(t, value, readings)
    if isinstance(value, dict):
        return {k: compact_value(t, v, readings) for k, v in value.items()}
    if isinstance(value, list) and readings.lists == "traverse":
        return [compact_value(t, v, readings) for v in value]
    return value


def block_said(t: Tables, block: dict, readings: Readings = DEFAULT) -> str:
    """The most compact SAID of a SAIDed block (lines 142 to 147)."""
    return said(t, {k: compact_value(t, v, readings) for k, v in block.items()},
                readings=readings)


def aggregate(t: Tables, blocks: list, readings: Readings = DEFAULT) -> list:
    """The compact list form of an aggregate: the AGID, then each block's SAID. A block may be
    given expanded or as its SAID, as a selective disclosure gives it."""
    saids = [b if isinstance(b, str) else block_said(t, b, readings) for b in blocks]
    return [agid(t, saids, readings)] + saids


def agid(t: Tables, saids: list[str], readings: Readings = DEFAULT) -> str:
    """The AGID over the blinded attribute blocks' SAIDs (A-C1)."""
    if readings.aggregate == "list":
        return digest(t, serialize([DUMMY] + list(saids), readings))
    return digest(t, "".join(saids).encode())


def most_compact(t: Tables, acdc: dict, readings: Readings = DEFAULT) -> dict:
    """The ACDC's most compact form, with its top-level SAID in ``d`` (lines 134 to 155)."""
    out = {}
    for key, value in acdc.items():
        if key == "s" and isinstance(value, dict):
            out[key] = schema_said(t, value, Readings(**{**readings.__dict__,
                                                         "schema": "compact"}))
        elif key == "A" and isinstance(value, list):
            out[key] = aggregate(t, value[1:], readings)[0]
        else:
            out[key] = compact_value(t, value, readings)
    if readings.compact_v == "own":
        return saidify(t, out, readings=readings)
    if "v" not in acdc:
        raise ScenarioError("The presented-size reading of the most compact form needs the "
                            "presented ACDC's version string.", E_READING)
    out["v"] = acdc["v"]
    out["d"] = digest(t, serialize({**out, "d": DUMMY}, readings))
    return out


def acdc_said(t: Tables, acdc: dict, readings: Readings = DEFAULT) -> str:
    return most_compact(t, acdc, readings)["d"]


def state_primitive(t: Tables, value: str, readings: Readings = DEFAULT) -> str:
    """The qualified text of a transaction state value (lines 2062, 2087, A-B3)."""
    if value == "":
        return EMPTY
    if any(c not in b64.ALPHABET for c in value):
        raise ScenarioError(f"The state {value!r} has characters outside Base64, which none of "
                            f"the candidate state codes can carry.", E_STATE)
    if readings.ts_code == "strb64":
        ws = (4 - len(value) % 4) % 4
        ls = (3 - len(value) % 4) % 3
        raw = b64.decode("A" * ws + value)[ls:]
        return encoding.variable(t, "A", raw)
    if readings.ts_code == "bytes":
        return encoding.variable(t, "B", value.encode())
    if len(value) in PREPADDED_TAGS:
        raise ScenarioError(f"The state {value!r} needs the {PREPADDED_TAGS[len(value)]} tag, "
                            f"whose pre-pad character the CESR text does not give.", E_STATE)
    if len(value) not in TAGS:
        raise ScenarioError(f"The state {value!r} is longer than any tag code carries.", E_STATE)
    code = TAGS[len(value)]
    assert t.primitives[code].fs == len(code) + len(value)  # the table agrees with TAGS
    return code + value


def _transaction_said(t: Tables, td: str) -> str:
    if td == "":
        return EMPTY
    if len(td) != t.primitives["E"].fs or not td.startswith("E") or \
            any(c not in b64.ALPHABET for c in td):
        raise ScenarioError(f"The transaction SAID {td!r} is not a Blake3-256 qualified digest "
                            f"or empty.", E_STATE)
    return td


def _block_text(t, u, td, ts, readings) -> str:
    return u + _transaction_said(t, td) + state_primitive(t, ts, readings)


def blid(t: Tables, u: str, td: str, ts: str, readings: Readings = DEFAULT) -> str:
    """The BLID of the blinded state block ``[d, u, td, ts]``: ``u`` is a qualified salt, ``td``
    an ACDC SAID or empty, ``ts`` a state string or empty."""
    return digest(t, (DUMMY + _block_text(t, u, td, ts, readings)).encode())


def blinded_block(t: Tables, u: str, td: str, ts: str, readings: Readings = DEFAULT) -> str:
    """The block's text-domain serialization with its BLID in place, as an attachment carries
    it after a ``-a`` count code."""
    return blid(t, u, td, ts, readings) + _block_text(t, u, td, ts, readings)
