"""A model validator for ``acdc.verify``: the decision procedure of docs/design.md ("ACDC", "The
decision procedure"), applied to the exact bytes of a bundle.

The ACDC generator never writes an expected value by hand. It builds a bundle, runs this model
over the bundle's bytes, and grades what the model finds (acdc_cases). The model reports every
check that fails, not only the first, because a refusal is graded at the highest of its
independent derivations (docs/design.md, "How levels are derived"); the step that decides the
case is the earliest of them.

What it checks, for the presented ACDC and for every far node its edges reach:

1. Intrinsic: the version string frames a 2.00 JSON body by its declared size (line 62) and
   names ACDC (line 64), checked no further when it names another protocol; the top-level fields
   are known and in the order of line 32; the required fields of line 36 are present; ``a`` and
   ``A`` are not both non-empty (line 110); every SAIDed block, the aggregate's AGID and the
   top-level most compact SAID verify (CESR line 1194; lines 134 to 147, 714). A body that does
   not frame is checked no further.
2. Schema: a schema whose ``$id`` is the ACDC's ``s`` is in the bundle and verifies against that
   SAID (lines 186 and 248), uses no reference that leaves it (line 206), names the 2020-12
   dialect if it names one (line 226), and the ACDC as presented validates against it (lines 246
   and 250).
3. Issuer key state: the issuer's inception is seen, by the KERI model (keri_model) under every
   keep policy (line 95).
4. and 5. Commitment: a digest seal of the ACDC's SAID on the issuer's trunk, or a disclosed
   blinded state block in the verified chain of the registry its ``rd`` names. The registry's
   chain is verified event by event and stops at the first failure.

Then every edge in the provenance DAG is checked on its own: the far node is in the bundle, its
recomputed SAID is the edge's ``n``, it satisfies its own schema and the edge's ``s``, and an
``I2I`` operator finds the near node's issuer as the far node's issuee (lines 1174, 1178, 1205).
An edge without an explicit operator, and any operator but ``I2I``, is outside the first batch
and refused.

The model reads the bytes under a ``Readings`` (acdc_saids), so the grading can ask whether a
result depends on a reading the text leaves open.
"""

import json
from dataclasses import dataclass, field

from . import acdc_saids as sa
from . import b64, keri_model
from . import json_schema_subset as js
from .acdc_build import ACDC_FIELDS
from .decoding import VERSION_2
from .errors import ScenarioError
from .tables import Tables

GENUS = b"-_AAACAA"
REQUIRED = ("v", "d", "i", "s")
EMPTY = sa.EMPTY
# Tag codes by code, the inverse of acdc_saids.TAGS.
TAG_CODES = {code: size for size, code in sa.TAGS.items()}
# The deepest nesting of maps and lists the model reads in any JSON body: an ACDC, a schema or a
# registry event. The deepest legitimate body in the first batch is a schema at about ten levels;
# the bound sits far above that and far below the interpreter's recursion limit, which the
# model's recursive walks over a body would otherwise reach (about 1,100 levels in 2.5 KB).
MAX_NESTING = 64
# A body nested deeper than MAX_NESTING. No clause makes such a body invalid, so the model
# refuses to derive any expectation from it rather than inventing a verdict.
E_NESTING = "e.input.range.kcs-acdc-nesting.f"


@dataclass(frozen=True)
class Failure:
    step: int
    reason: str

    @property
    def tag(self) -> str:
        return f"{self.step}/{self.reason}"


@dataclass
class Node:
    """One ACDC as received: its body if it framed, and what failed in steps 1 to 5."""

    body: dict | None
    failures: list[Failure] = field(default_factory=list)

    @property
    def said(self):
        return self.body.get("d") if self.body else None


@dataclass
class Edge:
    near: str
    path: str
    n: str
    failure: str | None  # the reason the edge is not valid, or None


@dataclass
class Registry:
    """The verified head of a registry and what its verified chain names."""

    rd: str
    n: int
    d: str
    td: str | None
    ts: str | None
    stop: str | None = None  # why the chain stopped before the bundle's last event, if it did
    block: str | None = None  # why the head's attached blinded state block does not verify
    names: set[str] = field(default_factory=set)
    updates: int = 0  # bup events in the bundle for this registry

    def facts(self) -> dict:
        return {"rd": self.rd, "n": self.n, "d": self.d, "td": self.td, "ts": self.ts}


@dataclass
class Result:
    presented: Node
    far: dict[str, Node]  # far nodes by claimed SAID
    edges: list[Edge]
    registry: Registry | None = None
    registry_failure: str | None = None  # why no registry is reported, when the ACDC names one

    def failing(self) -> bool:
        """Whether anything in the bundle fails a check."""
        return bool(self.presented.failures or any(n.failures for n in self.far.values())
                    or any(e.failure for e in self.edges) or self.registry_failure
                    or (self.registry and (self.registry.stop or self.registry.block)))


# -- reading the bytes ------------------------------------------------------------------------


def _parse(t: Tables, stream: bytes, protocol: bytes | None = b"ACDC"):
    """The message body, its raw bytes and the blinded state blocks attached to it, or None if
    the stream is not the genus/version code, one ACDC 2.00 JSON body and an attachments group.
    With ``protocol`` None, a 2.00 version string naming any protocol frames the body.

    The attachments are read here rather than by the reference parser (decoding), which does not
    read the Tag codes a blinded state block's ``ts`` uses (A-B3)."""
    if not stream.startswith(GENUS):
        return None
    rest = stream[len(GENUS):]
    m = VERSION_2.match(rest)
    if m is None or (protocol is not None and m.group(1) != protocol) \
            or (m.group(2), m.group(3)) != (b"C", b"AA") \
            or m.group(5) != b"JSON":
        return None
    size = b64.b64_to_int(m.group(6).decode())
    raw = rest[:size]
    body = _strict_json(raw)
    if len(raw) != size or not isinstance(body, dict):
        return None
    try:
        blocks = _blocks(t, rest[size:].decode("ascii"))
    except (ValueError, KeyError, UnicodeDecodeError):
        return None
    return body, raw, blocks


def _take(text: str, i: int, n: int) -> tuple[str, int]:
    if i + n > len(text):
        raise ValueError("truncated")
    return text[i:i + n], i + n


def _blocks(t: Tables, text: str) -> list[tuple[str, str, str, str]]:
    """The blinded state quadruples in an attachments group ``-C`` (``-a`` groups), skipping
    every other group; an empty text has none."""
    if not text:
        return []
    code, i = _take(text, 0, 2)
    count, i = _take(text, i, 2)
    if code != "-C" or len(text) != i + 4 * b64.b64_to_int(count):
        raise ValueError("not one attachments group")
    out = []
    while i < len(text):
        code, i = _take(text, i, 2)
        count, i = _take(text, i, 2)
        content, i = _take(text, i, 4 * b64.b64_to_int(count))
        if code == "-a":
            j = 0
            while j < len(content):
                fields = []
                for _ in range(4):
                    prim = _primitive_code(t, content[j:])
                    value, j = _take(content, j, t.primitives[prim].fs)
                    fields.append(value)
                out.append(tuple(fields))
    return out


def _primitive_code(t: Tables, text: str) -> str:
    for size in (4, 2, 1):
        if text[:size] in t.primitives:
            return text[:size]
    raise KeyError(text[:4])


def _nesting(raw: bytes) -> int:
    """The deepest nesting of maps and lists in JSON text, counted without parsing it, so that a
    body too deep to walk is refused before anything recurses into it. A bracket inside a string
    does not count; in UTF-8 neither a quote nor a backslash byte occurs inside a multi-byte
    character, so a byte scan finds the strings exactly."""
    depth = deepest = 0
    in_string = escaped = False
    for byte in raw:
        if escaped:
            escaped = False
        elif in_string:
            if byte == 0x5C:  # backslash
                escaped = True
            elif byte == 0x22:  # quote
                in_string = False
        elif byte == 0x22:
            in_string = True
        elif byte in b"[{":
            depth += 1
            deepest = max(deepest, depth)
        elif byte in b"]}":
            depth -= 1
    return deepest


def _strict_json(raw: bytes):
    if _nesting(raw) > MAX_NESTING:
        raise ScenarioError(f"A JSON body in the bundle nests maps and lists more than "
                            f"{MAX_NESTING} levels deep, beyond any ACDC, schema or registry "
                            f"event the model reads, so it derives no expectation from the "
                            f"bundle.", E_NESTING)

    def refuse(constant):
        raise ValueError(constant)
    try:
        return json.loads(raw, parse_constant=refuse)
    except ValueError:
        return None


class _Kels:
    """The trunk of every KEL in the bundle, which must not depend on the keep policy."""

    def __init__(self, t: Tables, streams: list[bytes]):
        trunks = []
        for policy in keri_model.POLICIES:
            model = keri_model.run(t, streams, policy)
            trunks.append({pre: [r.body for r in kel.trunk] for pre, kel in model.kels.items()
                           if kel.trunk})
        if any(tr != trunks[0] for tr in trunks):
            raise ScenarioError("The bundle's KELs end differently under different keep "
                                "policies, so no ACDC verdict can rest on them.")
        self.trunks = trunks[0]

    def seen(self, pre) -> bool:
        return pre in self.trunks

    def sealed(self, pre, seal: dict) -> bool:
        return any(seal in (body.get("a") or []) for body in self.trunks.get(pre, []))


def kels(t: Tables, request: dict) -> _Kels:
    """The trunks of a request's KELs, which do not depend on any ACDC reading, so one can serve
    every evaluation of the same request."""
    return _Kels(t, [bytes.fromhex(k["stream"]) for k in request["kels"]])


class _Model:
    def __init__(self, t: Tables, request: dict, readings: sa.Readings,
                 trunks: _Kels | None = None):
        self.t, self.readings = t, readings
        self.kels = trunks or kels(t, request)
        self.schemas = [bytes.fromhex(s) for s in request["schemas"]]
        self.registry_streams = [_parse(t, bytes.fromhex(r["stream"]))
                                 for r in request["registry"]]
        self.far = {}
        for entry in request["acdcs"]:
            node, raw = self.node(bytes.fromhex(entry["stream"]))
            if node.body is not None and isinstance(node.said, str):
                self.far.setdefault(node.said, (node, raw))

    # -- steps 1 to 5 ---------------------------------------------------------------------------

    def node(self, stream: bytes) -> tuple[Node, bytes]:
        parsed = _parse(self.t, stream)
        if parsed is None:
            # A body its version string frames under another protocol is not an ACDC body,
            # which is a different failure from bytes no version string frames.
            other = _parse(self.t, stream, protocol=None) is not None
            return Node(None, [Failure(1, "protocol" if other else "unframeable")]), b""
        body, raw, _ = parsed
        node = Node(body)
        node.failures += self._intrinsic(body)
        node.failures += self._schema(body)
        node.failures += self._commitment(node)
        return node, raw

    def _intrinsic(self, body: dict) -> list[Failure]:
        out = []
        keys = list(body)
        if any(k not in ACDC_FIELDS for k in keys) or keys != sorted(keys, key=ACDC_FIELDS.index):
            out.append(Failure(1, "field-order"))
        if any(k not in body for k in REQUIRED):
            out.append(Failure(1, "required-field"))
        if body.get("a") and body.get("A"):
            out.append(Failure(1, "a-and-A"))
        if not self._saids_verify(body):
            out.append(Failure(1, "said"))
        return out

    def _saids_verify(self, body: dict) -> bool:
        try:
            for section in ("a", "e", "r"):
                if not self._blocks_verify(body.get(section)):
                    return False
            aggregate = body.get("A")
            if isinstance(aggregate, list):
                blocks = aggregate[1:]
                if any(isinstance(b, dict) and sa.block_said(self.t, b, self.readings) != b["d"]
                       for b in blocks):
                    return False
                if sa.aggregate(self.t, blocks, self.readings)[0] != aggregate[0]:
                    return False
            return isinstance(body.get("d"), str) and \
                sa.acdc_said(self.t, body, self.readings) == body["d"]
        except (ScenarioError, TypeError, KeyError, AttributeError, IndexError):
            return False

    def _blocks_verify(self, value) -> bool:
        """Whether every SAIDed block in ``value`` verifies against its own SAID, wherever it
        sits, inside a list included. The ``lists`` reading (acdc_saids) is a different question:
        whether a block inside a list is compacted to its SAID in the enclosing block's most
        compact form. Under either answer a block that carries a SAID is self-addressing, and a
        SAID that does not verify is a failure (CESR line 1194)."""
        if isinstance(value, dict):
            if sa.is_saided(value) and sa.block_said(self.t, value, self.readings) != value["d"]:
                return False
            return all(self._blocks_verify(v) for v in value.values())
        if isinstance(value, list):
            return all(self._blocks_verify(v) for v in value)
        return True

    def schema(self, said) -> tuple[dict | None, str | None]:
        """The bundle's schema whose ``$id`` is ``said`` and that verifies against it, or the
        reason there is none."""
        found = None
        for raw in self.schemas:
            schema = _strict_json(raw)
            if isinstance(schema, dict) and schema.get("$id") == said and isinstance(said, str):
                try:
                    verifies = sa.schema_said(self.t, schema, self.readings, raw=raw) == said
                except ScenarioError:
                    # A schema whose SAID cannot be computed under this reading (its received
                    # bytes have no top-level $id to dummy, say) does not verify against it.
                    verifies = False
                if verifies:
                    return schema, None
                found = "schema-said"
        return None, found or "schema-absent"

    def satisfies(self, body: dict, said) -> list[str]:
        """The reasons ``body`` does not satisfy the schema ``said`` names, empty if it does."""
        schema, missing = self.schema(said)
        if schema is None:
            return [missing]
        if js.nonlocal_references(schema):
            return ["schema-nonlocal"]
        out = []
        if js.dialect(schema) not in (None, js.DIALECT):
            out.append("schema-dialect")
        if not js.validate(schema, body):
            out.append("schema-invalid")
        return out

    def _schema(self, body: dict) -> list[Failure]:
        return [Failure(2, r) for r in self.satisfies(body, body.get("s"))]

    def _commitment(self, node: Node) -> list[Failure]:
        body = node.body
        issuer = body.get("i")
        if not self.kels.seen(issuer):
            return [Failure(3, "issuer-kel")]
        said = body.get("d")
        if self.kels.sealed(issuer, {"d": said}):
            return []
        if "rd" in body:
            registry, _ = self.registry(body["rd"], issuer)
            if registry is not None and said in registry.names:
                return []
            return [Failure(5, "no-registry-commitment")]
        return [Failure(4, "no-commitment")]

    # -- the registry -----------------------------------------------------------------------------

    def registry(self, rd, issuer) -> tuple[Registry | None, str | None]:
        """The verified head of the registry ``rd``, walked in delivery order, or None with the
        reason its inception does not verify."""
        events = [p for p in self.registry_streams if p is not None and isinstance(p[0], dict)
                  and (p[0].get("d") == rd or p[0].get("rd") == rd)]
        rip = next((p for p in events if p[0].get("d") == rd), None)
        if rip is None or rip[0].get("t") != "rip":
            return None, "rip-absent"
        body = rip[0]
        if not self._event_said(body):
            return None, "rip-said"
        if body.get("i") != issuer:
            return None, "rip-issuer"
        if not self.kels.sealed(issuer, {"s": "0", "d": rd}):
            return None, "rip-unsealed"
        head = Registry(rd=rd, n=0, d=rd, td=None, ts=None)
        updates = [p for p in events if p is not rip]
        head.updates = len(updates)
        for bup, _, attachments in updates:
            stop = self._update_problem(bup, head, issuer)
            if stop:
                head.stop = stop
                break
            head.n, head.d = head.n + 1, bup["d"]
            head.td, head.ts, head.block = self._block(bup, attachments)
            if head.td:
                head.names.add(head.td)
        return head, None

    def _event_said(self, body: dict) -> bool:
        return sa.said(self.t, body, readings=self.readings) == body.get("d")

    def _update_problem(self, bup: dict, head: Registry, issuer) -> str | None:
        if bup.get("t") != "bup":
            return "bup-type"
        if not self._event_said(bup):
            return "bup-said"
        n = bup.get("n")
        if not isinstance(n, str) or n != f"{head.n + 1:x}":
            return "bup-sn"
        if bup.get("p") != head.d:
            return "bup-prior"
        if not self.kels.sealed(issuer, {"s": n, "d": bup["d"]}):
            return "bup-unsealed"
        return None

    def _block(self, bup: dict, blocks: list) -> tuple[str | None, str | None, str | None]:
        """The transaction SAID and state of the attached blinded state block that is the
        update's ``b`` and consistent with that BLID (lines 2066 and 2141), else unknown, with
        the reason when a block was attached and none verifies: ``blid-self`` when no block
        hashes to its own BLID, else ``blid-other`` when none is the update's ``b``."""
        own = [blk for blk in blocks
               if sa.digest(self.t, (sa.DUMMY + "".join(blk[1:])).encode()) == blk[0]]
        for blid, _, td, ts in own:
            if blid == bup.get("b"):
                return ("" if td == EMPTY else td), _state(ts), None
        if not blocks:
            return None, None, None
        return None, None, ("blid-other" if own else "blid-self")

    # -- edges ----------------------------------------------------------------------------------

    def edges(self, near: Node) -> list[Edge]:
        out = []
        for path, block in edge_blocks(near.body.get("e")):
            out.append(Edge(near.said, path, block["n"], self._edge_problem(near.body, block)))
        return out

    def _edge_problem(self, near: dict, block: dict) -> str | None:
        operators = block.get("o")
        if operators is None:
            raise ScenarioError("An edge with no operator is outside the first batch, so the "
                                "model does not evaluate one.")
        operators = operators if isinstance(operators, list) else [operators]
        if operators != ["I2I"]:
            raise ScenarioError(f"The operators {operators!r} are outside the first batch; the "
                                f"model evaluates I2I only.")
        far = self.far.get(block["n"])
        if far is None:
            return "far-absent"
        node, _ = far
        if any(f.reason == "said" for f in node.failures):
            return "far-said"
        if any(f.step == 2 for f in node.failures):
            return "far-schema"
        if "s" in block and self.satisfies(node.body, block["s"]):
            return "edge-schema"
        attributes = node.body.get("a")
        if not isinstance(attributes, dict):
            return "i2i-hidden"
        if "i" not in attributes:
            return "i2i-untargeted"
        if attributes["i"] != near.get("i"):
            return "i2i-issuee"
        return None


def _state(text: str) -> str:
    if text == EMPTY:
        return ""
    for size in (2, 1):
        if text[:size] in TAG_CODES:
            return text[size:]
    raise ScenarioError(f"The state {text!r} is not a Tag primitive, the only state code the "
                        f"first batch reads.")


def edge_blocks(e, path: str = "e") -> list[tuple[str, dict]]:
    """Every edge block in an edge section as (label path, block): a map with an ``n`` field."""
    if isinstance(e, dict):
        if isinstance(e.get("n"), str):
            return [(path, e)]
        return [p for k, v in e.items() for p in edge_blocks(v, f"{path}.{k}")]
    if isinstance(e, list):
        return [p for i, v in enumerate(e) for p in edge_blocks(v, f"{path}.{i}")]
    return []


def evaluate(t: Tables, request: dict, readings: sa.Readings = sa.DEFAULT,
             trunks: _Kels | None = None) -> Result:
    """What the decision procedure finds for an acdc.verify request's bundle. ``trunks``, from
    ``kels``, saves rerunning the KERI model for another reading of the same request."""
    model = _Model(t, request, readings, trunks)
    presented, _ = model.node(bytes.fromhex(request["presented"]["stream"]))
    result = Result(presented=presented, far={}, edges=[])
    if presented.body is None:
        return result
    body = presented.body
    if "rd" in body:
        result.registry, result.registry_failure = model.registry(body["rd"], body.get("i"))
    # The provenance DAG, from the presented ACDC through the far nodes the bundle holds.
    frontier, visited = [presented], set()
    while frontier:
        near = frontier.pop(0)
        if near.said in visited:
            continue
        visited.add(near.said)
        for edge in model.edges(near):
            result.edges.append(edge)
            if edge.n in model.far:
                far = model.far[edge.n][0]
                result.far[edge.n] = far
                # A far node whose SAID does not verify is not the node the edge names, so its
                # own edges are not followed: that is why a forged cycle is never walked.
                if not any(f.reason == "said" for f in far.failures):
                    frontier.append(far)
    return result
