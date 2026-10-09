"""Build ACDCs, their registry events and the ``acdc.verify`` request bundle from a declarative
scenario fragment.

Everything follows the ACDC specification v1.0 (``spec_source.ACDC``) and the readings
docs/design.md fixes, through ``acdc_saids``:

- **ACDCs** have their top-level fields in the order of line 32, ``[v, t, d, u, i, rd, s, a, A,
  e, r]``, with ``t`` = ``acm`` unless the scenario omits it, and ``d`` the most compact SAID.
  Every block in a scenario that carries ``"d": ""`` is a SAIDed block whose SAID is computed;
  an ``A`` section is a list of blinded attribute blocks, prefixed with its AGID. A schema marked
  ``"said": false`` is not a SAD: it is delivered as written, its ``$id`` the URI it stands at. Each ACDC is
  presented in the form its scenario names (``compact``, the default; ``expanded``; or a map
  naming dotted paths to ``compact`` and, for ``A``, the block indices to ``disclose``), with its
  version string sized to that form, unless the scenario names ``declared_size`` (``compact``:
  the version string keeps the compact form's size, a deliberate framing tamper).
- **Registry events** are the blindable registry's ``rip`` ``[v, t, d, u, i, n, dt]`` and ``bup``
  ``[v, t, d, rd, n, p, dt, b]`` (lines 1985 and 1989), ``n`` in hex without leading zeros, and
  ``b`` the BLID of the blinded state block ``[d, u, td, ts]``. Non-blindable ``upd`` events are
  deferred, as the design says.
- **Seals** in the issuer's KEL are written into the scenario's key events: ``{"acdc": name}``
  becomes the digest seal ``{d}`` of the ACDC's most compact SAID (line 1663, direct issuance),
  and ``{"registry": name}`` the transaction event seal ``{s, d}`` (line 1922).
- **Attachments** follow the body in a CESR attachments group ``-C``: a seal source couple
  ``-S`` (sequence number and SAID) of the key event a ``source_seal`` names (line 1671's
  reference), then, for a ``bup`` whose blinded block is disclosed, the block as a ``-a`` blinded
  state quadruple (line 2087).
- **The bundle** is the request of docs/adapter-protocol.md: hex streams, each led by the
  genus/version code ``-_AAACAA``, with schemas as raw compact JSON. Its ``acdcs`` hold the far
  nodes of the presented ACDC's provenance DAG, leaves first, each once, and nothing else: a
  fragment naming an ACDC that no edge path from the presented one reaches is refused. An edge is
  a map with an ``n`` field in an ACDC's ``e`` section, and ``n`` names its far node by reference
  or by literal SAID; an ``{"acdc": N}`` anywhere else is a SAID, not an edge. The DAG
  is bounded at 16 ACDCs and a longest path of 8 edges. An omitted ACDC leaves ``acdcs``, and
  so does every ACDC that only it reaches, because a validator cannot see the omitted node's
  edges; the ``dag`` lists only the edges of nodes the bundle carries.

Inside an ACDC's sections, a map with one key names another thing in the fragment: ``{"aid": X}``
is the prefix of X's inception, ``{"acdc": N}`` N's most compact SAID, ``{"schema": S}`` S's
SAID, ``{"registry": R}`` a registry event's SAID and ``{"nonce": L}`` a deterministic salt.

The builder never decides whether what it builds is valid; that is the grading's job.
"""

import hashlib
import json
import re
from dataclasses import dataclass, field

from . import acdc_saids as sa
from . import encoding
from . import json_schema_subset as js
from .errors import GeneratorError, ScenarioError
from .keri_events import GENUS_CODE, EventBuilder, label_digest
from .tables import Tables

RIP_FIELDS = ("v", "t", "d", "u", "i", "n", "dt")
BUP_FIELDS = ("v", "t", "d", "rd", "n", "p", "dt", "b")
ACDC_FIELDS = ("v", "t", "d", "u", "i", "rd", "s", "a", "A", "e", "r")
SECTIONS = ("a", "A", "e", "r")
REFS = ("aid", "acdc", "schema", "registry", "nonce", "nothing")
PROTOCOL = re.compile(r"[A-Z]{4}")
DEFAULT_DT = "2025-07-04T17:50:00.000000+00:00"
MAX_ACDCS = 16
MAX_DEPTH = 8

# A provenance DAG beyond the protocol's bounds, or an ACDC whose edges lead back to itself.
E_DAG = "e.input.range.kcs-acdc-dag.f"
# An ACDC in the fragment that no edge path from the presented ACDC reaches, which ``acdcs``
# (the presented ACDC's provenance DAG) cannot carry, or an edge whose far node is in no fragment.
E_DAG_UNREACHABLE = "e.input.format.kcs-acdc-dag-unreachable.f"
# An edge whose ``n`` is not a SAID string, so it names no far node.
E_EDGE = "e.input.format.kcs-acdc-edge.f"


def _seed(kind: str, label: str, size: int) -> bytes:
    return hashlib.shake_256(f"kcs-acdc-{kind}/{label}".encode()).digest(size)


def nonce(t: Tables, label: str) -> str:
    """A 128-bit salt (code ``0A``) fixed by its label, the form of the spec examples' UUIDs."""
    return encoding.primitive(t, "0A", _seed("nonce", label, 16))


def blind(t: Tables, label: str) -> str:
    """A 256-bit blinding factor (code ``a``) fixed by its label, for a blinded state block."""
    return encoding.primitive(t, "a", _seed("blind", label, 32))


def rip(t: Tables, issuer: str, u: str, dt: str = DEFAULT_DT,
        readings: sa.Readings = sa.DEFAULT) -> dict:
    fields = {"v": "", "t": "rip", "d": "", "u": u, "i": issuer, "n": "0", "dt": dt}
    return sa.saidify(t, fields, readings=readings)


def bup(t: Tables, rd: str, n: int, prior: str, b: str, dt: str = DEFAULT_DT,
        readings: sa.Readings = sa.DEFAULT) -> dict:
    fields = {"v": "", "t": "bup", "d": "", "rd": rd, "n": f"{n:x}", "p": prior, "dt": dt, "b": b}
    return sa.saidify(t, fields, readings=readings)


@dataclass
class Bundle:
    request: dict  # the acdc.verify request's bundle fields
    saids: dict[str, str]  # SAID of every named ACDC, schema and registry event
    expanded: dict[str, dict] = field(default_factory=dict)  # each ACDC fully expanded
    forms: dict[str, dict] = field(default_factory=dict)  # each ACDC as it is presented
    graph: dict[str, list[str]] = field(default_factory=dict)  # edges by ACDC name
    dag: dict = field(default_factory=dict)  # the case's dag field: root and keyed edges
    as_of: dict[str, int] = field(default_factory=dict)  # last sequence number per AID/registry

    def case_input(self) -> dict:
        """The case's input: the request, from a validator's perspective."""
        return {"perspective": {"role": "validator"}, **self.request}


def _index(items: list[dict], kind: str) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for item in items:
        if item["name"] in out:
            raise ScenarioError(f"The {kind} {item['name']!r} is defined twice.")
        out[item["name"]] = item
    return out


def edge_paths(e, path: str = "e") -> list[tuple[str, str]]:
    """Every edge in an expanded edge section as (label path, far node SAID): a map with an
    ``n`` field is an edge, whose ``n`` must be a string, and any other map or list is searched,
    a list's items labelled by their index."""
    if isinstance(e, dict):
        if "n" in e:
            if not isinstance(e["n"], str):
                raise ScenarioError(f"The edge at {path} has an n of {e['n']!r}; an edge's n "
                                    f"names its far node by SAID, so it is a string.", E_EDGE)
            return [(path, e["n"])]
        return [p for k, v in e.items() for p in edge_paths(v, f"{path}.{k}")]
    if isinstance(e, list):
        return [p for i, v in enumerate(e) for p in edge_paths(v, f"{path}.{i}")]
    return []


class _Builder:
    def __init__(self, t: Tables, frag: dict, readings: sa.Readings):
        self.t, self.frag, self.readings = t, frag, readings
        self.acdcs = _index(frag.get("acdcs", []), "ACDC")
        self.schemas = _index(frag.get("schemas", []), "schema")
        self.registries = _index(frag.get("registries", []), "registry event")
        # Schemas, registry events and ACDCs share one map of SAIDs and one namespace of
        # references, so a name used for two kinds of thing would silently resolve to the wrong one.
        kinds = (("a schema", self.schemas), ("a registry event", self.registries),
                 ("an ACDC", self.acdcs))
        for i, (kind, names) in enumerate(kinds):
            for other, other_names in kinds[i + 1:]:
                for name in names:
                    if name in other_names:
                        raise ScenarioError(f"The name {name!r} names both {kind} and "
                                            f"{other}; each name in a fragment names one thing.")
        self.eb = EventBuilder(t, frag.get("events", []), seal_resolver=self._seal)
        self.saids: dict[str, str] = {}
        self.expanded: dict[str, dict] = {}
        self.events: dict[str, tuple[dict, str]] = {}  # registry body and disclosed block
        self.schema_bodies: dict[str, dict] = {}
        self._building: set[str] = set()
        self._building_events: set[str] = set()

    # -- references ----------------------------------------------------------------------------

    def _seal(self, seal: dict) -> dict:
        if set(seal) == {"acdc"}:
            return {"d": self.acdc_said(seal["acdc"])}
        if set(seal) == {"registry"}:
            body = self.registry_event(seal["registry"])
            return {"s": body["n"], "d": body["d"]}
        raise ScenarioError(f"The seal {seal!r} names neither a key event, an ACDC nor a "
                            f"registry event.")

    def _resolve(self, value):
        if isinstance(value, dict):
            if len(value) == 1 and next(iter(value)) in REFS:
                kind, name = next(iter(value.items()))
                return {"aid": self.eb.prefix, "acdc": self.acdc_said,
                        "schema": self.schema_said, "nonce": lambda x: nonce(self.t, x),
                        "registry": lambda x: self.registry_event(x)["d"],
                        "nothing": lambda x: label_digest(self.t, x)}[kind](name)
            return {k: self._resolve(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self._resolve(v) for v in value]
        return value

    def _fill(self, value):
        """Compute the SAID of every SAIDed block, innermost first."""
        if isinstance(value, dict):
            filled = {k: self._fill(v) for k, v in value.items()}
            if sa.is_saided(filled):
                filled["d"] = sa.block_said(self.t, filled, self.readings)
            return filled
        if isinstance(value, list):
            return [self._fill(v) for v in value]
        return value

    # -- schemas and registry events -----------------------------------------------------------

    def schema_said(self, name: str) -> str:
        if name not in self.schemas:
            raise ScenarioError(f"No schema is named {name!r}.")
        if name not in self.schema_bodies and self.schemas[name].get("said", True) is False:
            # A document that stands at a non-local reference's URI: not a SAD, so its $id is
            # that URI and it is delivered as written.
            schema = self.schemas[name]["schema"]
            if not isinstance(schema.get("$id"), str) or not schema["$id"]:
                raise ScenarioError(f"The unsaided schema {name!r} needs the URI it stands at "
                                    f"as its $id.")
            js.check(schema, allow_nonlocal=True)
            self.saids[name], self.schema_bodies[name] = schema["$id"], schema
        if name not in self.schema_bodies:
            schema = self.schemas[name]["schema"]
            js.check(schema, allow_nonlocal=True)
            compact = sa.Readings(**{**self.readings.__dict__, "schema": "compact"})
            body = sa.saidify(self.t, schema, "$id", compact)
            self.saids[name] = body["$id"]
            self.schema_bodies[name] = self._alter(body, self.schemas[name].get("alter", []),
                                                   f"schema {name!r}", sized=False)
        return self.saids[name]

    def _prior(self, name: str, spec: dict) -> str:
        if "prior" in spec:
            return spec["prior"]
        order = list(self.registries)
        same = [n for n in order[: order.index(name)]
                if n == spec["registry"] or self.registries[n].get("registry") == spec["registry"]]
        if not same:
            raise ScenarioError(f"Registry event {name!r} has no earlier event of its registry "
                                f"{spec['registry']!r} to follow.")
        return same[-1]

    def _registry_spec(self, name: str) -> dict:
        if name not in self.registries:
            raise ScenarioError(f"No registry event is named {name!r}.")
        return self.registries[name]

    def registry_event(self, name: str) -> dict:
        if name in self.events:
            return self.events[name][0]
        spec = self._registry_spec(name)
        if name in self._building_events:
            raise ScenarioError(f"Registry event {name!r} depends on itself through its prior "
                                f"events or its state, which no SAID can satisfy.")
        self._building_events.add(name)
        dt = spec.get("dt", DEFAULT_DT)
        block = ""
        if spec["t"] == "rip":
            body = rip(self.t, self.eb.prefix(spec["issuer"]), nonce(self.t, spec.get("u", name)),
                       dt, self.readings)
        elif spec["t"] == "bup":
            rd = self.registry_inception(spec["registry"])
            prior = self.registry_event(self._prior(name, spec))
            n = spec.get("n", int(prior["n"], 16) + 1)
            state = spec["state"]
            u, td, ts = blind(self.t, state["u"]), self._resolve(state["td"]), state["ts"]
            b = sa.blid(self.t, u, td, ts, self.readings)
            body = bup(self.t, rd, n, prior["d"], b, dt, self.readings)
            block = self._disclosed(name, spec.get("disclose"), u, td, ts, b)
        else:
            raise ScenarioError(f"Registry event {name!r} has type {spec['t']!r}; only rip and "
                                f"bup are built (upd is deferred).")
        body = self._alter(body, spec.get("alter", []), f"registry event {name!r}")
        self.events[name] = (body, block)
        self.saids[name] = body["d"]
        self._building_events.discard(name)
        return body

    def _disclosed(self, name: str, how, u: str, td: str, ts: str, b: str) -> str:
        """The blinded state block a bup's attachment carries: none, the real one, or, for a
        tamper, other content with either the real BLID kept or the content's own BLID."""
        if not how:
            return ""
        if how is True:
            return sa.blinded_block(self.t, u, td, ts, self.readings)
        if not isinstance(how, dict) or how.get("blid") not in ("kept", "own"):
            raise ScenarioError(f"Registry event {name!r} discloses {how!r}; a tampered "
                                f"disclosure names its td or ts and whether its blid is kept "
                                f"or its own.")
        td = self._resolve(how.get("td", td))
        ts = how.get("ts", ts)
        own = sa.blinded_block(self.t, u, td, ts, self.readings)
        return own if how["blid"] == "own" else b + own[len(b):]

    def registry_inception(self, name: str) -> str:
        spec = self._registry_spec(name)
        if spec["t"] != "rip":
            raise ScenarioError(f"{name!r} is not a registry inception (rip) event.")
        return self.registry_event(name)["d"]

    # -- ACDCs ---------------------------------------------------------------------------------

    def acdc_said(self, name: str) -> str:
        if name in self.saids:
            return self.saids[name]
        if name not in self.acdcs:
            raise ScenarioError(f"No ACDC is named {name!r}.")
        if name in self._building:
            raise GeneratorError(f"ACDC {name!r} depends on its own SAID through its edges or "
                                 f"seals, which no SAID can satisfy.", E_DAG)
        self._building.add(name)
        spec = self.acdcs[name]
        values = {"v": "", "t": spec.get("t", "acm"), "d": ""}
        if "u" in spec:
            values["u"] = nonce(self.t, spec["u"])
        values["i"] = self.eb.prefix(spec["issuer"])
        if "registry" in spec:
            values["rd"] = self.registry_inception(spec["registry"])
        if spec.get("schema") is not None:
            values["s"] = self.schema_said(spec["schema"])
        for section in SECTIONS:
            if section in spec:
                values[section] = self._fill(self._resolve(spec[section]))
        if "A" in values:
            values["A"] = sa.aggregate(self.t, values["A"], self.readings)[:1] + values["A"]
        acdc = {k: values[k] for k in ACDC_FIELDS if k in values and values[k] is not None}
        acdc = self._ordered(name, acdc)
        acdc["d"] = self._top_said(name, sa.sized({**acdc, "d": sa.DUMMY}, self.readings))
        self.expanded[name] = self._protocol(name, sa.sized(acdc, self.readings))
        self.saids[name] = acdc["d"]
        self._building.discard(name)
        return acdc["d"]

    def _ordered(self, name: str, acdc: dict) -> dict:
        order = self.acdcs[name].get("order")
        if order is None:
            return acdc
        if sorted(order) != sorted(acdc):
            raise ScenarioError(f"ACDC {name!r} has the order {order!r}, which must name exactly "
                                f"its fields {list(acdc)!r}.")
        return {k: acdc[k] for k in order}

    def _protocol(self, name: str, sad: dict) -> dict:
        """The ACDC with its version string's protocol replaced, if its scenario names another
        (a tamper: the body is no longer framed as an ACDC); the replacement keeps the length."""
        protocol = self.acdcs[name].get("protocol")
        if protocol is None:
            return sad
        if not isinstance(protocol, str) or not PROTOCOL.fullmatch(protocol):
            raise ScenarioError(f"ACDC {name!r} names the protocol {protocol!r}; a version "
                                f"string's protocol is four uppercase letters.")
        return {**sad, "v": protocol + sad["v"][4:]}

    def _top_said(self, name: str, dummied: dict) -> str:
        """The top-level SAID: the most compact SAID (lines 134 to 147), or for a tamper the SAID
        over the expanded form, keripy 1.x's rule (A-C3), or over a body whose version string
        names another protocol."""
        rule = self.acdcs[name].get("said", "compact")
        if rule == "expanded":
            return sa.expanded_said(self.t, dummied, self.readings)
        if rule != "compact":
            raise ScenarioError(f"ACDC {name!r} has the said rule {rule!r}; it is compact or "
                                f"expanded.")
        compact = sa.most_compact(self.t, dummied, self.readings)
        if self.acdcs[name].get("protocol") is None:
            return compact["d"]
        patched = self._protocol(name, {**compact, "d": sa.DUMMY})
        return sa.digest(self.t, sa.serialize(patched, self.readings))

    def _alter(self, sad: dict, alterations: list, what: str, sized: bool = True) -> dict:
        """``sad`` with each alteration applied after its SAIDs were computed: a value set at a
        dotted path, then the SAIDs of any blocks named in ``resaid`` recomputed. Nothing else
        is recomputed, and a SAD with a version string must keep its length, so the tamper
        changes no framing."""
        if not alterations:
            return sad
        out = json.loads(json.dumps(sad))
        for alter in alterations:
            if not isinstance(alter, dict) or not isinstance(alter.get("path"), str):
                raise ScenarioError(f"An alteration of {what} needs a path: {alter!r}.")
            self._set(out, alter["path"], self._resolve(alter.get("value")), what)
            for path in alter.get("resaid", []):
                parts = path.split(".")
                block = self._get(out, parts, path, what)
                if not sa.is_saided(block):
                    raise ScenarioError(f"The path {path!r} of {what} does not name a SAIDed "
                                        f"block, so it has no SAID to recompute.")
                block["d"] = sa.block_said(self.t, block, self.readings)
        if sized and len(sa.serialize(out, self.readings)) != len(sa.serialize(sad,
                                                                                self.readings)):
            raise ScenarioError(f"An alteration of {what} changes its length; a tamper keeps the "
                                f"length so that its version string still frames it. Choose a "
                                f"value of the same length.")
        return out

    def _get(self, node, parts: list[str], path: str, what: str):
        for part in parts:
            if not isinstance(node, dict) or part not in node:
                raise ScenarioError(f"The path {path!r} names nothing in {what}.")
            node = node[part]
        return node

    def _set(self, node: dict, path: str, value, what: str) -> None:
        *head, last = path.split(".")
        parent = self._get(node, head, path, what)
        if not isinstance(parent, dict) or last not in parent:
            raise ScenarioError(f"The path {path!r} names nothing in {what}.")
        parent[last] = value

    def form(self, name: str) -> dict:
        """The ACDC as it is presented, after any alteration the scenario asks for."""
        out = self._protocol(name, self._form(name))
        out = self._alter(out, self.acdcs[name].get("alter", []), f"ACDC {name!r}")
        return self._declared(name, out)

    def _declared(self, name: str, out: dict) -> dict:
        """The presented form with its version string declaring another form's size, if the
        scenario says so (a tamper of framing, made on purpose: the issuer resized nothing after
        expanding). The version string keeps its length, so only the declared size changes."""
        declared = self.acdcs[name].get("declared_size")
        if declared is None:
            return out
        if declared != "compact":
            raise ScenarioError(f"ACDC {name!r} has declared_size {declared!r}; the only other "
                                f"size a form may declare is the compact form's.")
        compact = sa.sized({**sa.most_compact(self.t, self.expanded[name], self.readings),
                            "d": self.saids[name]}, self.readings)
        return {**out, "v": out["v"][:4] + compact["v"][4:]}

    def _form(self, name: str) -> dict:
        expanded = self.expanded[name]
        form = self.acdcs[name].get("form", "compact")
        if form == "expanded":
            return expanded
        if form == "compact":
            return sa.sized({**sa.most_compact(self.t, expanded, self.readings),
                             "d": self.saids[name]}, self.readings)
        if not isinstance(form, dict):
            raise ScenarioError(f"ACDC {name!r} has form {form!r}; a form is compact, expanded "
                                f"or a map of paths to compact and blocks to disclose.")
        out = dict(expanded)
        for key, value in form.items():
            if key == "compact":
                for path in value:
                    out = self._compact_path(out, path.split("."), path)
            elif key == "disclose":
                if not isinstance(out.get("A"), list):
                    raise ScenarioError(f"ACDC {name!r} discloses blocks, but has no A list.")
                blocks = out["A"][1:]
                out["A"] = [out["A"][0]] + [b if i in value else b["d"]
                                            for i, b in enumerate(blocks)]
            else:
                raise ScenarioError(f"ACDC {name!r} has an unknown form key {key!r}.")
        return sa.sized(out, self.readings)

    def _compact_path(self, node: dict, parts: list[str], path: str) -> dict:
        target = node.get(parts[0]) if isinstance(node, dict) else None
        if len(parts) == 1:
            if not sa.is_saided(target):
                raise ScenarioError(f"The form path {path!r} does not name a SAIDed block.")
            return {**node, parts[0]: sa.block_said(self.t, target, self.readings)}
        return {**node, parts[0]: self._compact_path(target, parts[1:], path)}

    # -- the DAG -------------------------------------------------------------------------------

    def dag(self) -> tuple[dict[str, list[str]], list[tuple[str, str, str]]]:
        """The provenance graph, from exactly the edges the bundle's ``dag`` lists: one per map
        with an ``n`` field in an ACDC's expanded ``e`` section, its far node the fragment ACDC
        whose SAID ``n`` holds, however the scenario wrote it. Returned as each ACDC's far nodes
        by name, and every edge as (near name, label path, far SAID). Run once every SAID is
        computed; a reference cycle has already been refused by ``acdc_said``, and a cycle of
        literal SAIDs would need a digest to contain itself."""
        # Two ACDCs written alike are one ACDC with one SAID; the bundle would carry it twice,
        # and the protocol carries each far node once.
        by_said: dict[str, str] = {}
        for name in self.acdcs:
            twin = by_said.get(self.saids[name])
            if twin is not None:
                raise ScenarioError(f"The ACDCs {twin!r} and {name!r} are written alike and "
                                    f"have one SAID; a bundle carries each ACDC once. Make them "
                                    f"differ or define one.")
            by_said[self.saids[name]] = name
        graph: dict[str, list[str]] = {}
        edges: list[tuple[str, str, str]] = []
        for name in self.acdcs:
            graph[name] = []
            for path, far in edge_paths(self.expanded[name].get("e", {})):
                if far not in by_said:
                    raise ScenarioError(f"ACDC {name!r} has an edge at {path} to {far!r}, which "
                                        f"is the SAID of no ACDC in the fragment. To leave a far "
                                        f"node out of the bundle, define it and list it in omit.",
                                        E_DAG_UNREACHABLE)
                edges.append((name, path, far))
                if by_said[far] not in graph[name]:
                    graph[name].append(by_said[far])
        depth: dict[str, int] = {}

        def longest(name):
            if name not in depth:
                depth[name] = max((1 + longest(c) for c in graph[name]), default=0)
            return depth[name]

        presented = self.frag["presented"]
        if longest(presented) > MAX_DEPTH:
            raise GeneratorError(f"The provenance DAG's longest path from {presented!r} has "
                                 f"{depth[presented]} edges; the bound is {MAX_DEPTH}.", E_DAG)
        return graph, edges

    def far_nodes(self, graph) -> list[str]:
        order: list[str] = []

        def visit(name):
            for child in graph[name]:
                visit(child)
                if child not in order:
                    order.append(child)

        presented = self.frag["presented"]
        visit(presented)
        rest = [n for n in self.acdcs if n not in order and n != presented]
        if rest:
            raise ScenarioError(f"The ACDCs {rest!r} are not in the provenance DAG of the "
                                f"presented ACDC {presented!r}: no edge path from it reaches "
                                f"them, and the bundle's acdcs hold that DAG and nothing else. "
                                f"Link them by an edge or remove them.", E_DAG_UNREACHABLE)
        return order

    def _reachable(self, graph, omit) -> set[str]:
        """The ACDCs reachable from the presented one without passing through an omitted one,
        which are the nodes the bundle carries."""
        seen, frontier = set(), [self.frag["presented"]]
        while frontier:
            name = frontier.pop()
            if name in seen or name in omit:
                continue
            seen.add(name)
            frontier.extend(graph[name])
        return seen

    # -- streams -------------------------------------------------------------------------------

    def _group(self, code: str, parts: list[str]) -> str:
        text = "".join(parts)
        return encoding.counter(self.t, code, len(text) // 4) + text

    def attachments(self, source_seal: str | None, block: str = "") -> str:
        groups = []
        if source_seal is not None:
            said = None
            if isinstance(source_seal, dict):
                if "event" not in source_seal:
                    raise ScenarioError(f"The source seal {source_seal!r} names no event.")
                said = label_digest(self.t, source_seal["wrong_said"])
                source_seal = source_seal["event"]
            anchor = self.eb.event(source_seal)
            sn = encoding.primitive(self.t, "0A", anchor.sn.to_bytes(16, "big"))
            groups.append(self._group("-S", [sn + (said or anchor.said)]))
        if block:
            groups.append(self._group("-a", [block]))
        return self._group("-C", groups) if groups else ""

    def stream(self, body: dict, attachments: str) -> str:
        data = GENUS_CODE.encode() + sa.serialize(body, self.readings) + attachments.encode()
        return data.hex()

    def bundle(self) -> Bundle:
        presented = self.frag["presented"]
        if presented not in self.acdcs:
            raise ScenarioError(f"The presented ACDC {presented!r} is not defined.")
        omit = set(self.frag.get("omit", []))
        for name in omit:
            if not any(name in m for m in (self.acdcs, self.schemas, self.registries)):
                raise ScenarioError(f"{name!r} is omitted but names nothing in the fragment.")
        if presented in omit:
            raise ScenarioError(f"The presented ACDC {presented!r} cannot be omitted.")
        if len(self.acdcs) > MAX_ACDCS:
            raise GeneratorError(f"The fragment has {len(self.acdcs)} ACDCs; a bundle holds at "
                                 f"most {MAX_ACDCS}.", E_DAG)
        for name in list(self.schemas):
            self.schema_said(name)
        for name in list(self.registries):
            self.registry_event(name)
        for name in list(self.acdcs):
            self.acdc_said(name)
        graph, edges = self.dag()
        far = self.far_nodes(graph)
        # An omitted node's edges are invisible to a validator, so a node that only it reaches
        # leaves the bundle with it: acdcs and the dag hold the same nodes, less the omitted.
        kept = self._reachable(graph, omit)
        far = [n for n in far if n in kept]
        forms = {name: self.form(name) for name in self.acdcs}
        kels, as_of = [], {}
        for delivery in self.frag.get("kels", []):
            message = self.eb.message(delivery)
            kels.append({"stream": message.stream.hex(),
                         "source": delivery.get("source", message.event.aid)})
            ev = message.event
            as_of[ev.pre] = max(as_of.get(ev.pre, 0), ev.sn)
        for name in self.registries:
            if name not in omit:
                body = self.events[name][0]
                rd = body.get("rd", body["d"])
                as_of[rd] = max(as_of.get(rd, 0), int(body["n"], 16))
        dag = {"root": self.saids[presented], "edges": [
            {"near": self.saids[near], "path": path, "n": n}
            for near, path, n in edges if near in kept]}

        def acdc_entry(name):
            att = self.attachments(self.acdcs[name].get("source_seal"))
            return {"stream": self.stream(forms[name], att)}

        request = {
            "kels": kels,
            "registry": [{"stream": self.stream(self.events[n][0], self.attachments(
                self.registries[n].get("source_seal"), self.events[n][1]))}
                for n in self.registries if n not in omit],
            "schemas": [sa.serialize(self.schema_bodies[n], self.readings).hex()
                        for n in self.schemas if n not in omit],
            "acdcs": [acdc_entry(n) for n in far],
            "presented": acdc_entry(presented),
        }
        return Bundle(request=request, saids=dict(self.saids), expanded=dict(self.expanded),
                      forms=forms, graph=graph, dag=dag, as_of=as_of)


def build_bundle(t: Tables, fragment: dict, readings: sa.Readings = sa.DEFAULT) -> Bundle:
    """The acdc.verify bundle a scenario fragment describes, with every SAID it computed."""
    return _Builder(t, fragment, readings).bundle()
