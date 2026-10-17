"""A keripy 1.x issuance, built by the suite, for the sedi-1x-interop companion (test-plan item 11;
this.i 9sgwng6m).

No normative text defines what keripy 1.x issues, so everything here is transcribed from keripy
1.2.14 (tag ``1.2.14``, commit ``bab95c16e949b61398129a3e41a8f68bad84c94f``), and
``generators/keripy1x_check/check_acdc.py`` checks every bundle against keripy 1.2.14 itself:

- **KEL.** An inception and one interaction per anchored registry event, as keripy's
  ``eventing.incept`` and ``eventing.interact`` lay them out (``icp`` ``[v, t, d, i, s, kt, k, nt,
  n, bt, b, c, a]``, ``ixn`` ``[v, t, d, i, s, p, a]``), with the 1.x version string
  ``KERI10JSON<size in six hex digits>_`` and the controller's Ed25519 signature in a 1.00
  ``-A`` group, whose count is the number of signatures.
- **Registry.** keripy's ``vdr.eventing``: ``vcp`` ``[v, t, d, i, ii, s, c, bt, b, n]`` with
  ``i`` self-addressing like ``d``, ``iss`` ``[v, t, d, i, s, ri, dt]`` and ``rev`` ``[v, t, d, i,
  s, ri, p, dt]``. Each carries the KEL interaction that anchors it as a seal source couple
  (sequence number, digest) in a 1.00 ``-G`` group, and each interaction anchors it with the seal
  ``{i, s, d}``.
- **ACDC.** keripy's ``vc.proving.credential``: ``[v, d, i, ri, s, a]`` then ``e`` when it has
  edges, ``ACDC10JSON`` version string, the attribute block's SAID first and then the
  credential's over that expanded form. Unlike keripy's own builder, ``a.dt`` is written only
  when the scenario gives one, since whether a verifier needs it is what incompatibility 11 is
  about. The credential carries its ``iss`` event as a seal source triple (prefix, sequence
  number, digest) in a 1.00 ``-I`` group.

Every stream is a 1.x stream: no genus/version code, as keripy 1.x cannot read one.

A spec names the ``issuer`` role, the ``roles`` that get a KEL, the ``schemas`` by name, an
optional ``registry`` label that fixes the registry's nonce, and ``credentials`` in issuance order:
each with its ``name``, ``schema``, optional ``issuee`` and ``dt``, ``attributes`` (a dict value
becomes a nested block with its own SAID), ``revoked``, and ``edges`` naming credentials issued
before it, each optionally with ``o`` and with the ``u`` that makes it a SEDI edge block, plus an
optional ``edges_u`` for the section itself.
"""

import json

from . import acdc_saids as sa
from . import b64, encoding
from . import keri_events as ke
from .errors import ScenarioError
from .tables import Tables

DUMMY = "#" * 44
STAMP = "2026-10-01T00:00:00.000000+00:00"
KEL = {"icp": ("v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "a"),
       "ixn": ("v", "t", "d", "i", "s", "p", "a")}


def _json(fields: dict) -> bytes:
    return json.dumps(fields, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sized(fields: dict, protocol: str) -> dict:
    fields = {**fields, "v": f"{protocol}10JSON000000_"}
    return {**fields, "v": f"{protocol}10JSON{len(_json(fields)):06x}_"}


def _saidify(t: Tables, fields: dict, protocol: str, labels=("d",)) -> dict:
    """The body with its SAID in every label, computed over the sized body with each dummied."""
    dummied = _sized({**fields, **{label: DUMMY for label in labels}}, protocol)
    said = ke.digest(t, _json(dummied))
    return {**dummied, **{label: said for label in labels}}


def _count(code: str, count: int) -> str:
    """A 1.00 count code: two characters, then the count in two base 64 digits."""
    return code + b64.int_to_b64(count, 2)


def _seqner(t: Tables, sn: int) -> str:
    return encoding.primitive(t, "0A", sn.to_bytes(16, "big"))


def _signed(t: Tables, key: str, raw: bytes) -> str:
    return _count("-A", 1) + encoding.indexed(t, "A", ke.signature(key, raw), 0)


class Issuance:
    """One issuer's KEL, its registry and the credentials it issues, from a scenario's spec."""

    def __init__(self, t: Tables, spec: dict):
        self.t = t
        self.spec = spec
        self.events: list[tuple[dict, str]] = []  # KEL bodies, each with its signing key
        self.prefixes: dict[str, str] = {}
        self.kels: list[dict] = []
        self.registry: list[dict] = []
        self.acdcs: dict[str, bytes] = {}
        self.saids: dict[str, str] = {}
        self.edges: dict[str, list[tuple[str, str]]] = {}  # each credential's (label, far)
        self.as_of: dict[str, int] = {}  # each KEL and TEL's last sequence number
        self.schemas = {name: {**schema, "$id": sa.schema_said(t, {**schema, "$id": DUMMY})}
                        for name, schema in spec["schemas"].items()}
        for role in spec.get("roles", [spec["issuer"]]):
            self.prefixes[role] = self._inception(role)["i"]
        self._issue()

    # -- the KEL --

    def _inception(self, role: str) -> dict:
        fields = dict.fromkeys(KEL["icp"], "")
        fields.update(t="icp", s="0", kt="1", k=[ke.verkey(self.t, f"{role}/k0")], nt="1",
                      n=[ke.next_digest(self.t, f"{role}/k1")], bt="0", b=[], c=[], a=[])
        body = _saidify(self.t, fields, "KERI", ("d", "i"))
        self.kels.append({"stream": self._stream(body, f"{role}/k0").hex(), "source": role})
        self.as_of[body["i"]] = 0
        if role == self.spec["issuer"]:
            self.events.append((body, f"{role}/k0"))
        return body

    def _anchor(self, seal: dict) -> tuple[int, str]:
        """An interaction anchoring one seal; its sequence number and SAID."""
        prior, key = self.events[-1]
        fields = dict.fromkeys(KEL["ixn"], "")
        fields.update(t="ixn", i=prior["i"], s=f"{len(self.events):x}", p=prior["d"], a=[seal])
        body = _saidify(self.t, fields, "KERI")
        self.events.append((body, key))
        self.kels.append({"stream": self._stream(body, key).hex(), "source": self.spec["issuer"]})
        self.as_of[body["i"]] = len(self.events) - 1
        return len(self.events) - 1, body["d"]

    def _stream(self, body: dict, key: str) -> bytes:
        raw = _json(body)
        return raw + _signed(self.t, key, raw).encode()

    # -- the registry --

    def _tel(self, body: dict) -> dict:
        """A registry event anchored in the issuer's KEL, delivered with its seal source couple."""
        sn, said = self._anchor({"i": body["i"], "s": body["s"], "d": body["d"]})
        raw = _json(body) + (_count("-G", 1) + _seqner(self.t, sn) + said).encode()
        self.registry.append({"stream": raw.hex()})
        self.as_of[body["i"]] = int(body["s"], 16)
        return body

    def _issue(self):
        issuer = self.prefixes[self.spec["issuer"]]
        vcp = {"v": "", "t": "vcp", "d": "", "i": "", "ii": issuer, "s": "0", "c": ["NB"], "bt": "0", "b": [],
                   "n": encoding.primitive(self.t, "0A", ke.seed(
                       self.spec.get("registry", "registry-nonce"))[:16])}
        vcp = self._tel(_saidify(self.t, vcp, "KERI", ("d", "i")))
        self.saids["registry"] = vcp["i"]
        for asked in self.spec["credentials"]:
            acdc = self._credential(asked, issuer, vcp["i"])
            iss = self._tel(_saidify(self.t, {"v": "", "t": "iss", "d": "", "i": acdc["d"], "s": "0",
                                                  "ri": vcp["i"], "dt": STAMP}, "KERI"))
            raw = _json(acdc) + (_count("-I", 1) + acdc["d"] + _seqner(self.t, 0)
                                 + iss["d"]).encode()
            self.acdcs[asked["name"]] = raw
            if asked.get("revoked"):
                self._tel(_saidify(self.t, {"v": "", "t": "rev", "d": "", "i": acdc["d"], "s": "1",
                                                "ri": vcp["i"], "p": iss["d"], "dt": STAMP}, "KERI"))

    def _credential(self, asked: dict, issuer: str, registry: str) -> dict:
        if asked["schema"] not in self.schemas:
            raise ScenarioError(f"The credential {asked['name']!r} names the schema "
                                f"{asked['schema']!r}, which the scenario does not define.")
        block = {"d": ""}
        if "issuee" in asked:
            block["i"] = self.prefixes[asked["issuee"]]
        if "dt" in asked:
            block["dt"] = asked["dt"]
        for label, value in asked.get("attributes", {}).items():
            block[label] = self._block(value) if isinstance(value, dict) else value
        block = self._block(block)
        acdc = {"v": "", "d": "", "i": issuer, "ri": registry, "s": self.schemas[asked["schema"]]["$id"],
                    "a": block}
        if "edges" in asked:
            edges = {"d": ""}
            if "edges_u" in asked:
                edges["u"] = asked["edges_u"]
            for label, edge in asked["edges"].items():
                far = edge["credential"]
                if far not in self.saids:
                    raise ScenarioError(f"The edge {label!r} of {asked['name']!r} names "
                                        f"{far!r}, which is not issued before it.")
                node = {"d": "", "u": edge["u"]} if "u" in edge else {}
                node.update(n=self.saids[far], s=self.saids[f"{far}.schema"])
                if "o" in edge:
                    node["o"] = edge["o"]
                edges[label] = self._block(node) if "d" in node else node
                self.edges.setdefault(asked["name"], []).append((label, far))
            acdc["e"] = self._block(edges)
        acdc = _saidify(self.t, acdc, "ACDC")
        self.saids[asked["name"]] = acdc["d"]
        self.saids[f"{asked['name']}.schema"] = acdc["s"]
        return acdc

    def _block(self, block: dict) -> dict:
        """A block with its SAID in ``d``, over the block as given with ``d`` dummied. keripy 1.x
        never checks a nested block's SAID, but SEDI's schemas require one."""
        block = {"d": "", **block}
        return {**block, "d": ke.digest(self.t, _json({**block, "d": DUMMY}))}

    def dag(self, presented: str) -> dict:
        """The presented credential's provenance DAG, as a case records it: every edge reachable
        from it, each once."""
        edges, todo, seen = [], [presented], set()
        while todo:
            name = todo.pop(0)
            if name in seen:
                continue
            seen.add(name)
            for label, far in self.edges.get(name, []):
                edges.append({"near": self.saids[name], "path": f"e.{label}",
                              "n": self.saids[far]})
                todo.append(far)
        return {"root": self.saids[presented], "edges": edges}

    def request(self, presented: str) -> dict:
        """The acdc.verify request presenting one credential, with every other one as a far node
        in the order it was issued."""
        if presented not in self.acdcs:
            raise ScenarioError(f"The scenario presents {presented!r}, which it does not issue.")
        return {"perspective": {"role": "validator"}, "kels": self.kels,
                "registry": self.registry,
                "schemas": [_json(s).hex() for s in self.schemas.values()],
                "acdcs": [{"stream": raw.hex()} for name, raw in self.acdcs.items()
                          if name != presented],
                "presented": {"stream": self.acdcs[presented].hex()}}
