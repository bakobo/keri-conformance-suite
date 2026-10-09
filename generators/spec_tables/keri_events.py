"""Build KERI key events, receipts and their attachments from a scenario's named events.

Everything here follows the KERI specification v1.0.1 (``spec_source.KERI``) and the CESR code
tables of the CESR specification v1.0, and nothing else:

- **Bodies** are KERI 2.XX JSON field maps with their top-level fields in the order the
  specification gives for each type ("Inception Event Message Body" and the sections after it:
  ``icp`` ``[v, t, d, i, s, kt, k, nt, n, bt, b, c, a]``, ``dip`` the same plus ``di``, ``rot``
  and ``drt`` ``[v, t, d, i, s, p, kt, k, nt, n, bt, br, ba, c, a]``, ``ixn``
  ``[v, t, d, i, s, p, a]``, ``rct`` ``[v, t, d, i, s]``), serialized as compact JSON. The version
  string is ``KERIMmmGggKKKKSSSS.`` ("Version string field") with protocol and genus version 2.00.
- **SAIDs** follow the CESR SAID protocol: the SAID field (and ``i``, for a self-addressing
  inception) holds 44 ``#`` while the Blake3-256 digest of the serialization is taken.
- **Keys** are Ed25519, qualified with code ``D`` (transferable) or ``B`` (non-transferable), and
  each seed is the first 32 bytes of SHAKE-256 over the key's label, so every key is fixed by
  the scenario text. A next-key digest is the Blake3-256 digest of the qualified public key's
  text, the reading of "a fully qualified digest of a public key" that keripy also uses (recorded
  in generators/SPEC-ISSUES.md, K-I1).
- **Attachments** are one CESR 2.00 attachments group ``-C`` holding controller-indexed signatures
  (``-K``), witness-indexed signatures (``-L``), non-transferable receipt couples (``-M``) and
  seal source couples (``-S``), in that order. Each stream starts with the genus/version code
  ``-_AAACAA``, because the CESR specification gives no default table for a stream without one.

A scenario may tamper with an event on purpose (a wrong SAID, a ``d`` that differs from ``i``, a
wrong prior digest or sequence number, a forged signature). The builder applies only what the
scenario asks for; it never decides whether the result is acceptable. That is the model's job.
"""

import hashlib
import json
import re
from dataclasses import dataclass, field
from functools import cache

from . import b64, blake3, ed25519, encoding
from .errors import ScenarioError
from .tables import Tables

PROTOCOL = (2, 0)
GENUS = (2, 0)
GENUS_CODE = "-_AAACAA"
DUMMY = "#" * 44
FIELDS = {
    "icp": ("v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "a"),
    "dip": ("v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "a", "di"),
    "rot": ("v", "t", "d", "i", "s", "p", "kt", "k", "nt", "n", "bt", "br", "ba", "c", "a"),
    "drt": ("v", "t", "d", "i", "s", "p", "kt", "k", "nt", "n", "bt", "br", "ba", "c", "a"),
    "ixn": ("v", "t", "d", "i", "s", "p", "a"),
    "rct": ("v", "t", "d", "i", "s"),
}
INCEPTIONS = ("icp", "dip")
ESTABLISHMENT = ("icp", "dip", "rot", "drt")
ROTATIONS = ("rot", "drt")
DELEGATED = ("dip", "drt")


def seed(label: str) -> bytes:
    return hashlib.shake_256(f"kcs-keri-seed/{label}".encode()).digest(32)


@cache
def public_key(label: str) -> bytes:
    """The public key of a label's seed. Pure-Python Ed25519 is slow, so each is made once."""
    return ed25519.public_key(seed(label))


@cache
def signature(label: str, message: bytes) -> bytes:
    return ed25519.sign(seed(label), message)


def verkey(t: Tables, label: str, transferable: bool = True) -> str:
    return encoding.primitive(t, "D" if transferable else "B", public_key(label))


def digest(t: Tables, data: bytes) -> str:
    return encoding.primitive(t, "E", blake3.digest(data))


def next_digest(t: Tables, label: str) -> str:
    return digest(t, verkey(t, label).encode("ascii"))


def label_digest(t: Tables, label: str) -> str:
    """A digest that names nothing: for a deliberately wrong SAID, prior or seal."""
    return digest(t, f"kcs-keri-nothing/{label}".encode())


def version_string(size: int) -> str:
    return (f"KERI{b64.int_to_b64(PROTOCOL[0], 1)}{b64.int_to_b64(PROTOCOL[1], 2)}"
            f"{b64.int_to_b64(GENUS[0], 1)}{b64.int_to_b64(GENUS[1], 2)}JSON"
            f"{b64.int_to_b64(size, 4)}.")


WIRE = "KERICAACAAJSON"


def serialize(fields: dict) -> bytes:
    return json.dumps(fields, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sized(fields: dict) -> bytes:
    """Serialize with the version string's size field set to the serialization's own size."""
    fields["v"] = version_string(0)
    fields["v"] = version_string(len(serialize(fields)))
    return serialize(fields)


def corrupt(raw: bytes, label: str) -> bytes:
    """The body with one character of the first qualified primitive under a field changed, and
    every other byte, the claimed SAID included, as it was: a copy anyone can make of an event
    without its keys."""
    start = raw.index(f'"{label}":'.encode()) + len(label) + 3
    at = re.compile(rb'"[A-Za-z0-9_-]{8,}"').search(raw, start).start() + 2
    swapped = b"B" if raw[at:at + 1] == b"A" else b"A"
    return raw[:at] + swapped + raw[at + 1:]


@dataclass
class Event:
    """A built key event: its scenario name, its body and the labels behind it."""

    name: str
    aid: str
    ilk: str
    sn: int
    pre: str
    said: str
    body: dict
    raw: bytes
    keys: list[str] = field(default_factory=list)  # labels of the signing keys (k, or est's k)
    next: list[str] = field(default_factory=list)  # labels behind n (establishment events only)
    prior_next: list[str] = field(default_factory=list)  # labels behind the prior est's n
    wits: list[str] = field(default_factory=list)  # labels of the effective witness list


@dataclass
class Message:
    """One delivery: the stream and what went into it."""

    stream: bytes
    source: str
    event: Event  # the key event, or for a receipt the receipted event
    receipt: bool


class EventBuilder:
    """Builds a case's named events on demand, each once, resolving priors, prefixes and seals."""

    def __init__(self, t: Tables, specs: list[dict], seal_resolver=None):
        self.t = t
        # Turns a seal that names something other than a key event (an ACDC, a registry event)
        # into its field map; the ACDC builder supplies it.
        self.seal_resolver = seal_resolver
        self.specs: dict[str, dict] = {}
        self.order: list[str] = []
        for spec in specs:
            name = spec["name"]
            if name in self.specs:
                raise ScenarioError(f"Event {name!r} is defined twice.")
            self.specs[name] = spec
            self.order.append(name)
        self.built: dict[str, Event] = {}
        self._building: set[str] = set()

    # -- resolution ----------------------------------------------------------------------------

    def _inception_of(self, aid: str) -> str:
        for name in self.order:
            spec = self.specs[name]
            if spec["aid"] == aid and spec["t"] in INCEPTIONS:
                return name
        raise ScenarioError(f"Identifier {aid!r} has no inception event.")

    def _prior_of(self, name: str) -> str:
        spec = self.specs[name]
        if "prior" in spec:
            return spec["prior"]
        before = self.order[: self.order.index(name)]
        mine = [n for n in before if self.specs[n]["aid"] == spec["aid"]]
        if not mine:
            raise ScenarioError(f"Event {name!r} has no prior event of {spec['aid']!r}.")
        return mine[-1]

    def prefix(self, aid: str) -> str:
        return self.event(self._inception_of(aid)).pre

    def event(self, name: str) -> Event:
        if name in self.built:
            return self.built[name]
        if name not in self.specs:
            raise ScenarioError(f"No event is named {name!r}.")
        if name in self._building:
            raise ScenarioError(f"Event {name!r} depends on itself.")
        self._building.add(name)
        spec = self.specs[name]
        builder = {"icp": self._inception, "dip": self._inception, "rot": self._rotation,
                   "drt": self._rotation, "ixn": self._interaction}.get(spec["t"])
        if builder is None:
            raise ScenarioError(f"Event {name!r} has unknown type {spec['t']!r}.")
        ev = builder(name, spec)
        self._building.discard(name)
        self.built[name] = ev
        return ev

    def _seal(self, seal: dict) -> dict:
        if "event" not in seal:
            if self.seal_resolver is None:
                raise ScenarioError(f"The seal {seal!r} names no key event, and nothing here can "
                                    f"resolve it.")
            return self.seal_resolver(seal)
        target = self.event(seal["event"])
        d = label_digest(self.t, seal["wrong_said"]) if "wrong_said" in seal else target.said
        return {"i": target.pre, "s": f"{target.sn:x}", "d": d}

    def _threshold(self, value):
        if isinstance(value, (str, list)):
            return value
        raise ScenarioError(f"A threshold must be a string or a list, not {value!r}.")

    # -- events --------------------------------------------------------------------------------

    def _finish(self, name, spec, fields, self_addressing) -> Event:
        """Compute the SAID (and a self-addressing prefix), then apply any tampering."""
        tamper = spec.get("tamper", {})
        fields["d"] = DUMMY
        if self_addressing:
            fields["i"] = DUMMY
        said = digest(self.t, sized(fields))
        fields["d"] = said
        if self_addressing:
            fields["i"] = said
        if "d" in tamper:  # a SAID that is not the digest of the body
            fields["d"] = label_digest(self.t, tamper["d"])
        raw = sized(fields)
        return Event(name=name, aid=spec["aid"], ilk=fields["t"], sn=int(fields["s"], 16),
                     pre=fields["i"], said=fields["d"], body=dict(fields), raw=raw)

    def _inception(self, name, spec) -> Event:
        t = self.t
        kind = spec.get("prefix", "self")
        keys, nxt = spec["keys"], spec.get("next", [])
        tamper = spec.get("tamper", {})
        fields = {k: None for k in FIELDS[spec["t"]]}
        fields["t"] = spec["t"]
        fields["s"] = f"{spec.get('s', 0):x}"
        fields["kt"] = self._threshold(spec.get("kt", "1"))
        # A non-transferable identifier's key is qualified as non-transferable, like its prefix.
        fields["k"] = [verkey(t, x, transferable=kind != "nontransferable") for x in keys]
        fields["nt"] = self._threshold(spec.get("nt", "1" if nxt else "0"))
        fields["n"] = [next_digest(t, x) for x in nxt]
        wits = spec.get("wits", [])
        fields["bt"] = spec.get("bt", "0")
        fields["b"] = [verkey(t, w, transferable=False) for w in wits]
        fields["c"] = spec.get("c", [])
        fields["a"] = [self._seal(s) for s in spec.get("a", [])]
        if spec["t"] == "dip":
            fields["di"] = self.prefix(spec["delegator"])
        self_addressing = kind == "self" and "i" not in tamper
        if kind == "basic":
            fields["i"] = verkey(t, keys[0])
        elif kind == "nontransferable":
            fields["i"] = verkey(t, keys[0], transferable=False)
        elif "i" in tamper:  # a digest-type prefix that is not the inception's SAID
            fields["i"] = label_digest(t, tamper["i"])
        ev = self._finish(name, spec, fields, self_addressing)
        ev.keys, ev.next, ev.wits = list(keys), list(nxt), list(wits)
        return ev

    def _chain(self, name) -> tuple[Event, Event]:
        """The prior event and the latest establishment event at or before it."""
        prior = self.event(self._prior_of(name))
        est = prior
        while est.ilk not in ESTABLISHMENT:
            est = self.event(self._prior_of(est.name))
        return prior, est

    def _common(self, name, spec, prior) -> dict:
        fields = {k: None for k in FIELDS[spec["t"]]}
        fields["t"] = spec["t"]
        fields["i"] = self.prefix(spec["aid"])
        fields["s"] = f"{spec.get('s', prior.sn + 1):x}"
        tamper = spec.get("tamper", {})
        fields["p"] = label_digest(self.t, tamper["p"]) if "p" in tamper else prior.said
        return fields

    def _rotation(self, name, spec) -> Event:
        t = self.t
        prior, est = self._chain(name)
        keys, nxt = spec["keys"], spec.get("next", [])
        fields = self._common(name, spec, prior)
        fields["kt"] = self._threshold(spec.get("kt", "1"))
        fields["k"] = [verkey(t, x) for x in keys]
        fields["nt"] = self._threshold(spec.get("nt", "1" if nxt else "0"))
        fields["n"] = [next_digest(t, x) for x in nxt]
        br, ba = spec.get("br", []), spec.get("ba", [])
        fields["bt"] = spec.get("bt", "0")
        fields["br"] = [verkey(t, w, transferable=False) for w in br]
        fields["ba"] = [verkey(t, w, transferable=False) for w in ba]
        fields["c"] = spec.get("c", [])
        fields["a"] = [self._seal(s) for s in spec.get("a", [])]
        ev = self._finish(name, spec, fields, False)
        remaining = [w for w in prior.wits if w not in br]
        ev.keys, ev.next, ev.prior_next = list(keys), list(nxt), list(est.next)
        ev.wits = remaining + [w for w in ba if w not in remaining]
        return ev

    def _interaction(self, name, spec) -> Event:
        prior, est = self._chain(name)
        fields = self._common(name, spec, prior)
        fields["a"] = [self._seal(s) for s in spec.get("a", [])]
        ev = self._finish(name, spec, fields, False)
        ev.keys, ev.wits = list(est.keys), list(prior.wits)
        return ev

    # -- attachments ---------------------------------------------------------------------------

    def _controller_sig(self, ev: Event, sig) -> str:
        if isinstance(sig, str):
            sig = {"key": sig}
        key = sig["key"]
        if "index" in sig:
            index = sig["index"]
        elif key in ev.keys:
            index = ev.keys.index(key)
        else:
            raise ScenarioError(f"{ev.name}: {key!r} is not one of its signing keys.")
        if ev.ilk in ROTATIONS:
            ondex = sig.get("ondex", ev.prior_next.index(key) if key in ev.prior_next else None)
        else:
            ondex = sig.get("ondex", index)
        code = sig.get("code")
        if code is None:
            if ondex is None:
                code = "B" if index < 64 else "2B"
            elif ondex == index and index < 64:
                code = "A"
            else:
                code = "2A"
        signer = f"{key}/forged" if sig.get("forged") else key
        raw = signature(signer, ev.raw)
        entry = self.t.indexed[code]
        return encoding.indexed(self.t, code, raw, index, ondex if entry.os else None)

    def _witness_sig(self, ev: Event, wig) -> str:
        if isinstance(wig, str):
            wig = {"key": wig}
        key = wig["key"]
        if "index" in wig:
            index = wig["index"]
        elif key in ev.wits:
            index = ev.wits.index(key)
        else:
            raise ScenarioError(f"{ev.name}: {key!r} is not one of its witnesses.")
        signer = f"{key}/forged" if wig.get("forged") else key
        raw = signature(signer, ev.raw)
        return encoding.indexed(self.t, "A", raw, index)

    def _group(self, code: str, parts: list[str]) -> str:
        body = "".join(parts)
        return encoding.counter(self.t, code, len(body) // 4) + body

    def attachments(self, ev: Event, delivery: dict) -> str:
        groups = []
        sigs = delivery.get("sigs", [])
        if sigs:
            groups.append(self._group("-K", [self._controller_sig(ev, s) for s in sigs]))
        wigs = delivery.get("wigs", [])
        if wigs:
            groups.append(self._group("-L", [self._witness_sig(ev, w) for w in wigs]))
        couples = delivery.get("couples", [])
        if couples:
            parts = []
            for label in couples:
                parts.append(verkey(self.t, label, transferable=False))
                parts.append(encoding.primitive(self.t, "0B", signature(label, ev.raw)))
            groups.append(self._group("-M", parts))
        if "source_seal" in delivery:
            anchor = self.event(delivery["source_seal"])
            sn = encoding.primitive(self.t, "0A", anchor.sn.to_bytes(16, "big"))
            groups.append(self._group("-S", [sn + anchor.said]))
        if not groups:
            return ""
        return self._group("-C", groups)

    def message(self, delivery: dict) -> Message:
        if "receipt" in delivery:
            ev = self.event(delivery["receipt"])
            fields = {"v": None, "t": "rct", "d": ev.said, "i": ev.pre, "s": f"{ev.sn:x}"}
            body = sized(fields)
            source = delivery.get("source", "witness")
        else:
            ev = self.event(delivery["event"])
            body = ev.raw
            if "corrupt" in delivery:
                body = corrupt(body, delivery["corrupt"])
            source = delivery.get("source", "controller")
        stream = GENUS_CODE.encode() + body + self.attachments(ev, delivery).encode()
        return Message(stream=stream, source=source, event=ev, receipt="receipt" in delivery)
