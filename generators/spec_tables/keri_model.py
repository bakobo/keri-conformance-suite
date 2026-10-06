"""A model validator that applies docs/design.md's KERI decision procedure to delivered streams.

The generator does not take any implementation's word for a disposition. It runs this model over
the exact bytes a case delivers, and the model decides each message's readings by the first step
of the procedure that applies:

1. intrinsic failure (the stream does not parse, the SAID does not match, an inception's ``d``
   and ``i`` differ, an inception's ``s`` is not 0);
2. no verifiable controller signature (none attached, or the key state needed to verify is held
   and none verifies);
3. forbidden by state the validator holds (establishment-only, do-not-delegate, any event after a
   non-transferable inception or an abandoning rotation);
4. not yet acceptable (prior not seen or not the trunk's, a broken pre-rotation commitment, a
   signing or witness threshold shortfall, a delegating seal not seen);
5. conflict on the trunk (a rotation that rule A0 permits supersedes; any other conflict is
   refused);
6. otherwise seen, and on the trunk.

The model reads every stream with the spec-table parser (``decoding.Parser``) and verifies every
signature and SAID itself; it never consults the scenario's labels. What it keeps for later is a
policy, because the specification's only escrow obligation is for threshold shortfalls (line 1266)
and everything else a validator keeps is its own choice:

- ``all``: keep every step-4 message and re-evaluate it at each quiescence (an escrowing
  validator, as keripy is);
- ``thresholds``: keep only signature and witness threshold shortfalls;
- ``none``: keep nothing.

The generator runs all three and refuses a case whose graded assertions would depend on the
choice (see keri_build). Superseding among delegated rotations (rules B and C) is not modelled;
a scenario that reaches it is refused rather than guessed at.
"""

import json
from dataclasses import dataclass, field
from fractions import Fraction
from functools import cache

from . import b64, ed25519, encoding
from .decoding import Parser, Rejected
from .errors import ScenarioError
from .keri_events import DUMMY, ESTABLISHMENT, FIELDS, INCEPTIONS, ROTATIONS, digest, sized
from .tables import Tables

POLICIES = ("all", "thresholds", "none")
THRESHOLD_REASONS = ("signing-threshold", "witness-threshold")
# Steps 3 and 5 judge an event version whose SAID step 1 has verified, so their refusal covers
# every copy of it. A step-1 failure names no version: its claimed SAID is the thing that failed.
VERSION_STEPS = (3, 5)
BASIC_CODES = ("D", "B")  # transferable and non-transferable Ed25519 prefixes


@cache
def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    """Ed25519 verification, remembered: the three keep policies verify the same signatures."""
    return ed25519.verify(public, message, signature)


def qb64_raw(text: str) -> bytes:
    """The raw value of a one-character-code, 44-character primitive (D, B, E)."""
    return b64.decode("A" + text[1:])[1:]


def satisfies(threshold, indices: set[int], size: int) -> bool:
    """Whether the signers at ``indices`` (positions in a list of ``size``) satisfy
    ``threshold``: a hex integer M of N, or fractionally weighted clauses, each of which must sum
    to at least one (lines 1407-1423)."""
    indices = {i for i in indices if 0 <= i < size}
    if isinstance(threshold, str):
        need = int(threshold, 16)
        if need < 1:
            raise ScenarioError(f"A numeric threshold of {threshold!r} is not modelled (G13).")
        return len(indices) >= need
    clauses = threshold if all(isinstance(c, list) for c in threshold) else [threshold]
    weights = [w for clause in clauses for w in clause]
    if len(weights) != size:
        raise ScenarioError(f"A weighted threshold of {len(weights)} weights over {size} keys is "
                            f"not modelled (I2).")
    offset = 0
    for clause in clauses:
        total = sum((Fraction(w) for j, w in enumerate(clause) if offset + j in indices),
                    Fraction(0))
        if total < 1:
            return False
        offset += len(clause)
    return True


@dataclass
class Sig:
    code: str
    index: int
    ondex: int | None  # the prior-next position it claims, or None for a current-only code
    raw: bytes


@dataclass
class Parsed:
    """What one delivered stream says, read from its bytes."""

    error: str | None = None
    body: dict = field(default_factory=dict)
    raw: bytes = b""
    sigs: list[Sig] = field(default_factory=list)
    wigs: list[tuple[int, bytes]] = field(default_factory=list)
    couples: list[tuple[str, bytes]] = field(default_factory=list)
    seals: list[tuple[int, str]] = field(default_factory=list)

    @property
    def ilk(self):
        return self.body.get("t")

    @property
    def pre(self):
        return self.body.get("i")

    @property
    def sn(self):
        return int(self.body.get("s", "0"), 16)

    @property
    def said(self):
        return self.body.get("d")


def parse(t: Tables, stream: bytes) -> Parsed:
    try:
        items = Parser(t).parse(stream)
    except Rejected as e:
        return Parsed(error=f"unparseable: {e}")
    messages = [it for it in items if it["kind"] == "message"]
    if len(messages) != 1:
        return Parsed(error="unparseable: not exactly one message")
    m = messages[0]
    raw = stream[m["start"]:m["end"]]
    body = json.loads(raw)
    p = Parsed(body=body, raw=raw)
    group, pending = None, []
    for it in items:
        if it["kind"] == "counter":
            group = it["code"]
        elif group == "-K" and it["kind"] == "indexed":
            ondex = None if it["code"] in ("B", "2B") else it.get("ondex", it["index"])
            p.sigs.append(Sig(it["code"], it["index"], ondex, bytes.fromhex(it["raw"])))
        elif group == "-L" and it["kind"] == "indexed":
            p.wigs.append((it["index"], bytes.fromhex(it["raw"])))
        elif group in ("-M", "-S") and it["kind"] == "primitive":
            pending.append(it)
            if len(pending) == 2:
                a, b = pending
                pending = []
                if group == "-M":
                    prefix = encoding.primitive(t, a["code"], bytes.fromhex(a["raw"]))
                    p.couples.append((prefix, bytes.fromhex(b["raw"])))
                else:
                    said = encoding.primitive(t, b["code"], bytes.fromhex(b["raw"]))
                    p.seals.append((int(a["raw"], 16), said))
    return p


def _code(t: Tables, text: str) -> str:
    """The derivation code of a qualified primitive, by the master table's selector rules."""
    return text[:2] if text[:1].isdigit() else text[:1]


def digest_codes(t: Tables) -> set[str]:
    return {c for c, prim in t.primitives.items() if "Digest" in prim.description}


def intrinsic(t: Tables, p: Parsed) -> str | None:
    """Step 1: the reason the message fails in itself, or None."""
    if p.error:
        return p.error
    ilk = p.ilk
    if ilk not in FIELDS or tuple(p.body) != FIELDS[ilk]:
        return "fields"
    if sized(dict(p.body)) != p.raw:
        # A body that is not its own compact serialization (whitespace, escapes, a repeated
        # label) may still carry a correct SAID; whether it is valid is K-I4, so no case grades it.
        raise ScenarioError("A body that is not its own compact JSON serialization is not "
                            "modelled (K-I4).")
    if ilk == "rct":
        return None
    self_addressing = False
    if ilk in INCEPTIONS:
        code = _code(t, p.pre)
        if code in digest_codes(t):
            self_addressing = True
        elif code not in BASIC_CODES:
            raise ScenarioError(f"An inception prefix with code {code!r} is not modelled.")
        elif p.body["k"][:1] != [p.pre]:
            raise ScenarioError("A basic prefix that is not the inception's only key is not "
                                "modelled (K-I3).")
    if self_addressing and p.said != p.pre:
        return "d-i"
    fields = dict(p.body)
    fields["d"] = DUMMY
    if self_addressing:
        fields["i"] = DUMMY
    if digest(t, sized(fields)) != p.said:
        return "said"
    if ilk in INCEPTIONS and p.sn != 0:
        return "inception-sn"
    if ilk not in INCEPTIONS and p.sn == 0:
        return "sn"
    return None


@dataclass
class Record:
    """An event the model has seen."""

    said: str
    ilk: str
    sn: int
    body: dict
    raw: bytes
    wits: list[str]  # effective witness list after this event


@dataclass
class Kel:
    trunk: list[Record] = field(default_factory=list)
    seen: dict[str, Record] = field(default_factory=dict)

    def est_before(self, sn: int) -> Record:
        """The latest establishment event on the trunk below ``sn``."""
        # The trunk starts with an inception, so there is always one for sn >= 1.
        return next(r for r in reversed(self.trunk[:sn]) if r.ilk in ESTABLISHMENT)


@dataclass
class Outcome:
    state: str  # seen, kept, dropped
    step: int
    reason: str

    @property
    def tag(self) -> str:
        return f"{self.step}/{self.reason}"


class Model:
    """``order`` lists message indices in the order kept messages are re-evaluated at each
    quiescence (unlisted ones follow in delivery order). ``recovery`` is whether the validator
    accepts a superseding rotation that rule A0 permits: accepting one is only SHOULD, so a
    validator that declines is a validator the MUST assertions must also hold for."""

    def __init__(self, t: Tables, policy: str, order: tuple[int, ...] = (),
                 recovery: bool = True):
        if policy not in POLICIES:
            raise ScenarioError(f"Unknown keep policy {policy!r}.")
        self.t = t
        self.policy = policy
        self.order = tuple(order)
        self.recovery = recovery
        self.kels: dict[str, Kel] = {}
        self.parsed: list[Parsed] = []
        self.state: list[str] = []  # per message: seen, kept, dropped
        self.outcome: list[Outcome] = []
        self.initial: list[Outcome] = []

    # -- helpers -------------------------------------------------------------------------------

    def _digest(self, text: str) -> str:
        return digest(self.t, text.encode("ascii"))

    def _live(self, said: str) -> list[int]:
        """Messages for the event ``said`` that are seen or kept: their signatures pool."""
        return [i for i, p in enumerate(self.parsed)
                if p.said == said and self.state[i] in ("seen", "kept")]

    def _signers(self, p: Parsed, keys: list[str], extra: list[int]) -> list[Sig]:
        sigs = list(p.sigs)
        for i in extra:
            if self.parsed[i] is not p and self.parsed[i].ilk != "rct":
                sigs.extend(self.parsed[i].sigs)
        return [s for s in sigs if s.index < len(keys)
                and verify(qb64_raw(keys[s.index]), p.raw, s.raw)]

    def _witness_sigs(self, p: Parsed, wits: list[str], extra: list[int]) -> set[int]:
        wigs = list(p.wigs)
        for i in extra:
            if self.parsed[i] is not p:
                wigs.extend(self.parsed[i].wigs)
        good = set()
        for index, raw in wigs:
            if index < len(wits) and verify(qb64_raw(wits[index]), p.raw, raw):
                good.add(index)
        for prefix, raw in [c for i in [*extra] for c in self.parsed[i].couples] + p.couples:
            if prefix in wits:
                raise ScenarioError("A receipt couple from a witness is not modelled (G21).")
        return good

    def _receipts_for(self, said: str) -> list[int]:
        return [i for i, p in enumerate(self.parsed)
                if p.ilk == "rct" and p.said == said and self.state[i] in ("seen", "kept")]

    def _delegator(self, p: Parsed, kel: Kel | None) -> str | None:
        """The delegator whose seal an event needs. A delegation seals establishment events
        only, "Either an inception or rotation" (line 1616), so a delegatee's interaction has
        none."""
        if p.ilk == "dip":
            return p.body["di"]
        if p.ilk == "drt" and kel and kel.trunk and kel.trunk[0].ilk == "dip":
            return kel.trunk[0].body["di"]
        return None

    def _anchored(self, p: Parsed, delegator: str) -> bool:
        dkel = self.kels.get(delegator)
        seal = {"i": p.pre, "s": p.body["s"], "d": p.said}
        return bool(dkel) and any(seal in r.body.get("a", []) for r in dkel.trunk)

    # -- the procedure -------------------------------------------------------------------------

    def evaluate(self, index: int) -> Outcome:
        p = self.parsed[index]
        reason = intrinsic(self.t, p)
        if reason:
            return Outcome("dropped", 1, reason.split(":")[0])
        if p.ilk == "rct":
            return self._receipt(p)
        kel = self.kels.get(p.pre)
        if kel and p.said in kel.seen:
            return Outcome("seen", 6, "already-seen")
        # Step 2.
        if not p.sigs:
            return Outcome("dropped", 2, "unsigned")
        keys = self._keys(p, kel)
        pool = self._live(p.said)
        verified = None if keys is None else self._signers(p, keys, pool)
        if verified is not None and not verified:
            return Outcome("dropped", 2, "unverified")
        # Step 3.
        forbidden = self._forbidden(p, kel)
        if forbidden:
            return Outcome("dropped", 3, forbidden)
        # Step 5, the part that needs no signatures: a rotation at a location the trunk already
        # holds, which rule A0 does not permit to supersede, is discarded (line 1823) however
        # it is signed, so it never waits as a threshold shortfall.
        if (p.ilk in ROTATIONS and kel and p.sn < len(kel.trunk)
                and kel.trunk[p.sn].said != p.said and not self._may_supersede(p, kel)):
            return Outcome("dropped", 5, "supersede-refused")
        # Step 4.
        waiting = self._not_yet(p, kel, keys, verified, pool)
        if waiting:
            keep = self.policy == "all" or (self.policy == "thresholds"
                                            and waiting in THRESHOLD_REASONS)
            return Outcome("kept" if keep else "dropped", 4, waiting)
        # Step 5.
        if kel and p.sn < len(kel.trunk):
            return self._conflict(p, kel)
        # Step 6.
        self._accept(p, kel)
        return Outcome("seen", 6, "accepted")

    def _keys(self, p: Parsed, kel: Kel | None) -> list[str] | None:
        """The signing keys a signature on ``p`` indexes into, if the validator holds them. An
        establishment event's signatures index into its own keys. An interaction's index into
        the keys of the latest establishment event on its own prior chain, "when the event was
        issued" (line 1737), whether or not that chain is the trunk; if its prior has not been
        seen, the validator does not hold that state."""
        if p.ilk in ESTABLISHMENT:
            return p.body["k"]
        prior = kel.seen.get(p.body["p"]) if kel else None
        if prior is None or prior.sn != p.sn - 1:
            return None
        while prior.ilk not in ESTABLISHMENT:
            prior = kel.seen[prior.body["p"]]  # a seen event's prior is always seen
        return prior.body["k"]

    def _may_supersede(self, p: Parsed, kel: Kel) -> bool:
        """Rule A0: a rotation may supersede an interaction that lies before no other rotation.
        Rules B and C, for a delegated rotation superseding one, are not modelled."""
        if p.ilk == "drt" and kel.trunk[p.sn].ilk == "drt":
            raise ScenarioError("Superseding a delegated rotation (rules B, C) is not modelled.")
        return all(r.ilk == "ixn" for r in kel.trunk[p.sn:])

    def _forbidden(self, p: Parsed, kel: Kel | None) -> str | None:
        if kel and kel.trunk and p.ilk not in INCEPTIONS:
            for r in kel.trunk:
                if r.ilk in ESTABLISHMENT and not r.body["n"] and r.sn < p.sn:
                    return "nontransferable" if r.ilk in INCEPTIONS else "abandoned"
            if p.ilk == "ixn" and "EO" in kel.trunk[0].body["c"]:
                return "establishment-only"
        delegator = self._delegator(p, kel)
        if delegator:
            dkel = self.kels.get(delegator)
            if dkel and dkel.trunk and "DND" in dkel.trunk[0].body["c"]:
                return "do-not-delegate"
        return None

    def _wits_at(self, p: Parsed, kel: Kel | None) -> list[str]:
        if p.ilk in INCEPTIONS:
            return p.body["b"]
        prior = kel.trunk[p.sn - 1].wits
        if p.ilk not in ROTATIONS:
            return prior
        remaining = [w for w in prior if w not in p.body["br"]]
        return remaining + [w for w in p.body["ba"] if w not in remaining]

    def _not_yet(self, p, kel, keys, verified, pool) -> str | None:
        if p.ilk not in INCEPTIONS:
            if not kel or p.sn > len(kel.trunk):
                return "out-of-order"
            if p.body["p"] != kel.trunk[p.sn - 1].said:
                return "prior-digest"
        indices = {s.index for s in verified}
        if p.ilk in ROTATIONS:
            est = kel.est_before(p.sn)
            prior_n, prior_nt = est.body["n"], est.body["nt"]
            exposed = {j for j, d in enumerate(prior_n)
                       if any(self._digest(k) == d for k in p.body["k"])}
            if not prior_n or not satisfies(prior_nt, exposed, len(prior_n)):
                return "pre-rotation"
            ondexes = {s.ondex for s in verified if s.ondex is not None
                       and s.ondex < len(prior_n)
                       and self._digest(keys[s.index]) == prior_n[s.ondex]}
            if not satisfies(prior_nt, ondexes, len(prior_n)):
                return "signing-threshold"
            if not satisfies(p.body["kt"], indices, len(keys)):
                return "signing-threshold"
        else:
            kt = p.body["kt"] if p.ilk in INCEPTIONS else kel.est_before(p.sn).body["kt"]
            if not satisfies(kt, indices, len(keys)):
                return "signing-threshold"
        wits = self._wits_at(p, kel)
        if p.ilk in ROTATIONS:
            old = kel.trunk[p.sn - 1].wits
            for index, _ in p.wigs:
                if index >= len(old) or old[index] != wits[index]:
                    raise ScenarioError("Witness signatures on a rotation that changes the "
                                        "witness at their index are not modelled (G12).")
        bt = p.body["bt"] if p.ilk in ESTABLISHMENT else kel.est_before(p.sn).body["bt"]
        good = self._witness_sigs(p, wits, pool + self._receipts_for(p.said))
        if len(good) < int(bt, 16):
            return "witness-threshold"
        delegator = self._delegator(p, kel)
        if delegator and not self._anchored(p, delegator):
            return "delegation"
        return None

    def _conflict(self, p: Parsed, kel: Kel) -> Outcome:
        if p.ilk in ROTATIONS:  # one A0 permits: refusals were decided before step 4
            if not self.recovery:
                return Outcome("dropped", 5, "recovery-declined")
            self._accept(p, kel)
            return Outcome("seen", 5, "supersedes")
        return Outcome("dropped", 5, "conflict")

    def _accept(self, p: Parsed, kel: Kel | None) -> None:
        if kel is None:
            kel = self.kels[p.pre] = Kel()
        wits = self._wits_at(p, kel)
        record = Record(p.said, p.ilk, p.sn, p.body, p.raw, wits)
        kel.trunk = kel.trunk[:p.sn] + [record]
        kel.seen[p.said] = record

    def _receipt(self, p: Parsed) -> Outcome:
        kel = self.kels.get(p.pre)
        if kel and p.said in kel.seen:
            return Outcome("seen", 6, "receipt")
        if any(q.said == p.said and q.ilk != "rct" and self.state[i] == "kept"
               for i, q in enumerate(self.parsed)):
            return Outcome("kept", 4, "receipt")
        if self.policy == "all":
            raise ScenarioError("A receipt for an event the validator does not hold is not "
                                "modelled (G4).")
        return Outcome("dropped", 4, "receipt")

    # -- delivery and quiescence ---------------------------------------------------------------

    def deliver(self, stream: bytes) -> None:
        index = len(self.parsed)
        self.parsed.append(parse(self.t, stream))
        self.state.append("kept")  # provisionally, so that its own signatures pool
        self.outcome.append(Outcome("kept", 0, "delivered"))
        self._settle(index)
        self._quiesce()
        self.initial.append(self.outcome[index])

    def _settle(self, index: int) -> bool:
        before = (self.state[index], self.outcome[index].tag)
        out = self.evaluate(index)
        self.outcome[index] = out
        self.state[index] = out.state
        if out.state == "dropped" and out.step in VERSION_STEPS:
            # Steps 1, 3 and 5 refuse the event version, not one copy of it: every kept copy of
            # the same event is refused with it, whatever signatures it carries.
            said = self.parsed[index].said
            for i, p in enumerate(self.parsed):
                if i != index and p.said == said and p.ilk != "rct" and self.state[i] == "kept":
                    self.state[i], self.outcome[i] = "dropped", out
        return (out.state, out.tag) != before

    def _quiesce(self) -> None:
        n = len(self.parsed)
        sequence = [i for i in self.order if i < n] + [i for i in range(n) if i not in self.order]
        changed = True
        while changed:
            changed = False
            for i in sequence:
                if self.state[i] == "kept" and self._settle(i):
                    changed = True

    # -- readings ------------------------------------------------------------------------------

    def on_trunk(self, index: int) -> bool:
        p = self.parsed[index]
        kel = self.kels.get(p.pre)
        return (p.ilk != "rct" and kel is not None and p.sn < len(kel.trunk)
                and kel.trunk[p.sn].said == p.said)

    def key_state(self, pre: str) -> dict:
        kel = self.kels[pre]
        last = kel.trunk[-1]
        est = kel.est_before(len(kel.trunk))
        return {"sn": last.sn, "said": last.said, "keys": est.body["k"], "kt": est.body["kt"],
                "ndigs": est.body["n"], "nt": est.body["nt"], "wits": last.wits,
                "bt": est.body["bt"], "delegator": kel.trunk[0].body.get("di")}


def run(t: Tables, streams: list[bytes], policy: str, order: tuple[int, ...] = (),
        recovery: bool = True) -> Model:
    model = Model(t, policy, order, recovery)
    for s in streams:
        model.deliver(s)
    return model
