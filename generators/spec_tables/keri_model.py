"""A model validator that applies docs/design.md's KERI decision procedure to delivered streams.

The generator does not take any implementation's word for a disposition. It runs this model over
the exact bytes a case delivers, and the model decides each message's readings by the first step
of the procedure that applies:

1. intrinsic failure (the stream does not parse, the type is not a key event's, the fields are
   not the type's, the SAID does not match by the algorithm its own code names, an inception's ``d`` and ``i`` differ, a sequence
   number is out of range, a key list is empty, a backer list repeats an AID or names a
   transferable witness, an inception's backer threshold exceeds its backer list, a rotation
   carries an inception-only configuration trait);
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
import re
from dataclasses import dataclass, field
from fractions import Fraction
from functools import cache

from . import b64, digests, ed25519, encoding
from .decoding import Parser, Rejected
from .errors import ScenarioError
from .keri_events import DUMMY, ESTABLISHMENT, INCEPTIONS, ROTATIONS, V2, Wire, sized, wire_of
from .tables import Tables

POLICIES = ("all", "thresholds", "none")
THRESHOLD_REASONS = ("signing-threshold", "witness-threshold")
# Steps 3 and 5 judge an event version whose SAID step 1 has verified, so their refusal covers
# every copy of it. A step-1 failure names no version: its claimed SAID is the thing that failed.
VERSION_STEPS = (3, 5)
CANONICAL_HEX = re.compile(r"0|[1-9a-f][0-9a-f]*")  # line 323: hex with no leading zeros
BASIC_CODES = ("D", "B")  # transferable and non-transferable Ed25519 prefixes
MAX_SN = 2 ** 128 - 1  # line 323
# The configuration-traits table, lines 369-373. keripy ignores them in a rotation. ~4fsy
INCEPTION_ONLY_TRAITS = ("EO", "DND", "DID")


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
    wire: Wire = V2  # the wire the body's version string selects

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
    """Read one delivery. A stream that starts with a KERI 1.0 body is read with keripy 1.x's
    CESR 1.00 table and no genus/version code (keri_events.V1); any other with genus 2.00."""
    wire = wire_of(stream)
    try:
        items = Parser(t, wire.table).parse(stream)
    except Rejected as e:
        return Parsed(error=f"unparseable: {e}")
    messages = [it for it in items if it["kind"] == "message"]
    if len(messages) != 1:
        return Parsed(error="unparseable: not exactly one message")
    m = messages[0]
    raw = stream[m["start"]:m["end"]]
    body = json.loads(raw)
    p = Parsed(body=body, raw=raw, wire=wire_of(raw))
    if p.wire is not wire or (wire.table is not None
                              and any(it["kind"] == "genus" for it in items)):
        # A body of one KERI version under the other's attachment framing, including a 1.x
        # stream whose genus/version code switches its attachments to 2.00: neither wire this
        # model knows defines it, so it is refused as not modelled rather than graded.
        raise ScenarioError(f"A KERI {p.wire.name} body in a stream framed as {wire.name} is not "
                            f"modelled.")
    kinds = {code: kind for kind, code in wire.groups.items()}
    group, pending = None, []
    for it in items:
        if it["kind"] == "counter":
            group = kinds.get(it["code"])
        elif group == "sigs" and it["kind"] == "indexed":
            ondex = None if it["code"] in ("B", "2B") else it.get("ondex", it["index"])
            p.sigs.append(Sig(it["code"], it["index"], ondex, bytes.fromhex(it["raw"])))
        elif group == "wigs" and it["kind"] == "indexed":
            p.wigs.append((it["index"], bytes.fromhex(it["raw"])))
        elif group in ("couples", "seals") and it["kind"] == "primitive":
            pending.append(it)
            if len(pending) == 2:
                a, b = pending
                pending = []
                if group == "couples":
                    prefix = encoding.primitive(t, a["code"], bytes.fromhex(a["raw"]))
                    p.couples.append((prefix, bytes.fromhex(b["raw"])))
                else:
                    said = encoding.primitive(t, b["code"], bytes.fromhex(b["raw"]))
                    p.seals.append((int(a["raw"], 16), said))
    return p


def _canonical_hex(value) -> bool:
    return isinstance(value, str) and CANONICAL_HEX.fullmatch(value) is not None


def _names(receipt: Parsed, ev: Parsed) -> bool:
    return (receipt.said, receipt.pre, receipt.sn) == (ev.said, ev.pre, ev.sn)


def digest_codes(t: Tables) -> set[str]:
    return {c for c, prim in t.primitives.items() if "Digest" in prim.description}


def intrinsic(t: Tables, p: Parsed) -> str | None:
    """Step 1: the reason the message fails in itself, or None."""
    if p.error:
        return p.error
    ilk = p.ilk
    fields_of = p.wire.fields
    if "t" in p.body and ilk not in fields_of:
        return "ilk"
    if ilk not in fields_of or tuple(p.body) != fields_of[ilk]:
        return "fields"
    if not _canonical_hex(p.body["s"]):
        raise ScenarioError(f"A sequence number of {p.body['s']!r}, which is not hex without "
                            f"leading zeros (line 323), is not modelled.")
    if sized(dict(p.body), p.wire) != p.raw:
        # A body that is not its own compact serialization (whitespace, escapes, a repeated
        # label) may still carry a correct SAID; whether it is valid is K-I4, so no case grades it.
        raise ScenarioError("A body that is not its own compact JSON serialization is not "
                            "modelled (K-I4).")
    if ilk == "rct":
        return None
    self_addressing = False
    if ilk in INCEPTIONS:
        code = digests.code_of(p.pre)
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
    # Recomputed with the algorithm the claimed SAID's own code names (CESR line 1194), so a value
    # computed with another algorithm, or a code no algorithm here computes, does not verify.
    if not digests.verifies(t, p.said, sized(fields, p.wire)):
        return "said"
    if ilk in INCEPTIONS and p.sn != 0:
        return "inception-sn"
    if ilk not in INCEPTIONS and p.sn == 0:
        return "sn"
    if p.sn > MAX_SN:
        return "sn-max"
    if ilk in ESTABLISHMENT:
        return _establishment_values(t, p)
    return None


def _check_bt_modelled(bt) -> None:
    if not _canonical_hex(bt):
        raise ScenarioError(f"A backer threshold of {bt!r}, which is not hex without leading "
                            f"zeros (line 345), is not modelled.")


def _check_witness_code_modelled(code: str) -> None:
    if code not in BASIC_CODES:
        raise ScenarioError(f"A witness prefix with code {code!r} is not modelled.")


def _establishment_values(t: Tables, p: Parsed) -> str | None:
    """The value rules of an establishment event's own body: a key list that is not empty (line
    335), backer lists without repeats of only non-transferable witnesses (lines 353, 1252), an
    inception's backer threshold no larger than its backer list (line 345), and no
    inception-only configuration trait in a rotation (lines 367-373). A rotation's threshold is
    checked against the effective list, which depends on state, at step 4."""
    # A 1.x rotation has no c field (keri_events.V1), so it carries no trait at all.
    traits = p.body.get("c", [])
    if not isinstance(traits, list) or not all(isinstance(x, str) for x in traits):
        raise ScenarioError(f"Configuration traits of {traits!r}, which are not a list of "
                            f"strings (line 367), are not modelled.")
    # First of the value rules: it is the one whose sentence says drop, so a weaker rule failing
    # on the same body must not hide it. Being a MUST, it is graded only on a body whose backer
    # fields the model can read; otherwise the body is refused as not modelled, as below.
    if p.ilk in ROTATIONS and set(traits) & set(INCEPTION_ONLY_TRAITS):
        _check_bt_modelled(p.body["bt"])
        added = p.body["ba"]
        if not isinstance(added, list) or not all(isinstance(x, str) for x in added):
            raise ScenarioError(f"A witness add list of {added!r}, which is not a list of "
                                f"prefixes (line 353), is not modelled.")
        for prefix in added:
            _check_witness_code_modelled(digests.code_of(prefix))
        return "trait-inception-only"
    if not p.body["k"]:
        return "empty-keys"
    _check_bt_modelled(p.body["bt"])
    lists = [p.body["b"]] if p.ilk in INCEPTIONS else [p.body["br"], p.body["ba"]]
    if any(len(set(backers)) != len(backers) for backers in lists):
        return "backer-duplicate"
    for prefix in lists[-1]:
        code = digests.code_of(prefix)
        _check_witness_code_modelled(code)
        if code == "D":
            return "witness-transferable"
    # A rotation's bt above its effective list waits at step 4 as a shortfall instead. ~5y5t
    if p.ilk in INCEPTIONS and int(p.body["bt"], 16) > len(p.body["b"]):
        return "backer-threshold"
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
        self.early: set[int] = set()  # receipts kept before the validator held their event

    # -- helpers -------------------------------------------------------------------------------

    def commits(self, next_digest: str, key: str) -> bool:
        """Whether a next-key digest commits to a qualified key, by the digest's own code."""
        return digests.verifies(self.t, next_digest, key.encode("ascii"))

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

    def _receipts_for(self, ev: Parsed) -> list[int]:
        """Receipts that name ``ev`` by all of its identifier, sequence number and SAID: a
        receipt whose fields disagree with each other names no event."""
        return [i for i, p in enumerate(self.parsed)
                if p.ilk == "rct" and _names(p, ev) and self.state[i] in ("seen", "kept")]

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
                       if any(self.commits(d, k) for k in p.body["k"])}
            if not prior_n or not satisfies(prior_nt, exposed, len(prior_n)):
                return "pre-rotation"
            ondexes = {s.ondex for s in verified if s.ondex is not None
                       and s.ondex < len(prior_n)
                       and self.commits(prior_n[s.ondex], keys[s.index])}
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
        good = self._witness_sigs(p, wits, pool + self._receipts_for(p))
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
        held = kel.seen.get(p.said) if kel else None
        if held is not None:
            # Line 1782: a validator must first verify the receipt's witness signatures, so one
            # that names its event inconsistently, or none of whose signatures verify against
            # that event, attaches nothing.
            if held.sn != p.sn or not (
                    any(index < len(held.wits)
                        and verify(qb64_raw(held.wits[index]), held.raw, raw)
                        for index, raw in p.wigs)
                    or any(verify(qb64_raw(prefix), held.raw, raw) for prefix, raw in p.couples)):
                return Outcome("dropped", 2, "receipt-unverified")
            return Outcome("seen", 6, "receipt")
        if any(q.ilk != "rct" and _names(p, q) and self.state[i] == "kept"
               for i, q in enumerate(self.parsed)):
            return Outcome("kept", 4, "receipt")
        if self.policy == "all":
            # Kept, as line 1286 permits ("can escrow"). It changes nothing unless its event
            # arrives later, and deliver() refuses that case.
            return Outcome("kept", 4, "receipt")
        return Outcome("dropped", 4, "receipt")

    # -- delivery and quiescence ---------------------------------------------------------------

    def deliver(self, stream: bytes) -> None:
        index = len(self.parsed)
        p = parse(self.t, stream)
        if p.ilk != "rct" and any(self.parsed[i].said == p.said for i in self.early
                                  if self.state[i] == "kept"):
            raise ScenarioError("A receipt for an event the validator does not hold is not "
                                "modelled (G4).")
        self.parsed.append(p)
        self.state.append("kept")  # provisionally, so that its own signatures pool
        self.outcome.append(Outcome("kept", 0, "delivered"))
        self._settle(index)
        self._quiesce()
        self.initial.append(self.outcome[index])

    def _settle(self, index: int) -> bool:
        before = (self.state[index], self.outcome[index].tag)
        out = self.evaluate(index)
        p = self.parsed[index]
        if (p.ilk == "rct" and out.state == "kept"
                and not any(q.said == p.said and q.ilk != "rct" for q in self.parsed)):
            self.early.add(index)
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
