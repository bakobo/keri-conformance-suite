"""Build exchange-message cases (``exn.verify``) from scenarios, and grade them.

Exchange messages are KERI messages, so their cases are KERI cases in the ``keri-1.0`` profile
(docs/design.md, IPEX). Everything here follows the KERI specification v1.0.1
(``spec_source.KERI``), reusing the key-event machinery of ``keri_events`` and ``keri_model``:

- **Bodies** are KERI 2.XX JSON field maps with their top-level fields in the order the
  specification gives: ``xip`` ``[v, t, d, u, i, ri, dt, r, q, a]`` (line 1154) and ``exn``
  ``[v, t, d, i, ri, x, p, dt, r, q, a]`` (line 1197), serialized as compact JSON, with the SAID
  computed by the CESR SAID protocol. An ``xip``'s nonce ``u`` is a 128-bit salt (code ``0A``)
  fixed by the scenario's label.
- **Attachments** are one CESR 2.00 attachments group ``-C`` holding one transferable indexed
  signature group ``-X`` per signer: the signer's prefix, the sequence number and SAID of the
  signer's latest establishment event in the scenario, and its controller-indexed signatures
  (``-K``). That is the "event reference in the attachment group" of line 1260.
- **KELs** are the parties' key events, built and signed by ``keri_events`` and delivered first.

The model validator applies the exchange-message decision procedure of docs/design.md (IPEX) to
the exact bytes a case delivers, never to the scenario's labels:

1. intrinsic failure: the stream does not parse as one message, its fields are not exactly the
   set and order of line 1154 or 1197, or its SAID does not verify;
2. no verifiable sender signature: no signature group, none by the sender (the AID in ``i``),
   or none of the sender's groups satisfies the signing threshold of the establishment event it
   references;
3. a broken transaction link: an ``x`` that names no exchange inception the validator holds
   (either nothing it holds, or a message it accepted that is not an ``xip``), or a ``p`` that is
   not the SAID of the message before it in the transaction its ``x`` names, membership being by
   ``x`` (line 979);
4. otherwise accepted.

Steps 1 and 2 are graded MUST, step 3 SHOULD inferred from the sender rules (lines 975 and 979),
and acceptance SHOULD inferred (liveness). The model keeps nothing for later, so a message's
reading on delivery is also its final one; a scenario in which a later delivery could cure an
earlier refusal, or that needs anything else the model does not decide, is refused rather than
guessed at.
"""

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime

from . import encoding, keri_model
from .decoding import Parser, Rejected
from .errors import ScenarioError
from .keri_build import (
    BASE_FEATURES,
    GENERATOR_NAME,
    GENERATOR_VERSION,
    SCHEMA_VERSION,
    _Assertions,
    _features,
)
from .keri_events import (
    DUMMY,
    ESTABLISHMENT,
    GENUS_CODE,
    WIRE,
    EventBuilder,
    digest,
    label_digest,
    signature,
    sized,
)
from .tables import Tables

FIELDS = {
    "xip": ("v", "t", "d", "u", "i", "ri", "dt", "r", "q", "a"),
    "exn": ("v", "t", "d", "i", "ri", "x", "p", "dt", "r", "q", "a"),
}
# Every exchange-message case needs the KERI base features and whatever its KELs need.
FEATURES_BASE = BASE_FEATURES
DEFAULT_DT = "2025-07-04T17:50:00.000000+00:00"
# KERI line 983: "the ISO-8601 datetime string with microseconds and UTC offset as per IETF
# RFC-3339", as in its example `2020-08-22T17:50:09.988921+00:00`. The pattern fixes the shape;
# ``datetime.fromisoformat`` then refuses a date, time or offset that does not exist.
DATETIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}[+-]\d{2}:\d{2}")
# Where a delivery's signature groups go: after the body they attach to, or, for a scenario that
# shows they then authenticate nothing, before it.
PLACEMENTS = ("after-body", "before-body")
ACCEPTED = "accepted"
# The clause and inference that grade each refusal (docs/design.md, IPEX). A field-set refusal
# cites the field order of its message type, graded MUST through line 1737, which counts "the
# appearance of fields" as structure a verifier checks.
REASON_CLAUSES = {
    "unparseable": ("act-as-verifier", None),
    "said": ("act-as-verifier", None),
    "fields": (None, None),
    "unsigned": ("drop-unsigned", None),
    "not-sender": ("drop-unsigned", None),
    "unverified": ("nonkey-threshold", None),
    "prior": ("exn-prior", "exn-prior-link"),
    "exchange-id": ("exn-x", "exn-x-link"),
    "no-xip": ("exn-x-empty", "exn-lone"),
    ACCEPTED: ("nonkey-threshold", "exn-liveness"),
}
FIELD_CLAUSES = {"xip": "xip-fields", "exn": "exn-fields"}
NOTES = {
    "fields": " Graded MUST because a validator must first act as a verifier, and verifying a "
              "message's structure includes the appearance of fields (line 1737).",
    "said": " The SAID is checked as the CESR SAID verification protocol requires (CESR "
            "specification v1.0, line 1194); line 1737 counts it as structure a verifier checks.",
    "not-sender": " The only signature group is another identifier's, naming that identifier's "
                  "own establishment event; it is not a signature by the sender, the AID in `i` "
                  "(lines 1266 and 1737; generators/SPEC-ISSUES.md, K-G8).",
}


# --- Building ---------------------------------------------------------------------------------


@dataclass
class Exchange:
    name: str
    ilk: str
    said: str
    body: dict
    raw: bytes


@dataclass
class Message:
    stream: bytes
    source: str


def well_formed_dt(dt) -> bool:
    """KERI line 983 by way of RFC 3339: the offset's hour is 00-23 and its minute 00-59, which
    is checked here because ``datetime.fromisoformat`` normalizes an offset minute of 60."""
    if not isinstance(dt, str) or not DATETIME.fullmatch(dt):
        return False
    if int(dt[-5:-3]) > 23 or int(dt[-2:]) > 59:
        return False
    try:
        datetime.fromisoformat(dt)
    except ValueError:
        return False
    return True


def nonce(t: Tables, label: str) -> str:
    return encoding.primitive(t, "0A", hashlib.shake_256(f"kcs-exn-nonce/{label}".encode())
                              .digest(16))


class ExchangeBuilder:
    """Builds a case's exchange messages, each once and in scenario order, over the key events
    of its KELs."""

    def __init__(self, t: Tables, events: list[dict], exchanges: list[dict]):
        self.t = t
        self.events = EventBuilder(t, events)
        self.specs = events
        self.built: dict[str, Exchange] = {}
        for spec in exchanges:
            if spec["name"] in self.built:
                raise ScenarioError(f"Exchange {spec['name']!r} is defined twice.")
            self.built[spec["name"]] = self._build(spec)

    def _resolve(self, value):
        """A one-key map names something: ``said`` an earlier exchange's SAID, ``aid`` an
        identifier's prefix, ``nothing`` a digest of nothing. Anything else is taken as is."""
        if isinstance(value, dict) and len(value) == 1 and next(iter(value)) in ("said", "aid",
                                                                                 "nothing"):
            kind, name = next(iter(value.items()))
            if kind == "aid":
                return self.events.prefix(name)
            if kind == "nothing":
                return label_digest(self.t, name)
            if name not in self.built:
                raise ScenarioError(f"{value!r} names no earlier exchange.")
            return self.built[name].said
        if isinstance(value, dict):
            return {k: self._resolve(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self._resolve(v) for v in value]
        return value

    def _build(self, spec: dict) -> Exchange:
        ilk = spec["t"]
        if ilk not in FIELDS:
            raise ScenarioError(f"Exchange {spec['name']!r}: {ilk!r} is not an exchange message "
                                f"type (xip or exn).")
        fields = {k: None for k in FIELDS[ilk]}
        fields["t"] = ilk
        fields["d"] = DUMMY
        if ilk == "xip":
            fields["u"] = nonce(self.t, spec["nonce"])
        fields["i"] = self.events.prefix(spec["sender"])
        fields["ri"] = self.events.prefix(spec["receiver"])
        if ilk == "exn":
            fields["x"] = self._resolve(spec["x"])
            fields["p"] = self._resolve(spec["p"])
        fields["dt"] = spec.get("dt", DEFAULT_DT)
        fields["r"] = spec["r"]
        fields["q"] = self._resolve(spec["q"])
        fields["a"] = self._resolve(spec["a"])
        fields.update(self._resolve(spec.get("extra", {})))  # fields the type does not allow
        said = digest(self.t, sized(fields))
        fields["d"] = said
        fields.update(spec.get("tamper", {}))  # changed after the SAID was computed
        raw = sized(fields)
        return Exchange(spec["name"], ilk, said, dict(fields), raw)

    def _latest_establishment(self, aid: str):
        names = [s["name"] for s in self.specs
                 if s["aid"] == aid and s["t"] in ESTABLISHMENT]
        if not names:
            raise ScenarioError(f"Signer {aid!r} has no establishment event.")
        return self.events.event(names[-1])

    def _group(self, ex: Exchange, group: dict) -> str:
        est = self._latest_establishment(group["aid"])
        sigs = []
        for sig in group["keys"]:
            sig = {"key": sig} if isinstance(sig, str) else sig
            key = sig["key"]
            if "index" in sig:
                index = sig["index"]
            elif key in est.keys:
                index = est.keys.index(key)
            else:
                raise ScenarioError(f"{ex.name}: {key!r} is not one of the signing keys of "
                                    f"{group['aid']!r}.")
            signer = f"{key}/forged" if sig.get("forged") else key
            sigs.append(encoding.indexed(self.t, "A", signature(signer, ex.raw), index))
        sn = encoding.primitive(self.t, "0A", est.sn.to_bytes(16, "big"))
        kgroup = self.events._group("-K", sigs)
        return self.events._group("-X", [est.pre, sn, est.said, kgroup])

    def message(self, delivery: dict) -> Message:
        name = delivery["exchange"]
        if name not in self.built:
            raise ScenarioError(f"No exchange is named {name!r}.")
        ex = self.built[name]
        placement = delivery.get("placement", "after-body")
        if placement not in PLACEMENTS:
            raise ScenarioError(f"{name}: {placement!r} is not a signature placement "
                                f"({', '.join(PLACEMENTS)}).")
        if placement == "before-body" and f"4/{ACCEPTED}" in (delivery.get("expect") or []):
            raise ScenarioError(f"{name}: signatures placed before the body attach to nothing, "
                                f"so only a refusal scenario may place them there.")
        groups = [self._group(ex, g) for g in delivery.get("sigs", [])]
        attachments = (self.events._group("-C", groups) if groups else "").encode()
        if placement == "before-body":
            return Message(GENUS_CODE.encode() + attachments + ex.raw,
                           delivery.get("source", "sender"))
        return Message(GENUS_CODE.encode() + ex.raw + attachments,
                       delivery.get("source", "sender"))

    def kel_message(self, delivery: dict) -> Message:
        m = self.events.message(delivery)
        return Message(m.stream, m.source)


# --- The model --------------------------------------------------------------------------------


@dataclass
class Group:
    pre: str
    sn: int
    said: str
    sigs: list = field(default_factory=list)


@dataclass
class Parsed:
    error: str | None = None
    body: dict = field(default_factory=dict)
    raw: bytes = b""
    groups: list[Group] = field(default_factory=list)
    other: bool = False  # an attachment other than signature groups

    @property
    def said(self):
        return self.body.get("d")


def _not_json(name: str):
    raise ValueError(f"{name} is not JSON")


def parse(t: Tables, stream: bytes) -> Parsed:
    """The message and the signature groups attached to it. Attachments follow the body they
    attach to: only the attachments group immediately after the body is read, and anything
    before the body or after that group authenticates nothing."""
    try:
        items = Parser(t).parse(stream)
    except Rejected as e:
        return Parsed(error=f"unparseable: {e}")
    at = [i for i, it in enumerate(items) if it["kind"] == "message"]
    if len(at) != 1:
        return Parsed(error="unparseable: not exactly one message")
    m = items[at[0]]
    raw = stream[m["start"]:m["end"]]
    try:
        body = json.loads(raw, parse_constant=_not_json)
    except ValueError:
        return Parsed(error="unparseable: the body is not JSON")
    p = Parsed(body=body, raw=raw)
    after = items[at[0] + 1:]
    if not after or after[0]["kind"] != "counter" or after[0]["code"] != "-C":
        return p
    end = after[0]["group_end"]
    group, prims = None, []
    for it in after:
        if it["start"] >= end:
            break
        if it["kind"] == "counter" and it["code"] == "-X":
            group, prims = Group("", 0, ""), []
            p.groups.append(group)
        elif it["kind"] == "counter" and it["code"] in ("-C", "-K"):
            continue
        elif it["kind"] == "genus" and it["start"] == after[0]["end"]:
            continue  # a genus/version override leading the group, as CESR permits
        elif it["kind"] == "primitive" and group is not None and len(prims) < 3:
            prims.append(it)
            if len(prims) == 3:  # the signer's prefix, its event's sequence number and SAID
                pre, sn, said = prims
                group.pre = encoding.primitive(t, pre["code"], bytes.fromhex(pre["raw"]))
                group.sn = int(sn["raw"], 16)
                group.said = encoding.primitive(t, said["code"], bytes.fromhex(said["raw"]))
        elif it["kind"] == "indexed" and group is not None:
            group.sigs.append(keri_model.Sig(it["code"], it["index"], it.get("ondex"),
                                             bytes.fromhex(it["raw"])))
        else:
            p.other = True
    return p


def intrinsic(t: Tables, p: Parsed) -> str | None:
    """Step 1: the reason the message fails in itself, or None."""
    if p.error:
        return "unparseable"
    ilk = p.body.get("t")
    if ilk not in FIELDS:
        raise ScenarioError(f"A message of type {ilk!r} is not an exchange message.")
    if tuple(p.body) != FIELDS[ilk]:
        return "fields"
    if sized(dict(p.body)) != p.raw:
        raise ScenarioError("A body that is not its own compact JSON serialization is not "
                            "modelled (K-I4).")
    fields = dict(p.body)
    fields["d"] = DUMMY
    if digest(t, sized(fields)) != p.said:
        return "said"
    return None


@dataclass
class Outcome:
    state: str  # accepted or rejected
    step: int
    reason: str

    @property
    def tag(self) -> str:
        return f"{self.step}/{self.reason}"


class Model:
    def __init__(self, t: Tables, kel_streams: list[bytes]):
        self.t = t
        kel = keri_model.run(t, kel_streams, "none")
        for i, out in enumerate(kel.outcome):
            if out.state != "seen":
                raise ScenarioError(f"KEL message {i} is not accepted by the KERI model "
                                    f"({out.tag}); exchange-message cases deliver valid KELs.")
        self.kel = kel
        self.parsed: list[Parsed] = []
        self.initial: list[Outcome] = []
        self.accepted: set[str] = set()
        self.transactions: dict[str, list[str]] = {}  # xip SAID -> SAIDs in order

    def _signed(self, p: Parsed) -> str | None:
        """Step 2: the reason no sender signature verifies, or None."""
        if not p.groups:
            return "unsigned"
        sender = p.body["i"]
        mine = [g for g in p.groups if g.pre == sender]
        if not mine:
            return "not-sender"
        if len(mine) != len(p.groups):
            raise ScenarioError("Signature groups by another AID beside the sender's are not "
                                "modelled.")
        kel = self.kel.kels.get(sender)
        if kel is None:
            raise ScenarioError("A message whose sender's KEL was not delivered is not "
                                "modelled.")
        if sum(r.ilk in ESTABLISHMENT for r in kel.trunk) != 1:
            raise ScenarioError("A message from an identifier whose KEL has rotated is not "
                                "modelled.")
        for g in mine:
            est = kel.seen.get(g.said)
            if est is None or est.sn != g.sn or est.ilk not in ESTABLISHMENT:
                raise ScenarioError("A signature group naming an establishment event the "
                                    "validator does not hold is not modelled.")
            keys = est.body["k"]
            good = {s.index for s in g.sigs if s.index < len(keys)
                    and keri_model.verify(keri_model.qb64_raw(keys[s.index]), p.raw, s.raw)}
            if keri_model.satisfies(est.body["kt"], good, len(keys)):
                return None
        return "unverified"

    def _linked(self, p: Parsed) -> str | None:
        """Step 3: the reason the message's transaction link is broken, or None."""
        if p.body["t"] == "xip":
            return None
        x, prior = p.body["x"], p.body["p"]
        if x == "":
            if prior != "":
                raise ScenarioError("A message outside a transaction with a non-empty prior "
                                    "is not modelled.")
            return None
        chain = self.transactions.get(x)
        if chain is None:
            # x names an accepted message that is not an xip: under either reading of which
            # transaction the message continues, x is not its first message's SAID.
            return "exchange-id" if x in self.accepted else "no-xip"
        # Membership is by x (line 979: x "universally uniquely associates" a message with its
        # transaction), so a p that is not the last message of x's transaction breaks line 975.
        if prior == chain[-1]:
            return None
        return "prior"

    def evaluate(self, p: Parsed) -> Outcome:
        reason = intrinsic(self.t, p)
        if reason:
            return Outcome("rejected", 1, reason)
        if p.said in self.accepted:
            raise ScenarioError("A second delivery of an accepted message is not modelled.")
        if p.other:
            raise ScenarioError("Attachments other than signature groups (such as a source "
                                "seal) are not modelled.")
        reason = self._signed(p)
        if reason:
            return Outcome("rejected", 2, reason)
        reason = self._linked(p)
        if reason:
            return Outcome("rejected", 3, reason)
        if not well_formed_dt(p.body["dt"]):
            raise ScenarioError(f"The message's dt {p.body['dt']!r} is not an RFC-3339 datetime "
                                f"with microseconds and a UTC offset (KERI line 983); the model "
                                f"does not grade dt, so it does not call the message accepted.")
        self.accepted.add(p.said)
        if p.body["t"] == "xip":
            self.transactions[p.said] = [p.said]
        elif p.body["x"]:
            self.transactions[p.body["x"]].append(p.said)
        return Outcome("accepted", 4, ACCEPTED)

    def deliver(self, stream: bytes) -> None:
        p = parse(self.t, stream)
        self.parsed.append(p)
        self.initial.append(self.evaluate(p))

    @property
    def outcome(self) -> list[Outcome]:
        """The readings after the last message. The model keeps nothing, so they are the
        readings on delivery; ``run`` refuses a scenario where a later delivery could change one."""
        return list(self.initial)


def run(t: Tables, kel_streams: list[bytes], streams: list[bytes]) -> Model:
    model = Model(t, kel_streams)
    for s in streams:
        model.deliver(s)
    for i, out in enumerate(model.initial):
        if out.reason in ("no-xip", "prior"):
            body = model.parsed[i].body
            named = body["x"] if out.reason == "no-xip" else body["p"]
            if any(q.said == named for q in model.parsed[i + 1:]):
                raise ScenarioError(f"Message {i}'s refusal could be cured by a later delivery "
                                    f"of the message it names, which a validator that keeps "
                                    f"it may accept; that is not modelled.")
    return model


# --- Grading ----------------------------------------------------------------------------------


def build_exn_case(t, scenario_path: str, case: dict, clauses: dict, inferences: dict,
                   conflicts: dict, normative: bool) -> list[dict]:
    cid = case["id"]
    if not normative:
        raise ScenarioError(f"{cid}: exchange-message cases are normative only.")
    xb = ExchangeBuilder(t, case["events"], case["exchanges"])
    kels = [xb.kel_message(k) for k in case["kels"]]
    messages = [xb.message(m) for m in case["messages"]]
    model = run(t, [k.stream for k in kels], [m.stream for m in messages])
    out = _Assertions(cid, clauses, inferences, conflicts)
    for i, d in enumerate(case["messages"]):
        got = [model.initial[i].tag, model.outcome[i].tag]
        if d.get("expect") != got:
            raise ScenarioError(f"{cid}: message {i} is expected to reach {d.get('expect')}, but "
                                f"the decision procedure gives {got}.")
        o = model.initial[i]
        if o.reason not in REASON_CLAUSES:
            raise ScenarioError(f"No clause grades a refusal for {o.reason!r}.")
        clause, inferred = REASON_CLAUSES[o.reason]
        if o.reason == "fields":
            clause = FIELD_CLAUSES[model.parsed[i].body["t"]]
        note = f"Decision procedure step {o.step} ({o.reason}).{NOTES.get(o.reason, '')}"
        out.add("exn_verdict", clause, inferred, note=note, message=i,
                expected="accepted" if o.state == "accepted" else "rejected")
    result = {
        "schema_version": SCHEMA_VERSION,
        "id": cid,
        "title": case["title"],
        "description": case["description"],
        "status": case.get("status", "active"),
        "profile": case["profile"],
        "targets": {"wire": ["CESR-2.00", WIRE], "features": _features(model.kel, None, set())},
        "operation": "exn.verify",
        "input": {
            "perspective": {"role": "validator"},
            "kels": [{"stream": k.stream.hex(), "source": k.source} for k in kels],
            "messages": [{"stream": m.stream.hex(), "source": m.source} for m in messages],
        },
        "assertions": out.numbered(),
        "provenance": {
            "scenario": f"{scenario_path}#{case['key']}",
            "generator": {"name": GENERATOR_NAME, "version": GENERATOR_VERSION},
            "reference": None,
        },
    }
    if "dispute" in case:
        d = case["dispute"]
        result["dispute"] = {"clauses": [clauses[k][1] for k in d["clauses"]],
                             "summary": d["summary"], "raised_at": d["raised_at"]}
    return [result]
