"""Cross-check the keripy-1x-interop KERI cases against keripy 1.2.14.

Imported by ``check.py``, which runs it after the CESR cases. keripy is never the authority here: a
disagreement is printed for a maintainer to record in ``generators/DISAGREEMENTS.md``, and it never
changes an expected value. The checks mirror ``generators/keripy_keri_check`` (which does the same
for keripy main and the keri-v1.0.1 cases), on keripy 1.2.14's API:

- **Bytes.** Every key event body a case delivers, and every receipt body, is rebuilt by keripy's
  ``SerderKERI(sad=..., makify=True)`` from its field values, which recomputes the 1.x version
  string and the SAID (and a self-addressing prefix); the result must equal the case's body unless
  the scenario tampered with that event on purpose. Every controller and witness signature keripy's
  ``Parser`` extracts is verified with keripy's ``Verfer``: one the scenario forged, or made over
  another event, must fail, and any other must verify.
- **Dispositions.** The case's messages go, in order, through keripy's ``Parser`` into a fresh
  ``Kevery``, and after each delivery ``Kevery.processEscrows`` runs until keripy's tables stop
  changing. A message reads ``seen`` if keripy recorded a first-seen ordinal for it (``.fons``),
  else ``duplicitous`` if it is in the likely-duplicitous escrow, ``pending`` if it is in the
  out-of-order, partially signed, partially witnessed or partially delegated escrow, and
  ``rejected`` otherwise; its trunk reading is whether it is the last event keripy holds at its
  sequence number, at or below the identifier's current one. Key states come from keripy's
  ``Kever``. The assertions are then evaluated with the runner's own evaluator, so a disagreement
  is what a keripy 1.2.14 adapter that read the same state would be graded on.
"""

import hashlib
import json
import pathlib
import signal
import sys

from keri.core import parsing, serdering
from keri.core.coring import Verfer
from keri.core.eventing import Kevery
from keri.core.signing import Signer
from keri.db import basing, dbing

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from keri_conformance.assertions import evaluate

PROFILE = "keripy-1x-interop"
TIMEOUT_SECONDS = 20
MAX_PASSES = 50
TABLES = ("kels", "fels", "ooes", "pses", "pwes", "ldes", "uwes", "ures", "wigs", "sigs")


class Hang(Exception):
    pass


def _alarm(signum, frame):
    raise Hang(f"no result within {TIMEOUT_SECONDS} seconds")


def body_of(stream: bytes) -> tuple[dict, bytes]:
    serder = serdering.SerderKERI(raw=bytearray(stream), verify=False)  # SAID checked elsewhere
    raw = bytes(stream[:serder.size])
    return json.loads(raw), raw


def scenario_of(case) -> dict:
    path, key = case["provenance"]["scenario"].split("#")
    scenario = json.loads((ROOT / path).read_text())
    return next(c for c in scenario["cases"]
                if key in (c["key"], c.get("companion", {}).get("key")))


class Recorder:
    """Stands in for a Kevery and keeps the signatures keripy's Parser extracted."""

    def __init__(self):
        self.sigers, self.wigers, self.cigars = [], [], []

    def processEvent(self, serder, sigers, wigers=None, **kwa):
        self.sigers, self.wigers = list(sigers), list(wigers or [])

    def processReceiptWitness(self, serder, wigers, **kwa):
        self.wigers = list(wigers)

    def processReceipt(self, serder, cigars, **kwa):
        self.cigars = list(cigars)

    def processAttachedReceiptCouples(self, serder, cigars, **kwa):
        self.cigars = list(cigars)


class EndOfInput(Exception):
    """keripy's parser asked for more bytes after the whole stream was delivered."""


class LeftOver(Exception):
    """keripy's parser finished one message and left part of the stream unread."""


def deliver(kvy, stream: bytes) -> None:
    """Hand one complete stream to keripy's ``Parser.msgParsator``. Its ``parse`` cannot be used:
    it swallows every exception, and after a message with no attachments it waits for more bytes
    forever. The adapter protocol makes the end of a stream final, so a request for more bytes is
    a refusal here (``EndOfInput``), as it is for the CESR cases in ``check.py``."""
    ims = bytearray(stream)
    gen = parsing.Parser(kvy=kvy).msgParsator(ims=ims, framed=True, kvy=kvy)
    try:
        next(gen)
    except StopIteration:
        if ims:  # every case stream holds one message; anything left was never examined
            raise LeftOver(f"keripy 1.2.14's parser left {len(ims)} bytes of the stream unread")
        return
    raise EndOfInput("keripy 1.2.14's parser waits for more bytes after the end of the stream")


def extract(stream: bytes) -> Recorder:
    """keripy's own extraction of one message's controller and witness signatures."""
    rec = Recorder()
    deliver(rec, stream)
    return rec


def _verfer(label: str, transferable: bool) -> Verfer:
    """The verifier of a scenario key label, derived by keripy from the seed the suite's builder
    uses, so that a signature's source is checked without the builder's own Ed25519."""
    seed = hashlib.shake_256(f"kcs-keri-seed/{label}".encode()).digest(32)
    return Signer(raw=seed, transferable=transferable).verfer


def _breaks_body(tamper: dict) -> bool:
    fields = tamper.get("fields", {})
    return bool({"d", "i", "said_digest"} & set(tamper) or {"add", "remove", "swap"} & set(fields)
                or "t" in fields.get("set", {}))


def _bad(sig) -> bool:
    return isinstance(sig, dict) and bool(sig.get("forged") or "over" in sig)


def check_bytes(case) -> list[str]:
    notes = []
    spec = scenario_of(case)
    tampered = {e["name"] for e in spec["events"] if _breaks_body(e.get("tamper", {}))}
    events = {e["name"]: e for e in spec["events"]}
    raws = {}
    for i, (m, d) in enumerate(zip(case["input"]["messages"], spec["messages"], strict=True)):
        stream = bytes.fromhex(m["stream"])
        body, raw = body_of(stream)
        name = d.get("event") or d.get("receipt")
        if "corrupt" in d:
            continue  # a corrupt copy: keripy must refuse it, which the dispositions check
        if "event" in d:
            raws.setdefault(name, (body, raw))  # the genuine bytes every signature covers
        try:
            same = serdering.SerderKERI(sad=dict(body), makify=True).raw == raw
            why = ""
        except Exception as e:  # noqa: BLE001 - keripy refusing the fields is a finding
            same, why = False, f" ({type(e).__name__}: {e})"
        if same == (name in tampered and "event" in d):
            notes.append(f"message {i} ({name}): keripy 1.2.14's SerderKERI(makify=True) "
                         f"{'reproduces' if same else 'does not reproduce'} the body{why}")
        try:
            exts = extract(stream)
        except Exception as e:  # noqa: BLE001
            if name not in tampered and (d.get("sigs") or d.get("wigs") or d.get("couples")):
                notes.append(f"message {i} ({name}): keripy 1.2.14's Parser does not extract it "
                             f"({type(e).__name__}: {e})")
            continue
        signed = raws[name][1] if name in raws else raw
        for siger, sig in zip(exts.sigers, d.get("sigs", []), strict=False):
            label = sig["key"] if isinstance(sig, dict) else sig
            ok = _verfer(label, True).verify(siger.raw, signed)
            if ok == _bad(sig):
                notes.append(f"message {i} ({name}): keripy's Verfer says controller signature "
                             f"{siger.index} {'verifies' if ok else 'fails'}")
        wits = _wits(events)
        for wiger, wig in zip(exts.wigers, d.get("wigs", []), strict=False):
            label = wig["key"] if isinstance(wig, dict) else wig
            ok = label in wits and _verfer(label, False).verify(wiger.raw, signed)
            if ok == (_bad(wig) or label not in wits):
                notes.append(f"message {i} ({name}): keripy's Verfer says witness signature "
                             f"{wiger.index} {'verifies' if ok else 'fails'}")
        # Receipt couples carry the receipter's prefix, so keripy's own Verfer checks each one.
        if len(exts.cigars) != len(d.get("couples", [])):
            notes.append(f"message {i} ({name}): keripy extracted {len(exts.cigars)} receipt "
                         f"couples, not {len(d.get('couples', []))}")
        for cigar in exts.cigars:
            if not cigar.verfer.verify(cigar.raw, signed):
                notes.append(f"message {i} ({name}): keripy's Verfer says the receipt couple "
                             f"from {cigar.verfer.qb64} fails")
    return notes


def _wits(events) -> list[str]:
    """Witness labels a witness signature may come from: any the scenario names."""
    labels = set()
    for e in events.values():
        labels.update(e.get("wits", []), e.get("ba", []))
    return sorted(labels)


def _decoded(values) -> list[str]:
    return [bytes(v).decode() if isinstance(v, (bytes, memoryview)) else str(v) for v in values]


def readings(db, kvy, ident):
    _, pre, sn, said = ident
    key = dbing.snKey(pre, sn)
    if db.fons.get(keys=(pre, said)) is not None:
        state = "seen"
    elif said in _decoded(db.getLdes(key)):
        state = "duplicitous"
    elif (any(said in _decoded(get(key)) for get in (db.getOoes, db.getPses, db.getPwes))
          or said in _decoded(db.pdes.getOn(keys=pre, on=sn))):
        state = "pending"
    else:
        state = "rejected"
    kever = kvy.kevers.get(pre)
    held = _decoded(db.getKes(key))
    trunk = bool(state == "seen" and kever is not None and sn <= kever.sner.num and held
                 and held[-1] == said)
    return state, trunk


def fingerprint(db):
    out = []
    for name in TABLES:
        sdb = getattr(db, name)
        with db.env.begin(db=sdb) as txn:
            out.append((name, txn.stat(sdb)["entries"]))
    with db.env.begin(db=db.pdes.sdb) as txn:
        out.append(("pdes", txn.stat(db.pdes.sdb)["entries"]))
    return tuple(out)


def key_state(kever) -> dict:
    return {
        "sn": kever.sner.num,
        "said": kever.serder.said,
        "keys": [v.qb64 for v in kever.verfers],
        "kt": kever.tholder.sith,
        "ndigs": [d.qb64 for d in kever.ndigers],
        "nt": kever.ntholder.sith,
        "wits": list(kever.wits),
        "bt": f"{kever.toader.num:x}",
        "delegator": kever.delpre,
    }


def run_case(case) -> dict:
    messages = [bytes.fromhex(m["stream"]) for m in case["input"]["messages"]]
    spec = scenario_of(case)
    corrupt = [bool(d.get("corrupt")) for d in spec["messages"]]
    idents = []
    for s in messages:
        body, _ = body_of(s)
        idents.append((body["t"], body["i"], int(body["s"], 16), body["d"]))
    result = {"dispositions": [None] * len(messages), "errors": []}
    with basing.openDB(name="kcs-keri1x-check", temp=True) as db:
        kvy = Kevery(db=db, lax=False, local=False)
        refused = set()
        for i, s in enumerate(messages):
            try:
                deliver(kvy, s)
            except Hang:
                raise
            except Exception as e:  # noqa: BLE001 - keripy refusing a message drops it
                result["errors"].append(f"message {i}: {type(e).__name__}: {e}")
                refused.add(i)
            before = None
            for _ in range(MAX_PASSES):
                kvy.processEscrows()
                now = fingerprint(db)
                if now == before:
                    break
                before = now
            if corrupt[i]:
                # A corrupt copy claims the genuine event's SAID, so keripy's tables cannot tell
                # the two apart. Read keripy's verdict from the delivery itself: a copy it took
                # without raising is reported seen, so a keripy that accepts one disagrees.
                corrupt_reading = "rejected" if i in refused else "seen"
                result["dispositions"][i] = {"initial": corrupt_reading}
            elif idents[i][0] == "rct":
                result["dispositions"][i] = {"initial": "seen"}
            else:
                result["dispositions"][i] = {"initial": readings(db, kvy, idents[i])[0]}
        for i, ident in enumerate(idents):
            if corrupt[i]:
                result["dispositions"][i].update({"final": result["dispositions"][i]["initial"],
                                                  "trunk": False})
            elif ident[0] == "rct":
                result["dispositions"][i].update({"final": "seen", "trunk": False})
            else:
                state, trunk = readings(db, kvy, ident)
                result["dispositions"][i].update({"final": state, "trunk": trunk})
        result["key_states"] = {pre: key_state(k) for pre, k in kvy.kevers.items()}
    return result


def check(case) -> dict:
    signal.signal(signal.SIGALRM, _alarm)
    signal.alarm(TIMEOUT_SECONDS)
    try:
        got = run_case(case)
    except Hang as e:
        return {"id": case["id"], "hang": str(e)}
    except Exception as e:  # noqa: BLE001 - a crash in keripy or here is reported, not raised
        return {"id": case["id"], "crash": f"{type(e).__name__}: {e}"}
    finally:
        signal.alarm(0)
    out = []
    for a in case["assertions"]:
        ev = evaluate(a, got)
        if ev.outcome == "fail":
            out.append({"assertion": a["id"], "check": a["check"],
                        "expected": a.get("expected"), "keripy": ev.actual, "detail": ev.detail})
    try:
        notes = check_bytes(case)
    except Exception as e:  # noqa: BLE001 - a body keripy cannot read is reported, not raised
        notes = [f"the byte check could not read the case ({type(e).__name__}: {e})"]
    return {"id": case["id"], "status": case["status"], "disagreements": out,
            "bytes": notes, "keripy_errors": got["errors"], "readings": got["dispositions"]}


def cases() -> list[dict]:
    out = []
    for path in sorted((ROOT / "cases" / "keri").glob("KERI-*.json")):
        case = json.loads(path.read_text(encoding="utf-8"))
        if case["profile"] == PROFILE:
            out.append(case)
    return out


def main_lines(results) -> list[str]:
    lines = []
    for r in results:
        bad = r.get("disagreements") or r.get("bytes") or "hang" in r or "crash" in r
        lines.append(f"{r['id']}: {'DISAGREES' if bad else 'agrees'}")
        for d in r.get("disagreements", []):
            lines.append(f"    {d['assertion']} {d['check']}: {d['detail']}")
        for b in r.get("bytes", []):
            lines.append(f"    bytes: {b}")
        for k in ("hang", "crash"):
            if k in r:
                lines.append(f"    {k}: {r[k]}")
    return lines
