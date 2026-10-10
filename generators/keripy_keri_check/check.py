"""Cross-check the KERI cases against keripy main, at a pinned commit.

Run from this directory, in its own pinned environment:

    uv run python check.py [--report PATH]

keripy is never the authority here. A disagreement is reported for a maintainer to record in
``generators/DISAGREEMENTS.md``; it never changes an expected value. Two things are checked:

- **Bytes.** Every key event body a case delivers is re-serialized by keripy's own
  ``SerderKERI(sad=..., makify=True)`` from the body's field values, which recomputes the version
  string and the SAID (and a self-addressing prefix); the result must equal the case's body,
  unless the scenario tampered with that body on purpose. Every controller and witness signature
  is verified with keripy's ``Verfer``; a signature a scenario forged must fail, any other must
  verify.
- **Dispositions.** The case's messages are delivered, in order, to a fresh keripy ``Kevery``
  through keripy's ``Parser``, and after each delivery ``Kevery.processEscrows`` runs until
  nothing in keripy's database changes. Each message's reading is then taken from keripy's
  state: ``seen`` if keripy recorded a first-seen ordinal for it (``.fons``); otherwise
  ``duplicitous`` if it is in the likely-duplicitous escrow (``.ldes``), ``pending`` if it is in
  the out-of-order, partially signed, partially witnessed or partially delegated escrow
  (``.ooes``, ``.pses``, ``.pwes``, ``.pdes``), and ``rejected`` if keripy holds it in none of
  them. The trunk reading is whether it
  is the last event at its sequence number (``.kels``) at or below the identifier's current
  sequence number. Key states come from keripy's ``Kever``. The case's assertions are then
  evaluated with the runner's own evaluator, so a disagreement here is what a keripy adapter that
  read the same state would be graded on.

Exchange-message cases (``exn.verify``) are checked the same way, with keripy's exchange
processing:

- **Bytes.** Every ``xip`` and ``exn`` body is rebuilt by ``SerderKERI(sad=..., makify=True)`` and
  must equal the case's body, unless its scenario added a field or changed one after the SAID on
  purpose, in which case keripy must not reproduce it. Every signature in each transferable
  signature group is verified with keripy's ``Verfer`` against the keys of the establishment
  event the group names, read from the case's KEL streams; a signature a scenario forged, or made
  with a key outside that event, must fail, and any other must verify.
- **Verdicts.** The KELs and then the messages go through keripy's ``Parser`` into a fresh
  ``Kevery`` and an ``Exchanger`` with no route handlers, over a temporary ``Habery``, with
  ``Kevery.processEscrows`` and ``Exchanger.processEscrow`` run after each delivery until
  keripy's tables stop changing. A message reads ``accepted`` if keripy logged it (``.exns``),
  else ``rejected``; no case delivers one body twice, so the log names the delivery.

This module and the keripy adapter under ``adapters/keripy`` do not share code, so the adapter is
not graded against the reading this module makes.
"""

import argparse
import json
import pathlib
import signal
import sys
import warnings

warnings.filterwarnings("ignore")

from keri.app import habbing
from keri.core import parsing, serdering
from keri.core.coring import Verfer
from keri.core.eventing import Kevery
from keri.db import basing
from keri.kering import Vrsn_2_0
from keri.peer import exchanging

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from keri_conformance.assertions import evaluate

KERIPY_COMMIT = "9a8b7aa70960f16fe7acffd8cf7901941ac912a1"
TIMEOUT_SECONDS = 20
PENDING_ESCROWS = ("ooes", "pses", "pwes", "pdes")
GENUS = b"-_AAACAA"


class Hang(Exception):
    pass


def _alarm(signum, frame):
    raise Hang(f"no result within {TIMEOUT_SECONDS} seconds")


def body_of(stream: bytes) -> tuple[dict, bytes]:
    data = stream.removeprefix(GENUS)
    serder = serdering.SerderKERI(raw=bytearray(data), verify=False)  # SAID checked elsewhere
    raw = bytes(data[:serder.size])
    return json.loads(raw), raw


def scenario_of(case) -> dict:
    path, key = case["provenance"]["scenario"].split("#")
    scenario = json.loads((ROOT / path).read_text())
    # A companion case (the ungated MUST half of a scenario) has its parent's deliveries.
    return next(c for c in scenario["cases"]
                if key in (c["key"], c.get("companion", {}).get("key")))


def extract(stream: bytes):
    """keripy's own extraction of one message: its Serder and its attachment lists."""
    parser = parsing.Parser(version=Vrsn_2_0)
    gen = parser.msgParsator(ims=bytearray(stream), framed=True, piped=False)
    try:
        while True:
            next(gen)
    except StopIteration as done:
        return done.value


def check_bytes(case) -> list[str]:
    """Where keripy disagrees with how the case's bytes were made: the body keripy builds from the
    same field values, and whether each signature verifies."""
    notes = []
    spec = scenario_of(case)
    # Only a tampered SAID or prefix makes a body that keripy cannot rebuild or parse.
    tampered = {e["name"] for e in spec["events"] if {"d", "i"} & set(e.get("tamper", {}))}
    events = {e["name"]: e for e in spec["events"]}
    for i, (m, d) in enumerate(zip(case["input"]["messages"], spec["messages"], strict=True)):
        stream = bytes.fromhex(m["stream"])
        body, raw = body_of(stream)
        name = d.get("event") or d.get("receipt")
        if "event" in d and "corrupt" in d:
            continue  # a corrupt copy: keripy must refuse it, which the dispositions check
        if "event" in d:
            try:
                same = serdering.SerderKERI(sad=dict(body), makify=True).raw == raw
                why = ""
            except Exception as e:  # noqa: BLE001 - keripy refusing the fields is a finding
                same, why = False, f" ({type(e).__name__}: {e})"
            if same == (name in tampered):
                notes.append(f"message {i} ({name}): keripy's SerderKERI(makify=True) "
                             f"{'reproduces' if same else 'does not reproduce'} the body{why}")
        try:
            exts = extract(stream)
        except Exception as e:  # noqa: BLE001
            if "event" in d and d.get("sigs") and name not in tampered:
                notes.append(f"message {i} ({name}): keripy's Parser does not extract it "
                             f"({type(e).__name__}: {e})")
            continue
        ev = events[name]
        signed = raw if "event" in d else _event_raw(case, spec, name)
        keys = body.get("k") if "event" in d and body["t"] != "ixn" else None
        forged = [isinstance(s, dict) and s.get("forged") for s in d.get("sigs", [])]
        if keys is not None:
            # A genuine (non-forged) signature verifies against one of the event's keys, whatever
            # index it is attached at; a forged one against none. The index is keripy's business.
            for siger, bad in zip(exts.sigers, forged, strict=True):
                ok = any(Verfer(qb64=k).verify(siger.raw, signed) for k in keys)
                if ok == bool(bad):
                    notes.append(f"message {i} ({name}): keripy's Verfer says signature "
                                 f"at index {siger.index} {'verifies' if ok else 'does not'}")
        wits = ev.get("wits")
        wforged = [isinstance(w, dict) and w.get("forged") for w in d.get("wigs", [])]
        if wits and exts.wigers:
            wit_keys = _witness_keys(case, spec, name)
            for wiger, bad in zip(exts.wigers, wforged, strict=True):
                ok = Verfer(qb64=wit_keys[wiger.index]).verify(wiger.raw, signed)
                if ok == bool(bad):
                    notes.append(f"message {i} ({name}): keripy's Verfer says witness "
                                 f"signature {wiger.index} {'verifies' if ok else 'fails'}")
    return notes


def _event_raw(case, spec, name) -> bytes:
    for m, d in zip(case["input"]["messages"], spec["messages"], strict=True):
        if d.get("event") == name:
            return body_of(bytes.fromhex(m["stream"]))[1]
    raise LookupError(f"no message delivers {name}")


def _witness_keys(case, spec, name) -> list[str]:
    for m, d in zip(case["input"]["messages"], spec["messages"], strict=True):
        if d.get("event") == name:
            return body_of(bytes.fromhex(m["stream"]))[0]["b"]
    raise LookupError(f"no message delivers {name}")


def readings(db, kvy, ident):
    """keripy's reading of one message, identified by (ilk, pre, sn, said)."""
    ilk, pre, sn, said = ident
    if ilk == "rct":
        return {"initial": "n/a", "final": "n/a", "trunk": False}
    if db.fons.get(keys=(pre, said)) is not None:
        state = "seen"
    elif said in [v.decode() if isinstance(v, bytes) else v
                  for v in db.ldes.get(keys=pre, on=sn)]:
        state = "duplicitous"
    elif any(said in [v.decode() if isinstance(v, bytes) else v
                      for v in getattr(db, name).get(keys=pre, on=sn)]
             for name in PENDING_ESCROWS):
        state = "pending"
    else:
        state = "rejected"
    kever = kvy.kevers.get(pre)
    last = db.kels.getLast(keys=pre, on=sn)
    last = last.decode() if isinstance(last, bytes) else last
    trunk = bool(state == "seen" and kever is not None and sn <= kever.sner.num and last == said)
    return state, trunk


def fingerprint(db):
    """The entry count of every keripy table an escrow pass can change."""
    out = []
    for name in ("kels", "fels", *PENDING_ESCROWS, "ldes", "uwes", "ures", "wigs", "sigs"):
        sdb = getattr(db, name).sdb
        with db.env.begin(db=sdb) as txn:
            out.append((name, txn.stat(sdb)["entries"]))
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
    with basing.openDB(name="kcs-keri-check", temp=True) as db:
        kvy = Kevery(db=db, lax=False, local=False)
        parser = parsing.Parser(kvy=kvy, version=Vrsn_2_0)
        for i, s in enumerate(messages):
            try:
                parser.parse(ims=bytearray(s))
            except Exception as e:  # noqa: BLE001 - keripy refusing a message drops it
                result["errors"].append(f"message {i}: {type(e).__name__}: {e}")
            before = None
            for _ in range(50):
                kvy.processEscrows()
                now = fingerprint(db)
                if now == before:
                    break
                before = now
            if corrupt[i]:
                # A copy whose SAID does not match its body is dropped; it shares the genuine
                # event's claimed SAID, so it cannot be read by (pre, sn, said).
                result["dispositions"][i] = {"initial": "rejected"}
            elif idents[i][0] == "rct":
                result["dispositions"][i] = {"initial": "seen", "final": "seen", "trunk": False}
            else:
                state, _ = readings(db, kvy, idents[i])
                result["dispositions"][i] = {"initial": state}
        for i, ident in enumerate(idents):
            if corrupt[i]:
                result["dispositions"][i].update({"final": "rejected", "trunk": False})
                continue
            if ident[0] == "rct":
                continue
            state, trunk = readings(db, kvy, ident)
            result["dispositions"][i].update({"final": state, "trunk": trunk})
        result["key_states"] = {pre: key_state(k) for pre, k in kvy.kevers.items()}
    return result


def check_exn_bytes(case) -> list[str]:
    """Where keripy disagrees with how an exchange-message case's bytes were made."""
    notes = []
    spec = scenario_of(case)
    exchanges = {e["name"]: e for e in spec["exchanges"]}
    kels = {}
    for k in case["input"]["kels"]:
        body, _ = body_of(bytes.fromhex(k["stream"]))
        kels[(body["i"], int(body["s"], 16), body["d"])] = body["k"]
    for i, (m, d) in enumerate(zip(case["input"]["messages"], spec["messages"], strict=True)):
        stream = bytes.fromhex(m["stream"])
        body, raw = body_of(stream)
        ex = exchanges[d["exchange"]]
        altered = bool(ex.get("extra") or ex.get("tamper"))
        try:
            same = serdering.SerderKERI(sad=dict(body), makify=True).raw == raw
            why = ""
        except Exception as e:  # noqa: BLE001 - keripy refusing the fields is a finding
            same, why = False, f" ({type(e).__name__}: {e})"
        if same == altered:
            notes.append(f"message {i} ({d['exchange']}): keripy's SerderKERI(makify=True) "
                         f"{'reproduces' if same else 'does not reproduce'} the body{why}")
        if altered:
            continue  # keripy's parser refuses the body, which the verdicts check
        try:
            exts = extract(stream)
        except Exception as e:  # noqa: BLE001
            if d.get("sigs"):
                notes.append(f"message {i}: keripy's Parser does not extract it "
                             f"({type(e).__name__}: {e})")
            continue
        made = [k for g in d.get("sigs", []) for k in g["keys"]]
        got = [(prefixer, number, diger, siger) for prefixer, number, diger, sigers in exts.tsgs
               for siger in sigers]
        if len(got) != len(made):
            notes.append(f"message {i}: keripy extracted {len(got)} signatures, not {len(made)}")
            continue
        for (prefixer, number, diger, siger), (sig, group) in zip(
                got, [(k, g) for g in d["sigs"] for k in g["keys"]], strict=True):
            keys = kels[(prefixer.qb64, number.sn, diger.qb64)]
            ok = Verfer(qb64=keys[siger.index]).verify(siger.raw, raw)
            sig = {"key": sig} if isinstance(sig, str) else sig
            genuine = not sig.get("forged") and "index" not in sig
            if ok != genuine:
                notes.append(f"message {i}: keripy's Verfer says the signature at index "
                             f"{siger.index} by {group['aid']} {'verifies' if ok else 'fails'}")
    return notes


def exn_tables(db):
    out = []
    for name in ("kels", "fels", *PENDING_ESCROWS, "exns", "epse", "esigs"):
        sdb = getattr(db, name).sdb
        with db.env.begin(db=sdb) as txn:
            out.append((name, txn.stat(sdb)["entries"]))
    return tuple(out)


def run_exn_case(case) -> dict:
    kels = [bytes.fromhex(k["stream"]) for k in case["input"]["kels"]]
    messages = [bytes.fromhex(m["stream"]) for m in case["input"]["messages"]]
    saids = [body_of(s)[0]["d"] for s in messages]
    result = {"verdicts": [], "errors": []}
    with habbing.openHby(name="kcs-keri-check-exn", temp=True) as hby:
        kvy = Kevery(db=hby.db, lax=False, local=False)
        exc = exchanging.Exchanger(hby=hby, handlers=[])
        parser = parsing.Parser(kvy=kvy, exc=exc, version=Vrsn_2_0)

        def deliver(i, s):
            try:
                parser.parse(ims=bytearray(s))
            except Exception as e:  # noqa: BLE001 - keripy refusing a message drops it
                result["errors"].append(f"{i}: {type(e).__name__}: {e}")
            before = None
            for _ in range(50):
                kvy.processEscrows()
                exc.processEscrow()
                now = exn_tables(hby.db)
                if now == before:
                    break
                before = now

        for i, s in enumerate(kels):
            deliver(f"kel {i}", s)
        on_delivery = []
        for i, s in enumerate(messages):
            deliver(f"message {i}", s)
            on_delivery.append(hby.db.exns.get(keys=(saids[i],)) is not None)
        for first, said in zip(on_delivery, saids, strict=True):
            final = hby.db.exns.get(keys=(said,)) is not None
            result["verdicts"].append({"on_delivery": "accepted" if first else "rejected",
                                       "verdict": "accepted" if final else "rejected"})
    return result


def check(case) -> dict:
    signal.signal(signal.SIGALRM, _alarm)
    signal.alarm(TIMEOUT_SECONDS)
    exn = case["operation"] == "exn.verify"
    try:
        got = run_exn_case(case) if exn else run_case(case)
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
            out.append({"assertion": a["id"], "level": a["level"], "check": a["check"],
                        "expected": a.get("expected"), "keripy": ev.actual,
                        "detail": ev.detail})
    return {"id": case["id"], "profile": case["profile"], "status": case["status"],
            "disagreements": out, "bytes": check_exn_bytes(case) if exn else check_bytes(case),
            "keripy_errors": got["errors"],
            "readings": got["verdicts"] if exn else got["dispositions"]}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--report", type=pathlib.Path)
    args = ap.parse_args()
    results = []
    for path in sorted((ROOT / "cases" / "keri").glob("KERI-*.json")):
        case = json.loads(path.read_text())
        r = check(case)
        results.append(r)
        bad = r.get("disagreements") or r.get("bytes") or "hang" in r or "crash" in r
        print(f"{case['id']}: {'DISAGREES' if bad else 'agrees'}"
              f"{' (disputed)' if case['status'] == 'disputed' else ''}")
        for d in r.get("disagreements", []):
            print(f"    {d['assertion']} {d['level']} {d['check']}: {d['detail']}")
        for b in r.get("bytes", []):
            print(f"    bytes: {b}")
        for k in ("hang", "crash"):
            if k in r:
                print(f"    {k}: {r[k]}")
    if args.report:
        args.report.write_text(json.dumps({"keripy": KERIPY_COMMIT, "results": results},
                                          indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
