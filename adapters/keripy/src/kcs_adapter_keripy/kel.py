"""keri.process: deliver each message, in order, to one fresh keripy Kevery and report keripy's own
state after each delivery.

Nothing here decides whether an event is acceptable. keripy's Parser routes every message to its
Kevery, which validates, escrows or drops it; the adapter then drives keripy's escrow processing
to quiescence and reads keripy's database. README.md, "keri.process", says which keripy state
backs each reported value.
"""

import sys

from keri.core import eventing, parsing
from keri.db import basing

from kcs_adapter_keripy import keripy_api
from kcs_adapter_keripy.errors import Unsupported

E_MALFORMED = "e.input.format.request.f"
E_PERSPECTIVE = "e.feature.unsupported.perspective.f"
E_QUIESCENCE = "e.self.unknown.quiescence.f"

# Everything keripy does for these cases, without the adapter composing any of it.
FEATURES = ("crypto.ed25519", "kel.basic", "kel.delegation", "kel.multisig.numeric",
            "kel.multisig.weighted", "kel.nontransferable", "kel.partial-rotation",
            "kel.recovery", "kel.witness", "keri.duplicity", "keri.escrow", "keri.routing")
# keripy's event escrows that hold an event it may still accept: out of order, partially signed,
# partially witnessed, partially delegated. The likely-duplicitous escrow is reported apart.
PENDING = ("ooes", "pses", "pwes", "pdes")
# Every table an escrow pass can change. Quiescence is a pass that changes none of them.
TABLES = ("evts", "fels", "kels", "sigs", "wigs", "rcts", "ooes", "pses", "pwes", "pdes", "ldes",
          "uwes", "ures")
MAX_ESCROW_PASSES = 1000


class Malformed(Exception):
    pass


class NotQuiescent(Exception):
    pass


def fingerprint(db):
    """How many entries each table in TABLES holds."""
    counts = []
    for name in TABLES:
        sdb = getattr(db, name).sdb
        with db.env.begin(db=sdb) as txn:
            counts.append(txn.stat(sdb)["entries"])
    return tuple(counts)


def quiesce(kvy, db):
    """Run keripy's escrow processing until a pass changes nothing."""
    before = fingerprint(db)
    for _ in range(MAX_ESCROW_PASSES):
        kvy.processEscrows()
        now = fingerprint(db)
        if now == before:
            return
        before = now
    raise NotQuiescent(f"{E_QUIESCENCE}: keripy's escrow processing still changed its database "
                       f"after {MAX_ESCROW_PASSES} passes, so the readings would depend on when "
                       "the adapter stopped.")


def identify(api, stream: bytes):
    """What keripy's own parser says the message is, or None if keripy cannot parse it. Uses a
    parser with no Kevery, so identifying a message never changes keripy's state."""
    try:
        gen = api.run(parsing.Parser(), bytearray(stream))
        while True:
            next(gen)
    except StopIteration as done:
        exts = done.value
    except Exception as exc:  # noqa: BLE001 - keripy refusing to parse is its answer
        print(f"keripy cannot parse message: {type(exc).__name__}: {exc}", file=sys.stderr)
        return None
    serder = exts.serder
    return {"ilk": serder.ilk, "pre": serder.pre, "sn": serder.sn, "said": serder.said,
            "wigers": [w.qb64 for w in exts.wigers],
            "cigars": [(c.verfer.qb64, c.qb64) for c in exts.cigars]}


def _strings(values):
    return [v.qb64 if hasattr(v, "qb64") else v for v in values]


def _receipt_reading(db, ident):
    pre, sn, said = ident["pre"], ident["sn"], ident["said"]
    wigs = _strings(db.wigs.get(keys=(pre, said)))
    rcts = [(p.qb64, c.qb64) for p, c in db.rcts.get(keys=(pre, said))]
    attached = (all(w in wigs for w in ident["wigers"])
                and all(c in rcts for c in ident["cigars"]))
    if attached and (ident["wigers"] or ident["cigars"]):
        return "seen"
    held = [tuple(_strings(v)) for v in db.uwes.get(keys=pre, on=sn)]
    if any(entry == (said, w) for entry in held for w in ident["wigers"]):
        return "pending"
    return "rejected"


def reading(db, ident):
    """keripy's state of one message: seen, duplicitous, pending or rejected."""
    if ident is None:
        return "rejected"
    if ident["ilk"] == "rct":
        return _receipt_reading(db, ident)
    pre, sn, said = ident["pre"], ident["sn"], ident["said"]
    if db.fons.get(keys=(pre, said)) is not None:
        return "seen"
    if said in db.ldes.get(keys=pre, on=sn):
        return "duplicitous"
    if any(said in getattr(db, name).get(keys=pre, on=sn) for name in PENDING):
        return "pending"
    return "rejected"


def on_trunk(db, kvy, ident, final) -> bool:
    """Whether keripy holds the event as the last at its sequence number, at or below its
    identifier's current sequence number."""
    if final != "seen" or ident["ilk"] == "rct":
        return False
    kever = kvy.kevers.get(ident["pre"])
    return (kever is not None and ident["sn"] <= kever.sner.num
            and db.kels.getLast(keys=ident["pre"], on=ident["sn"]) == ident["said"])


def key_state(kever) -> dict:
    return {"sn": kever.sner.num, "said": kever.serder.said,
            "keys": [v.qb64 for v in kever.verfers], "kt": kever.tholder.sith,
            "ndigs": [d.qb64 for d in kever.ndigers], "nt": kever.ntholder.sith,
            "wits": list(kever.wits), "bt": f"{kever.toader.num:x}",
            "delegator": kever.delpre or None}


def _streams(request) -> list[bytes]:
    messages = request.get("messages")
    if not isinstance(messages, list) or not all(isinstance(m, dict) for m in messages):
        raise Malformed(f'{E_MALFORMED}: "messages" must be a list of objects.')
    out = []
    for m in messages:
        stream = m.get("stream")
        if not isinstance(stream, str) or len(stream) % 2 or not all(
                c in "0123456789abcdef" for c in stream):
            raise Malformed(f'{E_MALFORMED}: every message\'s "stream" must be a lowercase hex '
                            "string.")
        out.append(bytes.fromhex(stream))
    return out


def process(request) -> dict:
    perspective = request.get("perspective")
    if not isinstance(perspective, dict):
        raise Malformed(f'{E_MALFORMED}: "perspective" must be an object.')
    streams = _streams(request)
    if perspective.get("role") != "validator":
        raise Unsupported(f"{E_PERSPECTIVE}: This adapter reports only an ordinary validator's "
                          f"perspective, not {perspective.get('role')!r}.")
    api = keripy_api.load()
    with basing.openDB(name="kcs-adapter-keripy", temp=True) as db:
        # A fresh database, Kevery and Parser for every request: nothing carries over.
        kvy = eventing.Kevery(db=db, lax=False, local=False)
        parser = parsing.Parser(kvy=kvy)
        idents = [identify(api, s) for s in streams]
        initial = []
        for s, ident in zip(streams, idents, strict=True):
            try:
                parser.parse(ims=bytearray(s))
            except Exception as exc:  # noqa: BLE001 - keripy refusing a message drops it
                print(f"keripy refused a message: {type(exc).__name__}: {exc}", file=sys.stderr)
            quiesce(kvy, db)
            initial.append(reading(db, ident))
        dispositions = []
        for first, ident in zip(initial, idents, strict=True):
            final = reading(db, ident)
            dispositions.append({"initial": first, "final": final,
                                 "trunk": ident is not None and on_trunk(db, kvy, ident, final)})
        states = {pre: key_state(kever) for pre, kever in kvy.kevers.items()}
    return {"dispositions": dispositions, "key_states": states}
