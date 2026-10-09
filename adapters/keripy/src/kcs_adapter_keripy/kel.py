"""keri.process: deliver each message, in order, to one fresh keripy Kevery and report keripy's own
state after each delivery.

Nothing here decides whether an event is acceptable. keripy's Parser routes every message to its
Kevery, which validates, escrows or drops it; the adapter then drives keripy's escrow processing
to quiescence and reads keripy's database. README.md, "keri.process", says which keripy state
backs each reported value.
"""

import hashlib
import sys

from keri.core import eventing, parsing
from keri.core.coring import Number, NumDex
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


def fingerprint(db, tables=TABLES):
    """A digest of the contents of every named table. A digest, not entry counts, because a
    pass that replaces one escrow entry with another leaves the counts equal while the state has
    moved, and counting that as quiescence would stop escrow processing a pass too early."""
    h = hashlib.blake2b(digest_size=16)
    for name in tables:
        sdb = getattr(db, name).sdb
        h.update(name.encode())
        with db.env.begin(db=sdb) as txn, txn.cursor(sdb) as cur:
            for key, val in cur:
                h.update(key)
                h.update(b"\x00")
                h.update(val)
                h.update(b"\x01")
    return h.digest()


def quiesce(kvy, db, extra=(), tables=TABLES):
    """Run keripy's escrow processing until a pass changes nothing in the named tables. `extra`
    holds further keripy escrow processors to run in each pass, such as an Exchanger's."""
    before = fingerprint(db, tables)
    for _ in range(MAX_ESCROW_PASSES):
        kvy.processEscrows()
        for process_escrow in extra:
            process_escrow()
        now = fingerprint(db, tables)
        if now == before:
            return
        before = now
    raise NotQuiescent(f"{E_QUIESCENCE}: keripy's escrow processing still changed its database "
                       f"after {MAX_ESCROW_PASSES} passes, so the readings would depend on when "
                       "the adapter stopped.")


def extract(api, stream: bytes, exact=False):
    """keripy's own parse of one message and its attachments (its MsgParseDom), or None if keripy
    cannot parse it. Uses a parser with no processors attached, so parsing never changes keripy's
    state. With exact, the stream must be that one message and nothing more: bytes keripy's parse
    leaves over make the stream unframeable as one message, and the answer None."""
    ims = bytearray(stream)
    try:
        gen = api.run(parsing.Parser(), ims)
        while True:
            next(gen)
    except StopIteration as done:
        exts = done.value
    except Exception as exc:  # noqa: BLE001 - keripy refusing to parse is its answer
        print(f"keripy cannot parse message: {type(exc).__name__}: {exc}", file=sys.stderr)
        return None
    if exact and ims:
        print(f"stream is not exactly one message: {len(ims)} bytes follow the first",
              file=sys.stderr)
        return None
    return exts


def identify(api, stream: bytes):
    """What keripy's own parser says the message is, or None if keripy cannot parse it."""
    exts = extract(api, stream)
    if exts is None:
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
    # A non-witness receipt couple for an event keripy has not accepted waits in the unverified
    # receipt escrow (ures), keyed by prefix and a huge-coded sequence number; keripy reports it
    # held, not dropped.
    couples = db.ures.get(keys=(pre, Number(num=sn, code=NumDex.Huge).qb64))
    receipt_sigs = [sig for _verfer, sig in ident["cigars"]]
    if any(diger.qb64 == said and cigar.qb64 in receipt_sigs
           for diger, _prefixer, cigar in couples):
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


def hex_stream(value, field):
    """The bytes of one hex-encoded stream, or Malformed naming the request field."""
    if not isinstance(value, str) or len(value) % 2 or not all(
            c in "0123456789abcdef" for c in value):
        raise Malformed(f'{E_MALFORMED}: every "stream" in "{field}" must be a lowercase hex '
                        "string.")
    return bytes.fromhex(value)


def streams(request, field) -> list[bytes]:
    """The streams of a request field that is a list of objects each carrying a "stream"."""
    entries = request.get(field)
    if not isinstance(entries, list) or not all(isinstance(m, dict) for m in entries):
        raise Malformed(f'{E_MALFORMED}: "{field}" must be a list of objects.')
    return [hex_stream(m.get("stream"), field) for m in entries]


def validator(request):
    """Check the request's perspective: an object, and an ordinary validator's."""
    perspective = request.get("perspective")
    if not isinstance(perspective, dict):
        raise Malformed(f'{E_MALFORMED}: "perspective" must be an object.')
    if perspective.get("role") != "validator":
        raise Unsupported(f"{E_PERSPECTIVE}: This adapter reports only an ordinary validator's "
                          f"perspective, not {perspective.get('role')!r}.")


def deliver(parser, stream: bytes):
    """Hand one stream to keripy unchanged. keripy refusing it drops it; that is logged."""
    try:
        parser.parse(ims=bytearray(stream))
    except Exception as exc:  # noqa: BLE001 - keripy refusing a message drops it
        print(f"keripy refused a message: {type(exc).__name__}: {exc}", file=sys.stderr)


def deliver_framed(api, parser, stream: bytes):
    """Hand one stream that must hold exactly one message to keripy, unchanged, and return
    keripy's parse of it; a stream that is not exactly one message is not delivered, and the
    answer is None."""
    exts = extract(api, stream, exact=True)
    if exts is not None:
        deliver(parser, stream)
    return exts


def process(request) -> dict:
    validator(request)
    messages = streams(request, "messages")
    api = keripy_api.load()
    with basing.openDB(name="kcs-adapter-keripy", temp=True) as db:
        # A fresh database, Kevery and Parser for every request: nothing carries over.
        kvy = eventing.Kevery(db=db, lax=False, local=False)
        parser = parsing.Parser(kvy=kvy)
        idents = [identify(api, s) for s in messages]
        initial = []
        for s, ident in zip(messages, idents, strict=True):
            deliver(parser, s)
            quiesce(kvy, db)
            initial.append(reading(db, ident))
        dispositions = []
        for first, ident in zip(initial, idents, strict=True):
            final = reading(db, ident)
            dispositions.append({"initial": first, "final": final,
                                 "trunk": ident is not None and on_trunk(db, kvy, ident, final)})
        states = {pre: key_state(kever) for pre, kever in kvy.kevers.items()}
    return {"dispositions": dispositions, "key_states": states}
