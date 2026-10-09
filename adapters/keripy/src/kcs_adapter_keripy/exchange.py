"""exn.verify: deliver the KELs and then each exchange message, in order, to one fresh keripy
validator (a Kevery and an Exchanger over one temporary Habery), and report whether keripy accepted
each delivery, at quiescence after its own delivery and after the last.

A reading is about the delivery: the message together with the attachments it arrived with, so a
second delivery of the same body is read on its own. keripy's Exchanger.processEvent returns True
when it verified a delivery's attachments and logged the message, and the adapter records that
return for the call keripy makes while parsing each delivery, whichever way keripy authenticated
the sender. A delivery whose attachments keripy
puts into escrow instead (escrowPSEvent) is accepted once keripy has logged the message and every signature the delivery carried
is among those keripy kept as verified when it did (db.esigs).

Nothing here decides whether a message is acceptable. keripy's Parser routes a KERI 2.x exn or xip
to Kevery.processMsg, which hands an exn to the Exchanger; the Exchanger authenticates the sender,
by a valid source seal in the sender's KEL or by the sender's signatures, and logs or escrows the
message. The adapter registers no route handlers, so keripy
applies only its generic exchange rules (README.md, "exn.verify").
"""

from keri.app import habbing
from keri.core import eventing, parsing
from keri.peer import exchanging

from kcs_adapter_keripy import kel, keripy_api

# The Exchanger's accepted-message and escrow tables, beside the Kevery's, so that quiescence
# also covers exchange-message escrow processing.
TABLES = kel.TABLES + ("exns", "epse", "esigs", "ecigs", "ests")


class Delivery:
    """One delivered stream, as keripy handled it."""

    def __init__(self, said, signatures):
        self.said = said  # the SAID keripy's parser gives the message, or None if unframeable
        self.signatures = signatures  # (prefix, sn, establishment SAID, signature) it carried
        self.processed = False  # keripy's processEvent returned True for this delivery
        self.escrowed = False  # keripy put this delivery's attachments into escrow


def parse(api, stream: bytes) -> Delivery:
    """The message and signatures keripy's own parser finds in one stream, which must be exactly
    one message."""
    exts = kel.extract(api, stream, exact=True)
    if exts is None:
        return Delivery(None, frozenset())
    return Delivery(exts.serder.said, frozenset(
        (prefixer.qb64, f"{number.sn:032x}", diger.qb64, siger.qb64)
        for prefixer, number, diger, sigers in exts.tsgs for siger in sigers))


def kept(db, said) -> frozenset:
    """The signatures keripy kept with a message it logged: those it verified."""
    return frozenset((*keys[1:], siger.qb64)
                     for keys, siger in db.esigs.getTopItemIter(keys=(said, "")))


def accepted(db, delivery) -> bool:
    """Whether keripy accepted this delivery: it verified the delivery's own attachments and
    logged the message, at once or from escrow. A message keripy only escrows, or logs on the
    strength of another delivery's signatures, is not accepted for this delivery."""
    if delivery.processed:
        return True
    return (delivery.escrowed and bool(delivery.signatures)
            and db.exns.get(keys=(delivery.said,)) is not None
            and delivery.signatures <= kept(db, delivery.said))


def observe(exc, seen):
    """Record, without changing either, what keripy's Exchanger does with each message: a
    processEvent's return (True when it verified and logged the message), and an escrowPSEvent that puts the
    message's attachments into escrow (keripy declines to escrow a message it already logged)."""
    process_event, escrow = exc.processEvent, exc.escrowPSEvent

    def processed(serder, **kwa):
        result = process_event(serder=serder, **kwa)
        seen.append(("processed", serder.said, result))
        return result

    def escrowed(serder, **kwa):
        if exc.hby.db.exns.get(keys=(serder.said,)) is None:
            seen.append(("escrowed", serder.said, True))
        return escrow(serder=serder, **kwa)

    exc.processEvent, exc.escrowPSEvent = processed, escrowed


def verify(request) -> dict:
    kel.validator(request)
    kels = kel.streams(request, "kels")
    messages = kel.streams(request, "messages")
    if not messages:
        raise kel.Malformed(f'{kel.E_MALFORMED}: "messages" must list at least one message.')
    api = keripy_api.load()
    with habbing.openHby(name="kcs-adapter-keripy", temp=True) as hby:
        # A fresh database, Kevery, Exchanger and Parser for every request: nothing carries over.
        kvy = eventing.Kevery(db=hby.db, lax=False, local=False)
        exc = exchanging.Exchanger(hby=hby, handlers=[])
        seen = []
        observe(exc, seen)
        parser = parsing.Parser(kvy=kvy, exc=exc)

        def settle():
            kel.quiesce(kvy, hby.db, extra=(exc.processEscrow,), tables=TABLES)

        for stream in kels:
            kel.deliver_framed(api, parser, stream)
            settle()
        deliveries = [parse(api, s) for s in messages]
        on_delivery = []
        for stream, delivery in zip(messages, deliveries, strict=True):
            if delivery.said is not None:
                del seen[:]
                kel.deliver(parser, stream)
                delivery.processed = ("processed", delivery.said, True) in seen
                delivery.escrowed = ("escrowed", delivery.said, True) in seen
            settle()
            on_delivery.append(accepted(hby.db, delivery))
        verdicts = [{"on_delivery": _word(first), "verdict": _word(accepted(hby.db, delivery))}
                    for first, delivery in zip(on_delivery, deliveries, strict=True)]
    return {"verdicts": verdicts}


def _word(value: bool) -> str:
    return "accepted" if value else "rejected"
