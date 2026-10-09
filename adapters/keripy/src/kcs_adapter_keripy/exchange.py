"""exn.verify: deliver the KELs and then each exchange message, in order, to one fresh keripy
validator (a Kevery and an Exchanger over one temporary Habery), and report whether keripy logged
each message as an accepted exchange, at quiescence after its own delivery and after the last.

Nothing here decides whether a message is acceptable. keripy's Parser routes a KERI 2.x exn or xip
to Kevery.processMsg, which hands an exn to the Exchanger; the Exchanger verifies the sender's
signatures and logs or escrows the message. The adapter registers no route handlers, so keripy
applies only its generic exchange rules (README.md, "exn.verify").
"""

from keri.app import habbing
from keri.core import eventing, parsing
from keri.peer import exchanging

from kcs_adapter_keripy import kel, keripy_api

# The Exchanger's accepted-message and escrow tables, beside the Kevery's, so that quiescence
# also covers exchange-message escrow processing.
TABLES = kel.TABLES + ("exns", "epse", "esigs", "ecigs", "ests")


def accepted(db, ident) -> bool:
    """Whether keripy logged the message as an accepted exchange: db.exns holds its SAID. A
    message keripy only escrows (db.epse) or never kept is not accepted."""
    return ident is not None and db.exns.get(keys=(ident,)) is not None


def said(api, stream: bytes):
    """The SAID keripy's own parser gives the message, or None if keripy cannot parse it."""
    exts = kel.extract(api, stream)
    return None if exts is None else exts.serder.said


def verify(request) -> dict:
    kel.validator(request)
    kels = kel.streams(request, "kels")
    messages = kel.streams(request, "messages")
    api = keripy_api.load()
    with habbing.openHby(name="kcs-adapter-keripy", temp=True) as hby:
        # A fresh database, Kevery, Exchanger and Parser for every request: nothing carries over.
        kvy = eventing.Kevery(db=hby.db, lax=False, local=False)
        exc = exchanging.Exchanger(hby=hby, handlers=[])
        parser = parsing.Parser(kvy=kvy, exc=exc)

        def settle():
            kel.quiesce(kvy, hby.db, extra=(exc.processEscrow,), tables=TABLES)

        for stream in kels:
            kel.deliver(parser, stream)
            settle()
        idents = [said(api, s) for s in messages]
        on_delivery = []
        for stream, ident in zip(messages, idents, strict=True):
            kel.deliver(parser, stream)
            settle()
            on_delivery.append(accepted(hby.db, ident))
        verdicts = [{"on_delivery": _word(first), "verdict": _word(accepted(hby.db, ident))}
                    for first, ident in zip(on_delivery, idents, strict=True)]
    return {"verdicts": verdicts}


def _word(value: bool) -> str:
    return "accepted" if value else "rejected"
