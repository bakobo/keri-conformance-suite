"""acdc.verify on keripy main, answered fail-closed.

keripy main verifies ACDC 2.00 only inside its IPEX grant handling (keri.acdc.ipexing.IpexHandler),
which needs a signed grant exchange message, a local registry store and IPEX workflow state; it
has no entry point that judges one ACDC against a bundle of KELs, registries, schemas and far
nodes, and its Parser refuses an ACDC message with no verifier attached. So the adapter never
answers `valid`: it answers `invalid` when keripy cannot parse the presented ACDC, and `incomplete`
otherwise, and it declares no acdc.* feature (README.md, "acdc.verify").

What keripy does do for a bundle is reported. The KELs are delivered to a fresh Kevery and driven
to quiescence, as for keri.process, and the registry the presented ACDC names in its top-level
`rd` is verified by keripy's own public registry verifier, keri.acdc.regeventing.vet, over the
registry events keripy can parse. The adapter offers vet the evidence the bundle carries and
reports the head vet returns; it never reports a head vet did not.
"""

import sys

from keri import kering
from keri.acdc import regeventing
from keri.acdc.ipexing import DisclosedNodeIlks
from keri.core import Blinder, BlindState, BoundState, eventing, parsing
from keri.core.serdering import SerderACDC
from keri.db import basing
from keri.kering import Ilks

from kcs_adapter_keripy import kel, keripy_api

REASON_NO_VERIFIER = ("keripy main has no entry point that judges an ACDC 2.00 against a "
                      "bundle; it verifies ACDCs only inside IPEX grant handling")
REASON_UNREADABLE = "keripy cannot parse the presented stream as a disclosed ACDC"


def _hex_list(request, field):
    values = request.get(field)
    if not isinstance(values, list):
        raise kel.Malformed(f'{kel.E_MALFORMED}: "{field}" must be a list of hex strings.')
    return [kel.hex_stream(v, field) for v in values]


def _presented(request) -> bytes:
    presented = request.get("presented")
    if not isinstance(presented, dict):
        raise kel.Malformed(f'{kel.E_MALFORMED}: "presented" must be an object.')
    return kel.hex_stream(presented.get("stream"), "presented")


def disclosed_acdc(exts):
    """The presented ACDC's serder, or None unless keripy parsed it as a disclosed ACDC node: a
    SerderACDC whose type is one keripy's IPEX verifier accepts as a node (DisclosedNodeIlks)."""
    if exts is None or not isinstance(exts.serder, SerderACDC):
        return None
    return exts.serder if exts.serder.ilk in DisclosedNodeIlks else None


def disclosures(exts) -> list:
    """The blinded-state disclosures attached to one parsed message, rebuilt as keripy's
    IpexHandler rebuilds a node's proofs (Blinder over the concatenated parsed fields)."""
    out = []
    for clan, proofs in ((BlindState, exts.bsqs), (BoundState, exts.bsss)):
        for proof in proofs:
            try:
                out.append(Blinder(clan=clan, qb64=b"".join(item.qb64b for item in proof)))
            except kering.KeriError as exc:
                print(f"keripy cannot rebuild a disclosure: {type(exc).__name__}: {exc}",
                      file=sys.stderr)
    return out


def _vet(db, rip, updates, sources, offered):
    """keripy's vet over the chain, with the first offered disclosure keripy accepts for the head;
    without one when it accepts none."""
    for blinder in offered:
        try:
            return regeventing.vet(rip, updates, db=db, blinder=blinder, sources=sources)
        except kering.UnverifiedBlindError:
            continue
    return regeventing.vet(rip, updates, db=db, sources=sources)


def registry(api, db, acdc_exts, streams):
    """The verified head keripy reports for the registry the presented ACDC names in its
    top-level rd, or None."""
    serder = acdc_exts.serder
    rd = serder.sad.get("rd")
    if not rd:
        return None
    events = [event for event in (kel.extract(api, s, exact=True) for s in streams)
              if event is not None and isinstance(event.serder, SerderACDC)]
    rip = next((event for event in events
                if event.serder.ilk == Ilks.rip and event.serder.said == rd), None)
    if rip is None:
        print(f"no registry inception {rd} that keripy can parse is in the bundle",
              file=sys.stderr)
        return None
    updates = [event for event in events
               if event.serder.ilk == Ilks.bup and event.serder.sad.get("rd") == rd]
    # An attached source couple names the key event that seals a registry event; keripy's vet
    # takes it as a hint and falls back to scanning the issuer's KEL.
    sources = {event.serder.said: event.sscs[-1][1].qb64
               for event in [rip, *updates] if event.sscs}
    offered = [d for event in [*events, acdc_exts] for d in disclosures(event)]
    try:
        record = _vet(db, rip.serder, [u.serder for u in updates], sources, offered)
    except kering.KeriError as exc:
        print(f"keripy did not verify registry {rd}: {type(exc).__name__}: {exc}",
              file=sys.stderr)
        return None
    if record.issuer != serder.sad.get("i"):
        # vet checks that the inception is sealed by the AID it names; the registry must also
        # be the ACDC issuer's. The adapter withholds a head keripy verified for someone else.
        print(f"registry {rd} was incepted by {record.issuer}, not the ACDC's issuer",
              file=sys.stderr)
        return None
    told = bool(record.acdc and record.state)
    return {"rd": record.regid, "n": record.sn, "d": record.said,
            "td": record.acdc if told else None, "ts": record.state if told else None}


def verify(request) -> dict:
    kel.validator(request)
    kels = kel.streams(request, "kels")
    registry_streams = kel.streams(request, "registry")
    # Far nodes and schemas are read and checked, but keripy has no standalone use for either.
    kel.streams(request, "acdcs")
    _hex_list(request, "schemas")
    presented = _presented(request)
    api = keripy_api.load()
    with basing.openDB(name="kcs-adapter-keripy", temp=True) as db:
        # A fresh database, Kevery and Parser for every request: nothing carries over.
        kvy = eventing.Kevery(db=db, lax=False, local=False)
        parser = parsing.Parser(kvy=kvy)
        for stream in kels:
            kel.deliver_framed(api, parser, stream)
            kel.quiesce(kvy, db)
        exts = kel.extract(api, presented, exact=True)
        if disclosed_acdc(exts) is None:
            return {"verdict": "invalid", "reason": REASON_UNREADABLE, "registry": None,
                    "edges": []}
        head = registry(api, db, exts, registry_streams)
    return {"verdict": "incomplete", "reason": REASON_NO_VERIFIER, "registry": head,
            "edges": []}
