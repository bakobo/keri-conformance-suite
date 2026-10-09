"""Builders for acdc.verify and exn.verify test bundles, made with keripy main's own helpers and
fixed seeds. These are test inputs, not cases: they check that the adapter reports what keripy did
with them, never what a case expects. Imported only on keripy main."""

import json

from keri.acdc import acdcmap, blindate, regcept
from keri.core import Blinder, Codens, Counter, SealSource, coring, eventing, signing
from keri.core.coring import MtrDex
from keri.kering import Kinds, Vrsn_2_0

from kcs_adapter_keripy import protocol

# The genus/version code every normative bundle stream begins with (adapter protocol, acdc.verify).
GENUS = b"-_AAACAA"
STAMP0 = "2025-07-04T17:50:00.000000+00:00"
STAMP1 = "2025-08-01T18:06:10.988921+00:00"
STAMP2 = "2025-09-01T18:06:10.988921+00:00"
UUID0 = "aG1lSjdJSNl7TiroPl67Uqzd5eFvzmr6bPlL7Lh4ukv8"
UUID1 = "aLfCdNAnc-0P2SiruarZSajXiUWu5iU2VfQahvpNCyzB"
SALT = signing.Salter(raw=b"0123456789abcdef").qb64


def signer(n, transferable=True):
    return signing.Signer(raw=bytes([n]) * 32, transferable=transferable)


def dig(s):
    return coring.Diger(ser=s.verfer.qb64b).qb64


def common():
    return {"pvrsn": Vrsn_2_0, "kind": Kinds.json}


def icp(key, nxt):
    return eventing.incept(keys=[key.verfer.qb64], isith="1", ndigs=[dig(nxt)], nsith="1",
                           code=MtrDex.Blake3_256, **common())


def ixn(prior, sn, data):
    return eventing.interact(pre=prior.pre, dig=prior.said, sn=sn, data=data, **common())


def signed(serder, key):
    return GENUS + bytes(eventing.messagize(serder, sigers=[key.sign(serder.raw, index=0)]))


def seal(serder):
    """A registry event's seal in a key event: its sequence number and SAID."""
    return {"s": serder.sad["n"], "d": serder.said}


def attached(serder, *bonds):
    """A registry event or ACDC with these attachment bonds (source seals, disclosures), or with
    an empty attachment group when there are none (keripy main requires one)."""
    if not bonds:
        # As keripy's ipexing._normalizeNestedStream frames a body with no attachments: an
        # attachment group holding an empty controller signature group.
        empty = Counter.enclose(qb64=b"", code=Codens.ControllerIdxSigs, version=Vrsn_2_0)
        group = Counter.enclose(qb64=empty, code=Codens.AttachmentGroup, version=Vrsn_2_0)
        return GENUS + bytes(serder.raw) + bytes(group)
    return GENUS + bytes(eventing.messagize(serder, bonds=list(bonds)))


def source(kel_event):
    return SealSource(s=f"{kel_event.sn:x}", d=kel_event.said)


class Issuer:
    """An issuer's KEL, grown one interaction at a time, with the streams to deliver."""

    def __init__(self, key=1, nxt=2):
        self.key = signer(key)
        self.icp = icp(self.key, signer(nxt))
        self.pre = self.icp.pre
        self.events = [self.icp]

    def anchor(self, *serders):
        event = ixn(self.events[-1], len(self.events), [seal(s) for s in serders])
        self.events.append(event)
        return event

    def kel(self):
        return [signed(e, self.key) for e in self.events]


def registry(issuer_pre, uuid=UUID0):
    return regcept(israid=issuer_pre, uuid=uuid, stamp=STAMP0)


def acdc(issuer_pre, rd=None):
    return acdcmap(israid=issuer_pre, regid=rd, uuid=UUID1,
                   attribute={"d": "", "name": "Sunspot College"})


def update(rip, prior, acdc_said, state, sn, stamp=STAMP1):
    blinder = Blinder.blind(acdc=acdc_said, state=state, salt=SALT, sn=sn)
    bup = blindate(regid=rip.said, prior=prior.said, blid=blinder.said, sn=sn, stamp=stamp)
    return blinder, bup


def entries(streams, label="test"):
    return [{"stream": s.hex(), "source": label} for s in streams]


def handle(request):
    return json.loads(protocol.handle_line(json.dumps(request).encode()))


def verify(presented, kels=(), registry_streams=(), acdcs=(), schemas=(), **extra):
    request = {"id": 7, "op": "acdc.verify", "perspective": {"role": "validator"},
               "kels": entries(kels), "registry": [{"stream": s.hex()} for s in registry_streams],
               "schemas": [s.hex() for s in schemas],
               "acdcs": [{"stream": s.hex()} for s in acdcs],
               "presented": {"stream": presented.hex()}, **extra}
    return handle(request)


def exchange(kels=(), messages=(), **extra):
    request = {"id": 8, "op": "exn.verify", "perspective": {"role": "validator"},
               "kels": entries(kels), "messages": entries(messages), **extra}
    return handle(request)


def exn(sender, route="/test/hello", prior="", xid="", stamp=STAMP0):
    return eventing.exchange(sender=sender, route=route, prior=prior, xid=xid,
                             attributes={"m": "hello"}, stamp=stamp, **common())


def exn_signed(serder, key, est):
    """An exchange message with one transferable signature group naming the establishment event
    est of the signer's KEL."""
    tsgs = [(coring.Prefixer(qb64=est.pre), coring.Number(num=est.sn),
             coring.Diger(qb64=est.said), [key.sign(serder.raw, index=0)])]
    return GENUS + bytes(eventing.messagize(serder, tsgs=tsgs))


def exn_cigned(serder, key):
    """An exchange message signed by a non-transferable sender."""
    return GENUS + bytes(eventing.messagize(serder, cigars=[key.sign(ser=serder.raw)]))
