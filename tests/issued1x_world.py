"""A small keripy 1.x issuer for the runner's 1.x issuance tests (issued1x): KELs, a vcp/iss
registry and 1.x ACDCs built with the runner's own primitives, so a test can make one thing wrong
and see the runner say so.

It is test scaffolding, not a second model, as issued_world is: the keripy 1.2.14 and signify-ts
fixtures (tests/fixtures/keripy1x-issuance.json, signify-keria-issuance.json) are the independent
check that the runner accepts what real 1.x issuers issue."""

from issued_world import salt, schema, seed, verkey

from keri_conformance import ed25519
from keri_conformance import issued as iss
from keri_conformance import issued1x as one

STAMP = "2026-10-01T00:00:00.000000+00:00"


def saidify(body: dict, protocol: str, labels=("d",)) -> dict:
    d = one.V1.said(body, protocol, labels)
    return one.sized({**body, **{label: d for label in labels}}, protocol)


def signed(raw: bytes, label: str, index: int = 0) -> str:
    sig = iss.base64.urlsafe_b64encode(b"\x00\x00" + ed25519.sign(seed(label), raw)).decode()[2:]
    return "-AAB" + "A" + iss.B64[index] + sig


class Kel:
    def __init__(self, label: str):
        self.label, self.events = label, []
        body = {"v": "", "t": "icp", "d": "", "i": "", "s": "0", "kt": "1",
                "k": [verkey(f"{label}/k0")], "nt": "1",
                "n": [iss.digest(verkey(f"{label}/k1").encode())], "bt": "0", "b": [], "c": [],
                "a": []}
        self.add(saidify(body, "KERI", ("d", "i")))

    @property
    def prefix(self) -> str:
        return self.events[0][0]["i"]

    def add(self, body: dict, attachments: str | None = None):
        raw = iss.serialize(body)
        self.events.append((body, signed(raw, f"{self.label}/k0") if attachments is None
                            else attachments))

    def ixn(self, seals: list[dict]):
        body = {"v": "", "t": "ixn", "d": "", "i": self.prefix, "s": f"{len(self.events):x}",
                "p": self.events[-1][0]["d"], "a": seals}
        self.add(saidify(body, "KERI"))

    def stream(self) -> str:
        return b"".join(iss.serialize(b) + a.encode() for b, a in self.events).hex()


def vcp(issuer: str, **over) -> dict:
    body = {"v": "", "t": "vcp", "d": "", "i": "", "ii": issuer, "s": "0", "c": ["NB"], "bt": "0",
            "b": [], "n": salt("registry")}
    return saidify({**body, **over}, "KERI", ("d", "i"))


def iss_event(said: str, regk: str, **over) -> dict:
    body = {"v": "", "t": "iss", "d": "", "i": said, "s": "0", "ri": regk, "dt": STAMP}
    return saidify({**body, **over}, "KERI")


def acdc(issuer: str, schema_said: str, regk: str, a: dict, **over) -> dict:
    a = {"d": "", **a}
    a["d"] = one.block_said(a)
    body = {"v": "", "d": "", "u": salt("acdc"), "i": issuer, "ri": regk, "s": schema_said, "a": a}
    return saidify({**body, **over}, "ACDC")


def issuance(attributes=None, issuee=True, a_over=None, acdc_over=None, vcp_over=None,
             iss_over=None, seal=None, extra=None):
    """A valid 1.x issuance, with hooks to make one part of it wrong: its request and result."""
    said_, schema_hex = schema()
    attributes = {"dt": STAMP, "name": "Zoe"} if attributes is None else attributes
    issuer, holder = Kel("I"), Kel("H")
    registry = vcp(issuer.prefix, **(vcp_over or {}))
    a = {"u": salt("a"), **({"i": holder.prefix} if issuee else {}), **attributes, **(a_over or {})}
    cred = acdc(issuer.prefix, said_, registry["i"], a, **(acdc_over or {}))
    event = iss_event(cred["d"], registry["i"], **(iss_over or {}))
    seal = seal or (lambda i, s, d: {"i": i, "s": s, "d": d})
    issuer.ixn([seal(registry["i"], "0", registry["d"])])
    issuer.ixn([seal(cred["d"], "0", event["d"])])
    asked = {"name": "c", "issuer": "issuer", "schema": said_, "attributes": attributes,
             "registry": iss.ONE_X}
    if issuee:
        asked["issuee"] = "holder"
    request = {"roles": ["issuer", "holder"], "schemas": [schema_hex], "credentials": [asked]}
    chain = iss.serialize(registry) + iss.serialize(event) + (extra or b"")
    result = {"kels": {"issuer": issuer.stream(), "holder": holder.stream()},
              "credentials": {"c": {"acdc": iss.serialize(cred).hex(), "registry": chain.hex()}}}
    return request, result
