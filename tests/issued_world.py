"""A small issuer for the runner's issuance tests: KELs, a blindable registry and ACDCs built with
the runner's own primitives, so a test can make one thing wrong and see the runner say so.

It is test scaffolding, not a second model: everything it computes, the runner recomputes from
the bytes and must agree with, and the heti fixture (tests/fixtures/heti-issuance.json) is the
independent check that the runner accepts what a real issuer issues."""

import hashlib
import json

from keri_conformance import ed25519
from keri_conformance import issued as iss

SCHEMA = {"$id": "", "$schema": "https://json-schema.org/draft/2020-12/schema", "title": "T",
          "type": "object"}


def seed(label: str) -> bytes:
    return hashlib.sha256(f"kcs-issued/{label}".encode()).digest()


def verkey(label: str) -> str:
    return iss.qb64("D", ed25519.public_key(seed(label)))


def salt(label: str, code: str = "0A") -> str:
    raw = hashlib.sha256(f"kcs-salt/{label}".encode()).digest()
    return iss.qb64(code, raw[:16] if code == "0A" else raw)


def schema() -> tuple[str, str]:
    """A schema's SAID and its bytes in hex."""
    s = {**SCHEMA, "$id": iss.DUMMY}
    s["$id"] = iss.digest(iss.serialize(s))
    return s["$id"], iss.serialize(s).hex()


def saidify(body: dict, protocol: str, labels=("d",)) -> dict:
    d = iss.said(body, protocol, labels)
    return iss.sized({**body, **{label: d for label in labels}}, protocol)


def sig_group(raw: bytes, signers: list[tuple[int, str]]) -> str:
    sigs = "".join("A" + iss.B64[i] + iss.base64.urlsafe_b64encode(
        b"\x00\x00" + ed25519.sign(seed(label), raw)).decode()[2:] for i, label in signers)
    return "-K" + iss.int_b64(len(sigs) // 4, 2) + sigs


def outer(*groups: str) -> str:
    inner = "".join(groups)
    return "-C" + iss.int_b64(len(inner) // 4, 2) + inner


class Kel:
    def __init__(self, label: str, keys=("k0",), nxt=("k1",)):
        self.label, self.events, self.signers = label, [], [list(keys)]
        body = {"v": "", "t": "icp", "d": "", "i": "", "s": "0", "kt": "1",
                "k": [verkey(f"{label}/{k}") for k in keys], "nt": "1",
                "n": [iss.digest(verkey(f"{label}/{k}").encode()) for k in nxt],
                "bt": "0", "b": [], "c": [], "a": []}
        self.add(saidify(body, "KERI", ("d", "i")))
        self.next = list(nxt)

    @property
    def prefix(self) -> str:
        return self.events[0][0]["i"]

    def add(self, body: dict, signers=None):
        raw = iss.serialize(body)
        labels = signers if signers is not None else [
            (i, f"{self.label}/{k}") for i, k in enumerate(self.signers[-1])]
        self.events.append((body, outer(sig_group(raw, labels))))

    def ixn(self, seals: list[dict], **over):
        body = {"v": "", "t": "ixn", "d": "", "i": self.prefix, "s": f"{len(self.events):x}",
                "p": self.events[-1][0]["d"], "a": seals}
        self.add(saidify({**body, **over}, "KERI"))

    def rot(self, nxt=("k2",)):
        keys = self.next
        body = {"v": "", "t": "rot", "d": "", "i": self.prefix, "s": f"{len(self.events):x}",
                "p": self.events[-1][0]["d"], "kt": "1",
                "k": [verkey(f"{self.label}/{k}") for k in keys], "nt": "1",
                "n": [iss.digest(verkey(f"{self.label}/{k}").encode()) for k in nxt],
                "bt": "0", "br": [], "ba": [], "c": [], "a": []}
        self.signers.append(list(keys))
        self.add(saidify(body, "KERI"))
        self.next = list(nxt)

    def stream(self) -> bytes:
        return b"".join(iss.GENUS + iss.serialize(b) + a.encode() for b, a in self.events)


def rip(issuer: str, u: str = "") -> dict:
    return saidify({"v": "", "t": "rip", "d": "", "u": u or salt("rip"), "i": issuer, "n": "0",
                    "dt": "2026-10-15T00:00:00.000000+00:00"}, "ACDC")


def bup(rd: str, n: int, prior: str, b: str) -> dict:
    return saidify({"v": "", "t": "bup", "d": "", "rd": rd, "n": f"{n:x}", "p": prior,
                    "dt": "2026-10-15T00:00:00.000000+00:00", "b": b}, "ACDC")


def block(td: str, ts: str = "issued", u_code: str = "a") -> str:
    u = salt(f"blind/{ts}", u_code)
    return iss.blid(u, td, ts) + u + (td or iss.EMPTY) + iss._state(ts)


def acdc(issuer: str, schema_said: str, rd: str | None, a: dict, e: dict | None = None) -> dict:
    body = {"v": "", "t": "acm", "d": "", "u": salt("acdc"), "i": issuer, "rd": rd,
            "s": schema_said, "a": a}
    if rd is None:
        del body["rd"]
    if e is not None:
        body["e"] = e
    return iss.sized({**body, "d": iss.acdc_said(body)}, "ACDC")


def chain(*events: dict) -> str:
    return (iss.GENUS + b"".join(iss.serialize(e) for e in events)).hex()


def issuance(attributes=None, issuee=True):
    """A valid request and result: an issuer and a holder, and one credential issued to the
    holder under its own blindable registry."""
    attributes = {"name": "Zoe"} if attributes is None else attributes
    issuer, holder = Kel("issuer"), Kel("holder")
    said, raw_schema = schema()
    r = rip(issuer.prefix)
    a = {"d": "", "u": salt("attrs"), **({"i": holder.prefix} if issuee else {}), **attributes}
    a["d"] = iss.block_said(a)
    credential = acdc(issuer.prefix, said, r["d"], a)
    disclosure = block(credential["d"])
    update = bup(r["d"], 1, r["d"], disclosure[:44])
    issuer.ixn([{"i": r["d"], "s": "0", "d": r["d"]}])
    issuer.ixn([{"s": "1", "d": update["d"]}])
    request = {"roles": ["issuer", "holder"], "schemas": [raw_schema],
               "credentials": [{"name": "c", "issuer": "issuer", "schema": said,
                                "attributes": attributes, "registry": "bup",
                                **({"issuee": "holder"} if issuee else {})}]}
    result = {"kels": {"issuer": issuer.stream().hex(), "holder": holder.stream().hex()},
              "credentials": {"c": {"acdc": (iss.GENUS + iss.serialize(credential)).hex(),
                                    "registry": chain(r, update),
                                    "disclosure": disclosure}}}
    return request, result, {"issuer": issuer, "holder": holder, "rip": r, "bup": update,
                             "acdc": credential, "schema": said}


def direct_issuance(seal=lambda d: {"d": d}, rd=None):
    """A valid request and result for a credential asked for with no registry (this.i
    92zkyy59): the ACDC names none, and ``seal`` of its SAID is anchored on the issuer's KEL
    (nothing when ``seal`` is None)."""
    issuer, holder = Kel("issuer"), Kel("holder")
    said, raw_schema = schema()
    a = {"d": "", "u": salt("attrs"), "i": holder.prefix, "name": "Zoe"}
    a["d"] = iss.block_said(a)
    credential = acdc(issuer.prefix, said, rd, a)
    if seal is not None:
        issuer.ixn([seal(credential["d"])])
    request = {"roles": ["issuer", "holder"], "schemas": [raw_schema],
               "credentials": [{"name": "c", "issuer": "issuer", "schema": said,
                                "attributes": {"name": "Zoe"}, "registry": "none",
                                "issuee": "holder"}]}
    result = {"kels": {"issuer": issuer.stream().hex(), "holder": holder.stream().hex()},
              "credentials": {"c": {"acdc": (iss.GENUS + iss.serialize(credential)).hex()}}}
    return request, result


def as_json(value) -> str:
    return json.dumps(value)
