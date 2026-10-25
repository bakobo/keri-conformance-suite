"""Grading a keripy 1.x issuance, by verifying it (registry kind ptel-1x; docs/adapter-protocol.md,
acdc.issue; this.i 9sgwng6m).

No specification defines what keripy 1.x issues, so the forms here are keripy 1.2.14's, as
generators/spec_tables/keripy1x_issue.py transcribes them for the sedi-1x-interop companion. The
checks are issued's, in those forms, with nothing but the standard library and the runner's own
BLAKE3 and Ed25519:

- **Each identifier's KEL**: issued.verify_kel's checks, over 1.x messages (``KERI10JSON`` with
  the size in six hex digits) whose attachments are 1.00 groups: the controller signatures in an
  ``-A`` group, which counts signatures, optionally with first-seen replay couples (``-E``) and
  optionally inside one ``-V`` attachments group, which counts quadlets.
- **Each credential's registry**: keripy's ``vcp`` with no backers, self-addressing, the issuer's
  and at sequence number 0, and the credential's ``iss`` after it, each anchored on the issuer's
  verified KEL by the event seal ``{i, s, d}`` keripy anchors it with: the registry's SAID in
  ``i`` for the ``vcp``, the credential's for the ``iss``. A 1.x registry has no blinded state, so
  nothing is disclosed.
- **Each ACDC**: its version string sized to its body, keripy's fields in keripy's order, its
  SAID over its expanded form after the attribute section's own, its issuer, schema and registry,
  and its attribute section: exactly the attributes asked for, with their values, the issuee asked
  for and a 128-bit salt where it has one. A value is issued as asked, so a nested block's SAID
  and salt are the request's.

What legitimately varies is never compared, as in issued.
"""

import base64
import json

from keri_conformance import issued
from keri_conformance.issued import Unread

ACDC_FIELDS = ("v", "d", "u", "i", "ri", "s", "a", "e", "r")
ACDC_REQUIRED = ("v", "d", "i", "ri", "s", "a")
VCP_FIELDS = ("v", "t", "d", "i", "ii", "s", "c", "bt", "b", "n")
ISS_FIELDS = ("v", "t", "d", "i", "s", "ri", "dt")
# 1.00 groups an issuer's KEL may carry, by the characters each counted item takes (keripy
# 1.2.14, src/keri/core/counting.py): indexed Ed25519 signatures, and first-seen replay couples
# (a 0A sequence number and a 1AAG datetime).
ITEMS = {"-A": 88, "-E": 24 + 36}


def version(protocol: str, size: int) -> str:
    return f"{protocol}10JSON{size:06x}_"


def sized(sad: dict, protocol: str) -> dict:
    out = dict(sad)
    out["v"] = version(protocol, 0)
    out["v"] = version(protocol, len(issued.serialize(out)))
    return out


def frame(stream: bytes, protocol: bytes) -> tuple[dict, bytes, bytes]:
    """One 1.x stream's first body as JSON, its raw bytes and what follows it."""
    if stream.startswith(issued.GENUS):
        raise Unread("a 1.x stream carries a genus/version code, which keripy 1.x cannot read")
    if not stream.startswith(b'{"v":"' + protocol + b"10JSON"):
        raise Unread(f"a stream does not begin with a {protocol.decode()} 1.x JSON body")
    v = stream[6:6 + 17]
    if len(v) < 17 or v[-1:] != b"_" or any(c not in b"0123456789abcdef" for c in v[10:16]):
        raise Unread("a version string is not a 1.x JSON version string")
    size = int(v[10:16], 16)
    if size > len(stream):
        raise Unread(f"a body declares {size} bytes, but only {len(stream)} follow")
    raw = stream[:size]
    if issued._nesting(raw) > issued.MAX_NESTING:
        raise Unread(f"a body nests deeper than {issued.MAX_NESTING} levels")
    try:
        body = json.loads(raw)
    except ValueError:
        raise Unread("a body is not JSON") from None
    # The body begins with '{', so JSON that reads is an object.
    return body, raw, stream[size:]


def frames(stream: bytes, protocol: bytes) -> list[tuple[dict, bytes, bytes]]:
    """Every message in a 1.x stream, each with its attachments, which end where the next body
    begins."""
    out = []
    rest = stream
    while rest:
        if len(out) >= issued.MAX_EVENTS:
            raise Unread(f"a stream holds more than {issued.MAX_EVENTS} messages")
        body, raw, after = frame(rest, protocol)
        nxt = after.find(b'{"v":"')
        nxt = len(after) if nxt < 0 else nxt
        out.append((body, raw, after[:nxt]))
        rest = after[nxt:]
    return out


def signatures(attachments: bytes) -> list[tuple[int, bytes]]:
    """The indexed controller signatures (codes A and B, Ed25519) in a 1.x event's -A group."""
    text = attachments.decode("ascii", "replace")
    if text.startswith("-0V"):
        size, text = issued.b64_int(text[3:8]) * 4, text[8:]
    elif text.startswith("-V"):
        size, text = issued.b64_int(text[2:4]) * 4, text[4:]
    else:
        size = len(text)
    if size != len(text):
        raise Unread("an attachments group's count does not measure what follows it")
    out = []
    i = 0
    while i < len(text):
        code = text[i:i + 2]
        if code not in ITEMS:
            raise Unread(f"a 1.x event carries a {code!r} group, which the runner does not read")
        count, i = issued.b64_int(text[i + 2:i + 4]), i + 4
        body, i = text[i:i + count * ITEMS[code]], i + count * ITEMS[code]
        if len(body) != count * ITEMS[code]:
            raise Unread("an attachment group is cut short")
        if code != "-A":
            continue
        for at in range(0, len(body), 88):
            item = body[at:at + 88]
            if item[:1] not in ("A", "B"):
                raise Unread("a controller signature is not an Ed25519 indexed signature "
                             "(code A or B)")
            if len(out) >= issued.MAX_SIGNATURES:
                raise Unread(f"a key event carries more than {issued.MAX_SIGNATURES} signatures")
            if any(c not in issued.B64 for c in item[1:]):
                raise Unread("a controller signature is not Base64")
            out.append((issued.B64.index(item[1]),
                        base64.urlsafe_b64decode("AA" + item[2:])[2:]))
    return out


V1 = issued.Form(frames, sized, signatures)


def block_said(block: dict) -> str:
    """A 1.x block's SAID: over the block as it is, expanded, with d dummied."""
    return issued.digest(issued.serialize({**block, "d": issued.DUMMY}))


def _is_nonce(text) -> bool:
    """A registry nonce as a 1.x issuer makes one: keripy's 128-bit salt (0A), or signify-ts's
    random 256-bit Ed25519 seed (A)."""
    if issued._is_salt(text):
        return True
    try:
        issued.raw_of(text, "A", 32)
    except Unread:
        return False
    return True


def anchored(trunk: list[dict], i: str, s: str, d: str) -> str | None:
    """None when the issuer's verified KEL anchors the event by keripy's event seal {i, s, d};
    else why not."""
    named = False
    for body in trunk:
        seals = body.get("a")
        for seal in seals if isinstance(seals, list) else []:
            if not isinstance(seal, dict) or seal.get("d") != d:
                continue
            if seal == {"i": i, "s": s, "d": d}:
                return None
            named = True
    return ("is anchored by a seal other than keripy's event seal {i, s, d}" if named
            else "is not anchored on the issuer's verified KEL")


def check_registry(chain: bytes, issuer: str, trunk: list[dict], acdc_said: str
                   ) -> tuple[str | None, list[str]]:
    """The registry's SAID, and what fails in its vcp and the credential's iss."""
    if len(chain) > issued.MAX_STREAM:
        return None, ["the registry exceeds the runner's bounds"]
    try:
        events = frames(chain, b"KERI")
        if any(attachments for _, _, attachments in events):
            raise Unread("bytes follow a registry event's body")
    except Unread as exc:
        return None, [f"the registry cannot be read: {exc}"]
    if not events:
        return None, ["no registry was issued"]
    vcp, raw, _ = events[0]
    if vcp.get("t") != "vcp" or tuple(vcp) != VCP_FIELDS:
        return None, ["the registry does not begin with keripy's inception (vcp)"]
    problems = []
    regk = vcp["i"]
    if issued.serialize(sized(vcp, "KERI")) != raw or regk != vcp["d"] or \
            V1.said(vcp, "KERI", ("d", "i")) != vcp["d"]:
        problems.append("the registry inception's SAID does not verify")
    if vcp.get("ii") != issuer or vcp.get("s") != "0":
        problems.append("the registry inception is not the issuer's at sequence number 0")
    if vcp.get("bt") != "0" or vcp.get("b") != [] or not isinstance(vcp.get("c"), list):
        problems.append("the registry has backers, which the runner does not verify")
    if not _is_nonce(vcp.get("n")):
        problems.append("the registry inception's nonce is not a 128-bit salt or a 256-bit seed")
    why = anchored(trunk, regk, "0", vcp["d"])
    if why:
        problems.append(f"the registry inception {why}")
    if len(events) != 2:
        problems.append("the registry is not its inception and the credential's issuance")
        return regk, problems
    iss, raw, _ = events[1]
    if iss.get("t") != "iss" or tuple(iss) != ISS_FIELDS:
        problems.append("the registry's second event is not keripy's issuance (iss)")
        return regk, problems
    if issued.serialize(sized(iss, "KERI")) != raw or V1.said(iss, "KERI") != iss["d"]:
        problems.append("the issuance's SAID does not verify")
    if iss["i"] != acdc_said or iss["s"] != "0" or iss["ri"] != regk:
        problems.append("the issuance is not the credential's, at sequence number 0 of its "
                        "registry")
    if not issued._is_stamp(iss["dt"]):
        problems.append("the issuance's stamp is not of the form it must be")
    why = anchored(trunk, acdc_said, "0", iss["d"])
    if why:
        problems.append(f"the issuance {why}")
    return regk, problems


def check_acdc(raw: bytes, asked: dict, issuer: str, issuee: str | None, schema: str
               ) -> tuple[str | None, dict | None, list[str]]:
    """The ACDC's SAID, its body, and what fails in it against what was asked."""
    if len(raw) > issued.MAX_STREAM:
        return None, None, ["the ACDC is longer than the runner reads"]
    try:
        body, framed, rest = frame(raw, b"ACDC")
    except Unread as exc:
        return None, None, [f"the ACDC cannot be read: {exc}"]
    problems = []
    if rest:
        problems.append("bytes follow the ACDC's body")
    keys = list(body)
    if any(k not in ACDC_FIELDS for k in keys) or keys != sorted(keys, key=ACDC_FIELDS.index) \
            or any(k not in keys for k in ACDC_REQUIRED):
        problems.append("the ACDC's fields are not keripy 1.x's in its order")
    if "u" in body and not issued._is_salt(body["u"]):
        problems.append("the ACDC's top-level salt is not a 128-bit salt")
    if issued.serialize(sized(body, "ACDC")) != framed:
        problems.append("the ACDC's version string does not size its body")
    a = body.get("a")
    try:
        if not isinstance(a, dict) or a.get("d") != block_said(a):
            problems.append("the ACDC's attribute section is not a map whose SAID verifies")
        if V1.said(body, "ACDC") != body.get("d"):
            problems.append("the ACDC's SAID does not verify")
    except (TypeError, ValueError):
        problems.append("the ACDC's SAID cannot be computed")
    if body.get("i") != issuer:
        problems.append("the ACDC's issuer is not the identifier asked for")
    if body.get("s") != schema:
        problems.append("the ACDC's schema is not the one asked for")
    if isinstance(a, dict):
        asked_attributes = asked.get("attributes", {})
        extra = set(a) - {"d", "u", "i", *asked_attributes}
        if extra or any(k not in a for k in asked_attributes):
            problems.append("the ACDC's attributes are not exactly those asked for")
        if (issuee and a.get("i") != issuee) or (not issuee and "i" in a):
            problems.append("the ACDC's issuee is not the identifier asked for")
        if any(a.get(k) != v for k, v in asked_attributes.items()):
            problems.append("an attribute's value is not the one asked for")
        if "u" in a and not issued._is_salt(a["u"]):
            problems.append("the attribute section's salt is not a 128-bit salt")
    if "edges" in asked:
        problems.append("an edge section asked of a 1.x issuance is beyond what the runner grades")
    elif body.get("e"):
        problems.append("the ACDC has edges, and none was asked for")
    return body.get("d"), body, problems


def grade(request: dict, result: dict) -> list[str]:
    """Every check a 1.x result fails; empty when what was issued verifies and is what was
    asked."""
    problems: list[str] = []
    prefixes, trunks = {}, {}
    kels = result.get("kels") or {}
    for role in request.get("roles", []):
        stream = kels.get(role)
        if not isinstance(stream, str):
            problems.append(f"no KEL was returned for {role}")
            continue
        prefix, trunk, failed = issued.verify_kel(bytes.fromhex(stream), V1)
        prefixes[role], trunks[role] = prefix, trunk
        problems += [f"{role}'s KEL: {p}" for p in failed]
    schemas: dict[str, dict] = {}
    for raw in request.get("schemas", []):
        try:
            said_ = issued.schema_said(bytes.fromhex(raw))
            if said_:
                schemas[said_] = json.loads(bytes.fromhex(raw))
        except (ValueError, TypeError, AttributeError):
            continue
    out_all = result.get("credentials") or {}
    for asked in request.get("credentials", []):
        name = asked["name"]
        out = out_all.get(name)
        if not isinstance(out, dict) or not isinstance(out.get("acdc"), str):
            problems.append(f"{name}: no ACDC was returned")
            continue
        issuer = prefixes.get(asked["issuer"])
        issuee = prefixes.get(asked["issuee"]) if asked.get("issuee") else None
        if asked["schema"] not in schemas:
            problems.append(f"{name}: no schema in the request verifies as {asked['schema']}")
        d, body, failed = check_acdc(bytes.fromhex(out["acdc"]), asked, issuer, issuee,
                                     asked["schema"])
        problems += [f"{name}: {p}" for p in failed]
        if d is None:
            continue
        problems += [f"{name}: {p}" for p in issued._fits(body, schemas.get(asked["schema"]))]
        if "disclosure" in out:
            problems.append(f"{name}: a disclosure was returned, and a 1.x registry has no "
                            "blinded state")
        chain = bytes.fromhex(out["registry"]) if isinstance(out.get("registry"), str) else b""
        rd, failed = check_registry(chain, issuer, trunks.get(asked["issuer"], []), d)
        problems += [f"{name}: {p}" for p in failed]
        if rd is not None and body.get("ri") != rd:
            problems.append(f"{name}: the ACDC does not name its registry in ri")
    return problems
