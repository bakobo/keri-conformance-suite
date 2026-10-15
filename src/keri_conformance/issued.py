"""Grading what an issuer issued, by verifying it (this.i 2u2ps8mt; docs/adapter-protocol.md,
acdc.issue).

An implementation issues with its own keys, salts, nonces and clock, so the runner never compares
its bytes with a case's. It verifies the result instead, with nothing but the standard library and
the runner's own BLAKE3 and Ed25519:

- **Each identifier's KEL**: every event's SAID, sequence number and prior; an inception's prefix;
  every event's indexed controller signatures against the key state it is signed under, to its
  signing threshold, and a rotation's new keys against the prior event's next-key digests and
  threshold. Witnessed and delegated KELs, weighted thresholds and big signature codes are beyond
  what the runner verifies; a KEL that uses one is reported unverifiable, never passed.
- **Each credential's registry**: the blindable registry's inception and updates, their SAIDs,
  sequence numbers and priors, each anchored on the issuer's verified KEL by a seal the profile
  accepts ({s, d}, or {i, s, d} whose i is the registry's SAID), and the head update's disclosed blinded
  state block, whose BLID is the update's b and which names the credential as issued.
- **Each ACDC**: its version string sized to its body, its fields in the order of ACDC line 32,
  its most compact SAID, its issuer and schema, its attribute block (a SAIDed block with a salt,
  the issuee, and exactly the attributes asked for, with their values), its registry, and each
  edge asked for (the far credential's SAID and the operators asked for).

What legitimately varies is never compared: SAIDs, salts, nonces, stamps, prefixes and keys are
checked for what they must be, not for what they are. Every check that fails is reported, and a
result passes only when none does.

Every count and size is bounded before anything is hashed or verified (docs/profiles/sedi-test-
plan.md, item 13), so the work is bounded by the bounds, not by what an adapter returned.
"""

import base64
import json

from keri_conformance import blake3, ed25519

GENUS = b"-_AAACAA"
B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
DUMMY = "#" * 44
EMPTY = "1AAP"
ACDC_FIELDS = ("v", "t", "d", "u", "i", "rd", "s", "a", "A", "e", "r")
RIP_FIELDS = ("v", "t", "d", "u", "i", "n", "dt")
BUP_FIELDS = ("v", "t", "d", "rd", "n", "p", "dt", "b")
# Tag codes by the number of characters they carry (CESR master table).
TAGS = {2: "0K", 3: "X", 4: "1AAF", 6: "0M", 7: "Y", 8: "1AAN", 10: "0O", 11: "Z"}
UNARY = ("I2I", "NI2I", "DI2I", "E1E")

# Bounds on a result, checked before any hashing or signature check.
MAX_STREAM = 1024 * 1024  # bytes in one KEL, one ACDC or one registry
MAX_EVENTS = 64  # key events in one KEL, registry events in one registry
MAX_SIGNATURES = 16  # controller signatures on one key event
MAX_KEYS = 16  # signing keys or next-key digests in one establishment event


class Unread(Exception):
    """Something in the result cannot be read as what it must be."""


# -- CESR text primitives ---------------------------------------------------------------------


def b64_int(text: str) -> int:
    value = 0
    for char in text:
        if char not in B64:
            raise Unread(f"{text!r} is not Base64")
        value = value * 64 + B64.index(char)
    return value


def int_b64(value: int, size: int) -> str:
    return "".join(B64[(value >> 6 * i) & 63] for i in reversed(range(size)))


def qb64(code: str, raw: bytes) -> str:
    pad = (3 - len(raw) % 3) % 3
    text = base64.urlsafe_b64encode(b"\x00" * pad + raw).decode()
    return code + text[len(code):]


def raw_of(text: str, code: str, size: int) -> bytes:
    """The raw bytes of a fixed-size primitive of ``code`` holding ``size`` bytes."""
    pad = (3 - size % 3) % 3
    width = (size + pad) * 4 // 3
    if not isinstance(text, str) or len(text) != width or not text.startswith(code) or \
            any(c not in B64 for c in text):
        raise Unread(f"{text!r} is not a {code} primitive")
    return base64.urlsafe_b64decode("A" * len(code) + text[len(code):])[pad:]


def digest(data: bytes) -> str:
    return qb64("E", blake3.digest(data))


# -- bodies -----------------------------------------------------------------------------------


def serialize(value) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def version(protocol: str, size: int) -> str:
    return f"{protocol}CAACAAJSON{int_b64(size, 4)}."


def sized(sad: dict, protocol: str) -> dict:
    out = dict(sad)
    out["v"] = version(protocol, 0)
    out["v"] = version(protocol, len(serialize(out)))
    return out


def said(sad: dict, protocol: str, labels=("d",)) -> str:
    return digest(serialize(sized({**sad, **{label: DUMMY for label in labels}}, protocol)))


def frame(stream: bytes, protocol: bytes) -> tuple[dict, bytes, bytes]:
    """One genus-pinned stream's body as JSON, its raw bytes and its attachments."""
    rest = stream.removeprefix(GENUS)
    start = b'{"v":"' + protocol
    if not rest.startswith(start):
        raise Unread(f"a stream does not begin with a {protocol.decode()} JSON body")
    v = rest[6:6 + 19]
    if len(v) < 19 or v[-1:] != b"." or v[10:14] != b"JSON":
        raise Unread("a version string is not a 2.00 JSON version string")
    size = b64_int(v[14:18].decode("ascii", "replace"))
    if size > len(rest):
        raise Unread(f"a body declares {size} bytes, but only {len(rest)} follow")
    raw = rest[:size]
    try:
        body = json.loads(raw)
    except ValueError:
        raise Unread("a body is not JSON") from None
    # The body begins with '{', so JSON that reads is an object.
    return body, raw, rest[size:]


def frames(stream: bytes, protocol: bytes) -> list[tuple[dict, bytes, bytes]]:
    """Every message in a stream of genus-pinned messages, each with its attachments."""
    out = []
    rest = stream
    while rest:
        if len(out) >= MAX_EVENTS:
            raise Unread(f"a stream holds more than {MAX_EVENTS} messages")
        body, raw, after = frame(rest, protocol)
        # A message's attachments end where the next message begins, with or without its own
        # genus/version code.
        ends = [i for i in (after.find(GENUS), after.find(b'{"v":"')) if i >= 0]
        nxt = min(ends) if ends else len(after)
        attachments, rest = after[:nxt], after[nxt:]
        out.append((body, raw, attachments))
    return out


# -- attachments ------------------------------------------------------------------------------


def groups(attachments: bytes) -> list[tuple[str, str]]:
    """The groups inside an attachments group, as (code, contents), read by their quadlet counts
    in the text domain, small (``-X##``) or big (``--X#####``)."""
    text = attachments.decode("ascii", "replace")
    if text.startswith("--C"):
        i = 8
    elif text.startswith("-C"):
        i = 4
    else:
        return []
    out = []
    while i < len(text):
        if text.startswith("--", i):
            code, size, i = text[i:i + 3], b64_int(text[i + 3:i + 8]) * 4, i + 8
        elif text.startswith("-", i):
            code, size, i = text[i:i + 2], b64_int(text[i + 2:i + 4]) * 4, i + 4
        else:
            raise Unread("an attachments group holds something that is not a group")
        if i + size > len(text):
            raise Unread("an attachment group is cut short")
        out.append((code, text[i:i + size]))
        i += size
    return out


def signatures(attachments: bytes) -> list[tuple[int, bytes]]:
    """The indexed controller signatures (codes A and B, Ed25519) in a -K group."""
    out = []
    for code, body in groups(attachments):
        if code != "-K":
            continue
        for at in range(0, len(body), 88):
            item = body[at:at + 88]
            if item[:1] not in ("A", "B") or len(item) != 88:
                raise Unread("a controller signature is not an Ed25519 indexed signature "
                             "(code A or B)")
            if len(out) >= MAX_SIGNATURES:
                raise Unread(f"a key event carries more than {MAX_SIGNATURES} signatures")
            if item[1] not in B64 or any(c not in B64 for c in item[2:]):
                raise Unread("a controller signature is not Base64")
            out.append((B64.index(item[1]), base64.urlsafe_b64decode("AA" + item[2:])[2:]))
    return out


# -- KELs -------------------------------------------------------------------------------------


def _threshold(value) -> int:
    if not isinstance(value, str):
        raise Unread("a weighted threshold is beyond what the runner verifies")
    try:
        return int(value, 16)
    except ValueError:
        raise Unread(f"the threshold {value!r} is not hex") from None


def _signed(raw: bytes, keys: list[str], sigs: list[tuple[int, bytes]]) -> set[int]:
    """The indices of ``keys`` whose signature over ``raw`` verifies."""
    good = set()
    for index, signature in sigs:
        if index < len(keys) and ed25519.verify(raw_of(keys[index], "D", 32), raw, signature):
            good.add(index)
    return good


def verify_kel(stream: bytes) -> tuple[str, list[dict], list[str]]:
    """The prefix, the verified events' bodies in order, and what failed. The KEL stops at the
    first event that fails."""
    if len(stream) > MAX_STREAM:
        return "", [], [f"the KEL is longer than {MAX_STREAM} bytes"]
    try:
        events = frames(stream, b"KERI")
    except Unread as exc:
        return "", [], [f"the KEL cannot be read: {exc}"]
    if not events:
        return "", [], ["the KEL is empty"]
    trunk: list[dict] = []
    prefix, keys, nxt, nt, kt = "", [], [], 0, 1
    for sn, (body, raw, attachments) in enumerate(events):
        where = f"event {sn}"
        try:
            ilk = body.get("t")
            if ilk not in ("icp", "rot", "ixn"):
                return prefix, trunk, [(f"{where} is a {ilk!r} event, which the runner does not "
                                       "verify")]
            if body.get("s") != f"{sn:x}":
                return prefix, trunk, [f"{where} has sequence number {body.get('s')!r}"]
            if (ilk == "icp") != (sn == 0):
                return prefix, trunk, [(f"{where} is a {ilk}, and a KEL begins with its only "
                                       "inception")]
            labels = ("d", "i") if ilk == "icp" else ("d",)
            if serialize(sized(body, "KERI")) != raw or said(body, "KERI", labels) != body["d"]:
                return prefix, trunk, [f"{where}'s SAID does not verify"]
            sigs = signatures(attachments)
            if ilk == "icp":
                prefix = body.get("i")
                if prefix != body["d"]:
                    return prefix, trunk, [f"{where}'s prefix is not its SAID"]
            elif body.get("i") != prefix or body.get("p") != trunk[-1]["d"]:
                return prefix, trunk, [f"{where} does not follow the event before it"]
            if ilk in ("icp", "rot"):
                if body.get("bt") != "0" or body.get("b") or body.get("ba") or body.get("br"):
                    return prefix, trunk, [(f"{where} has witnesses, which the runner does not "
                                           "verify")]
                new = body.get("k")
                if not isinstance(new, list) or not new or len(new) > MAX_KEYS:
                    return prefix, trunk, [f"{where} has no signing keys the runner reads"]
                if ilk == "rot":
                    committed = [k for k in new if digest(k.encode()) in nxt]
                    if len(committed) != len(new) or len(_signed(raw, new, sigs)) < nt:
                        return prefix, trunk, [(f"{where}'s keys do not satisfy the prior next-"
                                               "key commitment")]
                keys = new
                nxt = body.get("n") or []
                nt = _threshold(body.get("nt"))
                if len(nxt) > MAX_KEYS:
                    return prefix, trunk, [f"{where} commits to more than {MAX_KEYS} next keys"]
                if not nxt or nt < 1:
                    return prefix, trunk, [(f"{where} commits to no next keys, so its "
                                            "identifier is not transferable")]
            threshold = _threshold(body.get("kt")) if ilk != "ixn" else kt
            kt = threshold
            if len(_signed(raw, keys, sigs)) < max(threshold, 1):
                return prefix, trunk, [f"{where} is not signed to its threshold"]
        except (Unread, KeyError, TypeError, AttributeError) as exc:
            return prefix, trunk, [f"{where} cannot be verified: {exc}"]
        trunk.append(body)
    return prefix, trunk, []


def sealed(trunk: list[dict], rd: str, n: str, d: str) -> str | None:
    """None when the issuer's verified KEL anchors the event in a shape the profile accepts;
    else why not."""
    named = False
    for body in trunk:
        for seal in body.get("a") or []:
            if not isinstance(seal, dict) or seal.get("d") != d:
                continue
            if seal in ({"s": n, "d": d}, {"i": rd, "s": n, "d": d}):
                return None
            named = True
    return ("is anchored by a seal of a shape the profile refuses" if named
            else "is not anchored on the issuer's verified KEL")


# -- ACDCs ------------------------------------------------------------------------------------


def is_saided(value) -> bool:
    return isinstance(value, dict) and isinstance(value.get("d"), str)


def compact_value(value):
    if is_saided(value):
        return block_said(value)
    if isinstance(value, dict):
        return {k: compact_value(v) for k, v in value.items()}
    return value


def block_said(block: dict) -> str:
    return digest(serialize({**{k: compact_value(v) for k, v in block.items()}, "d": DUMMY}))


def acdc_said(acdc: dict) -> str:
    out = {}
    for key, value in acdc.items():
        if key == "s" and isinstance(value, dict):
            out[key] = digest(serialize(sized({**value, "$id": DUMMY}, "ACDC")))
        elif key == "A" and isinstance(value, list):
            saids = [b if isinstance(b, str) else block_said(b) for b in value[1:]]
            out[key] = digest(serialize([DUMMY] + saids))
        else:
            out[key] = compact_value(value)
    return said(out, "ACDC")


def schema_said(raw: bytes) -> str:
    """The SAID a schema's bytes verify as, or "" when they are not a schema with a SAID."""
    schema = json.loads(raw)
    if not isinstance(schema, dict) or not isinstance(schema.get("$id"), str):
        return ""
    said_ = digest(serialize({**schema, "$id": DUMMY}))
    return said_ if said_ == schema["$id"] else ""


def _state(ts: str) -> str:
    if ts == "":
        return EMPTY
    if len(ts) not in TAGS or any(c not in B64 for c in ts):
        raise Unread(f"the state {ts!r} is not a Tag the runner reads")
    return TAGS[len(ts)] + ts


def blid(u: str, td: str, ts: str) -> str:
    return digest((DUMMY + u + (td or EMPTY) + _state(ts)).encode())


def disclosed(text: str) -> tuple[str, str, str, str]:
    """A disclosed blinded state block's text, [d, u, td, ts], read field by field."""
    d, rest = text[:44], text[44:]
    if rest.startswith("0A"):
        u, rest = rest[:24], rest[24:]
    elif rest.startswith("a"):
        u, rest = rest[:44], rest[44:]
    else:
        raise Unread("a disclosure's salt is not a 128-bit (0A) or 256-bit (a) salt")
    if rest.startswith(EMPTY):
        td, rest = "", rest[4:]
    else:
        td, rest = rest[:44], rest[44:]
    for size, code in TAGS.items():
        if rest.startswith(code) and len(rest) == len(code) + size:
            return d, u, td, rest[len(code):]
    if rest == EMPTY:
        return d, u, td, ""
    raise Unread("a disclosure's state is not a Tag the runner reads")


def check_registry(chain: bytes, disclosure, issuer: str, trunk: list[dict], acdc_said_: str
                   ) -> tuple[str | None, list[str]]:
    """The registry's SAID, and what fails in its chain, its anchoring and the state its head's
    disclosure records. ``chain`` is the registry's events in order; ``disclosure`` is the head
    update's blinded state block as text, its group code optional."""
    if len(chain) > MAX_STREAM:
        return None, ["the registry exceeds the runner's bounds"]
    problems = []
    try:
        events = frames(chain, b"ACDC")
    except Unread as exc:
        return None, [f"the registry cannot be read: {exc}"]
    if not events:
        return None, ["no registry was issued"]
    rip, raw, _ = events[0]
    if rip.get("t") != "rip" or tuple(rip) != RIP_FIELDS:
        return None, ["the registry does not begin with a blindable inception (rip)"]
    rd = rip["d"]
    if serialize(sized(rip, "ACDC")) != raw or said(rip, "ACDC") != rd:
        problems.append("the registry inception's SAID does not verify")
    if rip.get("i") != issuer or rip.get("n") != "0":
        problems.append("the registry inception is not the issuer's at sequence number 0")
    why = sealed(trunk, rd, "0", rd)
    if why:
        problems.append(f"the registry inception {why}")
    prior, head = rd, None
    for n, (bup, raw, _) in enumerate(events[1:], start=1):
        if bup.get("t") != "bup" or tuple(bup) != BUP_FIELDS:
            problems.append(f"registry event {n} is not a blindable update (bup)")
            break
        if serialize(sized(bup, "ACDC")) != raw or said(bup, "ACDC") != bup["d"]:
            problems.append(f"registry event {n}'s SAID does not verify")
        if bup["rd"] != rd or bup["n"] != f"{n:x}" or bup["p"] != prior:
            problems.append(f"registry event {n} does not follow the event before it")
        why = sealed(trunk, rd, f"{n:x}", bup["d"])
        if why:
            problems.append(f"registry event {n} {why}")
        head, prior = bup, bup["d"]
    if head is None:
        problems.append("the registry has no update that issues the credential")
    elif not isinstance(disclosure, str) or not disclosure:
        problems.append("no disclosure of the head's blinded state was returned")
    else:
        text = disclosure
        for code in ("--a", "-a"):
            if text.startswith(code):
                text = text[len(code) + (5 if code == "--a" else 2):]
                break
        try:
            d, u, td, ts = disclosed(text)
            if d != head["b"] or blid(u, td, ts) != d:
                problems.append("the head's disclosed state does not hash to the update's BLID")
            elif td != acdc_said_ or ts != "issued":
                problems.append("the head's disclosed state does not record the credential as "
                                "issued")
        except Unread as exc:
            problems.append(f"the head's disclosure cannot be read: {exc}")
    return rd, problems


def _edges(asked: dict, e, near: dict, issued: dict[str, dict]) -> list[str]:
    """What fails in an issued edge section against the one asked for. ``issued`` maps each
    credential already checked to its body."""
    if not isinstance(e, dict):
        return ["the edge section is not a map"]
    problems = []
    if asked.get("o", "AND") != e.get("o", "AND"):
        problems.append("an edge group's operator is not the one asked for")
    labels = {k for k in asked if k != "o"}
    if labels != {k for k in e if k not in ("d", "u", "o")}:
        problems.append("the edge section's labels are not the ones asked for")
    for label in sorted(labels & set(e)):
        want, got = asked[label], e[label]
        if not isinstance(got, dict):
            problems.append(f"the edge {label} is not a map")
        elif "credential" not in want:
            problems += _edges(want, got, near, issued)
        else:
            problems += _edge(label, want, got, near, issued.get(want["credential"]))
    return problems


def _issuee(body: dict | None):
    a = body.get("a") if isinstance(body, dict) else None
    return a.get("i") if isinstance(a, dict) else None


def _edge(label: str, want: dict, got: dict, near: dict, far: dict | None) -> list[str]:
    """What fails in one issued edge: its own SAID (edge-said), its far node, the operators
    asked for (or the default when none was), and whether they hold between the two credentials
    as issued. The runner's identifiers are never delegated, so DI2I holds as I2I does."""
    if not isinstance(got.get("d"), str):
        return [f"the edge {label} carries no SAID of its own in d"]
    if far is None or got.get("n") != far.get("d"):
        return [f"the edge {label} does not name the credential asked for"]
    default = ["I2I" if _issuee(far) else "NI2I"]
    if _ops(got.get("o", default)) != _ops(want.get("o", default)):
        return [f"the edge {label}'s operators are not the ones asked for"]
    ops = _ops(want.get("o", default))
    relation = next((op for op in reversed(ops) if op in ("I2I", "NI2I", "DI2I")), None)
    holds = True
    if relation in ("I2I", "DI2I"):
        holds = _issuee(far) is not None and near.get("i") == _issuee(far)
    if "E1E" in ops:
        holds = holds and _issuee(far) is not None and _issuee(near) == _issuee(far)
    return [] if holds else [(f"the edge {label}'s operators do not hold between the "
                              "credentials issued")]


def _ops(o) -> list:
    return o if isinstance(o, list) else [o]


def _blocks_verify(value) -> bool:
    """Whether every SAIDed block in ``value``, at any depth, verifies against its own SAID."""
    if isinstance(value, dict):
        if is_saided(value) and block_said(value) != value["d"]:
            return False
        return all(_blocks_verify(v) for v in value.values())
    if isinstance(value, list):
        return all(_blocks_verify(v) for v in value)
    return True


def check_acdc(raw: bytes, asked: dict, issuer: str, issuee: str | None, schema: str,
               issued: dict[str, dict]) -> tuple[str | None, dict | None, list[str]]:
    """The ACDC's SAID, its body, and what fails in it against what was asked."""
    if len(raw) > MAX_STREAM:
        return None, None, ["the ACDC is longer than the runner reads"]
    try:
        if not raw.startswith(GENUS):
            raise Unread("it does not begin with the genus/version code")
        body, framed, rest = frame(raw, b"ACDC")
    except Unread as exc:
        return None, None, [f"the ACDC cannot be read: {exc}"]
    problems = []
    if body.get("t") != "acm":
        problems.append("the ACDC's type is not acm, the type of an ACDC with an attribute map")
    if rest:
        problems.append("bytes follow the ACDC's body")
    keys = list(body)
    if any(k not in ACDC_FIELDS for k in keys) or keys != sorted(keys, key=ACDC_FIELDS.index):
        problems.append("the ACDC's fields are not those of ACDC line 32 in its order")
    if serialize(sized(body, "ACDC")) != framed:
        problems.append("the ACDC's version string does not size its body")
    try:
        if acdc_said(body) != body.get("d"):
            problems.append("the ACDC's SAID does not verify")
        elif not all(_blocks_verify(body.get(section)) for section in ("a", "e", "r")):
            problems.append("a SAIDed block in the ACDC does not verify against its own SAID")
    except (TypeError, ValueError, AttributeError):
        problems.append("the ACDC's SAID cannot be computed")
    if body.get("i") != issuer:
        problems.append("the ACDC's issuer is not the identifier asked for")
    if body.get("s") != schema:
        problems.append("the ACDC's schema is not the one asked for")
    a = body.get("a")
    asked_attributes = asked.get("attributes", {})
    if not isinstance(a, dict):
        problems.append("the ACDC's attributes are not an expanded map")
    else:
        # d and u are optional (ACDC lines 264 to 272); a salt that is there must be one.
        extra = set(a) - {"d", "u", "i", *asked_attributes}
        if extra or any(k not in a for k in asked_attributes):
            problems.append("the ACDC's attributes are not exactly those asked for")
        if (issuee and a.get("i") != issuee) or (not issuee and "i" in a):
            problems.append("the ACDC's issuee is not the identifier asked for")
        if any(a.get(k) != v for k, v in asked_attributes.items()):
            problems.append("an attribute's value is not the one asked for")
        if "u" in a:
            try:
                raw_of(a["u"], "0A", 16)
            except Unread:
                problems.append("the attribute block's salt is not a 128-bit salt")
    if "edges" in asked:
        problems += _edges(asked["edges"], body.get("e"), body, issued)
    elif body.get("e"):
        problems.append("the ACDC has edges, and none was asked for")
    return body.get("d"), body, problems


def grade(request: dict, result: dict) -> list[str]:
    """Every check the result fails; empty when what was issued verifies and is what was asked."""
    problems: list[str] = []
    prefixes, trunks = {}, {}
    kels = result.get("kels") or {}
    for role in request.get("roles", []):
        stream = kels.get(role)
        if not isinstance(stream, str):
            problems.append(f"no KEL was returned for {role}")
            continue
        prefix, trunk, failed = verify_kel(bytes.fromhex(stream))
        prefixes[role], trunks[role] = prefix, trunk
        problems += [f"{role}'s KEL: {p}" for p in failed]
    issued = result.get("credentials") or {}
    bodies: dict[str, dict] = {}
    schemas = set()
    for raw in request.get("schemas", []):
        try:
            schemas.add(schema_said(bytes.fromhex(raw)))
        except (ValueError, TypeError, AttributeError):
            continue
    # Far credentials first, so an edge can be checked against its far node's SAID.
    for asked in _ordered(request.get("credentials", [])):
        name = asked["name"]
        out = issued.get(name)
        if not isinstance(out, dict) or not isinstance(out.get("acdc"), str):
            problems.append(f"{name}: no ACDC was returned")
            continue
        issuer = prefixes.get(asked["issuer"])
        issuee = prefixes.get(asked["issuee"]) if asked.get("issuee") else None
        if asked["schema"] not in schemas:
            problems.append(f"{name}: no schema in the request verifies as {asked['schema']}")
        d, body, failed = check_acdc(bytes.fromhex(out["acdc"]), asked, issuer, issuee,
                                     asked["schema"], bodies)
        problems += [f"{name}: {p}" for p in failed]
        if d is None:
            continue
        bodies[name] = body
        chain = bytes.fromhex(out["registry"]) if isinstance(out.get("registry"), str) else b""
        rd, failed = check_registry(chain, out.get("disclosure"), issuer,
                                    trunks.get(asked["issuer"], []), d)
        problems += [f"{name}: {p}" for p in failed]
        if rd is not None and body.get("rd") != rd:
            problems.append(f"{name}: the ACDC does not name its registry in rd")
    return problems


def _ordered(credentials: list[dict]) -> list[dict]:
    """The requested credentials, each after every credential its edges name."""
    by_name = {c["name"]: c for c in credentials}
    out, seen = [], set()

    def names(edges):
        for value in (edges or {}).values():
            if isinstance(value, dict):
                yield from ([value["credential"]] if "credential" in value else names(value))

    def visit(name, path):
        if name in seen or name not in by_name or name in path:
            return
        for far in names(by_name[name].get("edges")):
            visit(far, path | {name})
        seen.add(name)
        out.append(by_name[name])

    for c in credentials:
        visit(c["name"], set())
    return out
