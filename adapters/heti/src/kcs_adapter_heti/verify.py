"""acdc.verify through heti's public verifier, Lockbox.verify_acdc.

For every request the adapter builds a fresh lockbox in a temporary directory and hands heti the
bundle in the forms heti's API takes:

- **KELs.** heti learns another identifier's key state only by resolving its OOBI
  (Lockbox.add_other). The adapter serves each KEL of the bundle, its deliveries concatenated in
  order under the prefix its events name, from a loopback HTTP server it starts for the request,
  and resolves one OOBI per prefix. Nothing outside the bundle is served or fetched: the server
  answers only with the bundle's own bytes and stops with the request.
- **Schemas** go to Lockbox.learn_schema, one by one; a schema heti refuses is left out.
- **Registry events** are grouped by registry. heti takes a registry's chain as one
  genus/version code followed by its events' bodies, and the disclosed blinded state blocks
  separately, as the fields of each block without its group code (Lockbox.verify_acdc's
  ``tel`` and ``blinders``).
- **Far nodes** go in ``far``, each with its own registry's chain and disclosures, so heti walks
  the edges itself.

heti answers a verified ACDC with an AcdcVerdict and refuses everything else by raising a
BakoboError with a code (heti's docs/anchored-api.md). The adapter reads the code: a retryable
code, a missing input (``e.input.missing``) or an unsupported feature (``e.feature.unsupported``)
is ``incomplete``, because heti could not evaluate something; any other code is ``invalid``.

heti bounds how old its own observation of a key state may be by ``recency``; the bundle is the
whole world and the adapter consults no clock, so it passes a recency far beyond any request's
life, which makes the bound inert.
"""

import asyncio
import base64
import json
import pathlib
import re
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar

from heti.anchored.produce import Lockbox, new_recovery_code

E_MALFORMED = "e.input.format.request.f"
GENUS = b"-_AAACAA"
HEX = re.compile(r"(?:[0-9a-f]{2})*")
# A version string of a 2.00 body: protocol, version, genus version, kind, size, terminator.
VERSION = re.compile(rb'\{"v":"([A-Z]{4})[A-Za-z0-9_-]{6}([A-Z]{4})([A-Za-z0-9_-]{4})\.')
# A passcode heti accepts; the lockbox lives only for one request in a temporary directory.
PASSCODE = "kcs-adapter-heti-ephemeral-lockbox"
# Ten years in seconds: far past any request, so heti's recency bound never applies.
RECENCY = 10 * 365 * 24 * 3600
INCOMPLETE_PREFIXES = ("e.input.missing", "e.feature.unsupported")
# The profiles whose cases read direct issuance as ACDC v1.0 line 1667 does (any schema, any
# seal whose digest is the SAID), not as sedi-1's direct-issuance choice; for their requests the
# adapter turns heti's strict_direct off, and leaves heti's default on for every other request
# (this.i 9d1qrqge).
TEXT_DIRECT = ("acdc-v1.0",)


def strict_direct(request) -> bool:
    """heti's strict_direct for a request, from the profile its case belongs to."""
    return request.get("profile") not in TEXT_DIRECT


class Malformed(Exception):
    pass


def _streams(request, field) -> list[bytes]:
    values = request.get(field)
    if not isinstance(values, list):
        raise Malformed(f'{E_MALFORMED}: "{field}" must be a list.')
    out = []
    for value in values:
        stream = value.get("stream") if isinstance(value, dict) else None
        if not isinstance(stream, str) or not HEX.fullmatch(stream):
            raise Malformed(f'{E_MALFORMED}: every entry in "{field}" must be an object whose '
                            '"stream" is a lowercase hex string.')
        out.append(bytes.fromhex(stream))
    return out


def _schemas(request) -> list[bytes]:
    values = request.get("schemas")
    if not isinstance(values, list) or not all(isinstance(v, str) and HEX.fullmatch(v)
                                               for v in values):
        raise Malformed(f'{E_MALFORMED}: every entry in "schemas" must be a lowercase hex '
                        "string.")
    return [bytes.fromhex(v) for v in values]


def _presented(request) -> bytes:
    presented = request.get("presented")
    stream = presented.get("stream") if isinstance(presented, dict) else None
    if not isinstance(stream, str) or not HEX.fullmatch(stream):
        raise Malformed(f'{E_MALFORMED}: "presented" must be an object whose "stream" is a '
                        "lowercase hex string.")
    return bytes.fromhex(stream)


def split(stream: bytes) -> tuple[dict, bytes, bytes] | None:
    """A genus-pinned stream's body as JSON, its raw bytes and its attachments, or None when its
    version string does not frame a JSON body."""
    body = stream.removeprefix(GENUS)
    match = VERSION.match(body)
    if not match or match.group(2) != b"JSON":
        return None
    size = int.from_bytes(base64.urlsafe_b64decode(b"A" * 4 + match.group(3)), "big")
    raw = body[:size]
    try:
        sad = json.loads(raw)
    except (ValueError, RecursionError):  # a body nested past the parser's depth frames nothing
        return None
    return (sad, raw, body[size:]) if isinstance(sad, dict) else None


def kels(streams: list[bytes]) -> dict[str, bytes]:
    """Each prefix's deliveries, concatenated in delivery order. A stream whose body does not
    frame names no prefix, so it cannot be served under one and is left out."""
    out: dict[str, bytes] = {}
    for stream in streams:
        parts = split(stream)
        if parts and isinstance(parts[0].get("i"), str):
            out[parts[0]["i"]] = out.get(parts[0]["i"], b"") + stream
    return out


def registries(streams: list[bytes]) -> dict[str, dict]:
    """Each registry's event bodies and disclosed blinded state blocks, by the registry's SAID. An
    event the adapter cannot pass on whole (no genus/version code, or anything but one well-formed
    attachments group after its body) is left out, so heti judges without it (docs/adapter-
    protocol.md, acdc.verify: an element that cannot be read is judged without)."""
    out: dict[str, dict] = {}
    for stream in streams:
        parts = split(stream)
        if parts is None or not stream.startswith(GENUS) or not well_formed(parts[2]):
            continue
        sad, raw, attachments = parts
        rd = sad.get("rd") if sad.get("t") != "rip" else sad.get("d")
        if not isinstance(rd, str):
            continue
        group = out.setdefault(rd, {"bodies": [], "blinders": []})
        group["bodies"].append(raw)
        blinder = _blinder(attachments)
        if blinder:
            group["blinders"].append(blinder)
    return out


B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def _count(text: bytes) -> int:
    return sum(B64.index(chr(c)) << 6 * i for i, c in enumerate(reversed(text)))


def groups(attachments: bytes) -> list[tuple[bytes, bytes]]:
    """The groups in an attachments group, as (code, contents): each group code with its count
    of quadlets, small (``-X##``) or big (``--X#####``), read by its count rather than by a search,
    so text inside one group is never mistaken for another. Stops at anything it cannot read."""
    out, i = [], 0
    if attachments.startswith(b"--C"):
        i = 8
    elif attachments.startswith(b"-C"):
        i = 4
    while i < len(attachments):
        head = attachments[i:i + 8]
        try:
            if head.startswith(b"--"):
                code, size, i = head[:3], _count(head[3:8]) * 4, i + 8
            elif head.startswith(b"-"):
                code, size, i = head[:2], _count(head[2:4]) * 4, i + 4
            else:
                break
        except ValueError:
            break
        out.append((code, attachments[i:i + size]))
        i += size
    return out


def _blinder(attachments: bytes) -> str | None:
    """The fields of the first disclosed blinded state block in an attachments group; None when
    there is none, or when it is not text, which heti then judges without."""
    found = [body for code, body in groups(attachments) if code in (b"-a", b"--a")]
    try:
        return found[0].decode("ascii") if found else None
    except UnicodeDecodeError:
        return None


# The most groups an attachments group may hold for the adapter to trim it; one with more goes to
# heti as it came, so a request cannot make the adapter read millions of empty groups.
MAX_GROUPS = 64


# The groups an ACDC's attachments carry in a bundle, which the adapter may trim: a seal source
# couple pointing at the sealing event, and a disclosed blinded state block. Any other code, a
# defined one included, leaves the stream to heti as it came.
TRIMMABLE = (b"S", b"a")


def _trimmable(code: bytes) -> bool:
    """Whether a group's selector is one the adapter may trim (TRIMMABLE)."""
    return code in TRIMMABLE


def well_formed(attachments: bytes) -> bool:
    """Whether what follows a body is nothing, or exactly one attachments group whose count
    measures all of it and whose contents are groups that, read by their own counts, measure all
    of those."""
    if not attachments:
        return True
    try:
        if attachments.startswith(b"--C"):
            start, size = 8, _count(attachments[3:8]) * 4
        elif attachments.startswith(b"-C"):
            start, size = 4, _count(attachments[2:4]) * 4
        else:
            return False
        if start + size != len(attachments):
            return False
        i, read = start, 0
        while i < len(attachments):
            read += 1
            if read > MAX_GROUPS:
                return False
            if attachments.startswith(b"--", i) and _trimmable(attachments[i + 2:i + 3]):
                code, head, size = attachments[i + 2:i + 3], 8, _count(attachments[i + 3:i + 8])
            elif (attachments.startswith(b"-", i) and _trimmable(attachments[i + 1:i + 2])
                  and len(attachments) >= i + 4):
                code, head, size = attachments[i + 1:i + 2], 4, _count(attachments[i + 2:i + 4])
            else:
                return False
            contents = attachments[i + head:i + head + size * 4]
            if len(contents) != size * 4 or not _contents_read(code, contents):
                return False
            i += head + size * 4
        return i == len(attachments)
    except ValueError:
        return False


def _contents_read(code: bytes, contents: bytes) -> bool:
    """Whether a trimmable group's contents are what its code says: Base64 text throughout, and
    for seal source couples (-S) a whole number of couples, each a 128-bit sequence number (0A)
    and a Blake3-256 SAID (E)."""
    if any(chr(c) not in B64 for c in contents):
        return False
    if code == b"S":
        couples = [contents[n:n + 68] for n in range(0, len(contents), 68)]
        return all(len(c) == 68 and _canonical(c[:24], b"0A") and _canonical(c[24:], b"E")
                   for c in couples)
    return True


def _canonical(text: bytes, code: bytes) -> bool:
    """Whether a fixed-size primitive is of ``code`` and encoded canonically. Its pad is leading
    and as many bytes as the code has characters (one for a 32-byte digest under E, two for a
    16-byte number under 0A), and the bits of it that the code does not overwrite must be zero,
    as keripy's Matter requires ("nonzero midpad bytes")."""
    if not text.startswith(code):
        return False
    raw = base64.urlsafe_b64decode(b"A" * len(code) + text[len(code):])
    return not any(raw[:len(code)])


def evidence(stream: bytes, regs: dict[str, dict]) -> tuple:
    """An ACDC with its registry's chain, and its disclosures when it has any. heti reads an ACDC
    with nothing after it and finds the issuer's seal in the KEL itself, so the ACDC goes to heti
    as its genus/version code and body. Its attachments only point at the sealing event or carry
    a disclosure, which goes with the registry's. A stream that does not frame, or whose body is
    followed by anything but one well-formed attachments group, goes as it came, for heti to
    refuse."""
    parts = split(stream)
    if parts is None or not stream.startswith(GENUS) or not well_formed(parts[2]):
        return (stream, None)
    sad, raw, attachments = parts
    acdc = GENUS + raw
    rd = sad.get("rd")
    group = regs.get(rd) if isinstance(rd, str) else None
    if not group:
        return (acdc, None)
    blinders = group["blinders"] + [b for b in [_blinder(attachments)] if b]
    tel = GENUS + b"".join(group["bodies"])
    return (acdc, tel, blinders) if blinders else (acdc, tel)


class _Kels(BaseHTTPRequestHandler):
    served: ClassVar[dict[str, bytes]] = {}

    def do_GET(self):
        parts = [p for p in self.path.split("/") if p]
        body = self.served.get(parts[1]) if len(parts) >= 2 and parts[0] == "oobi" else None
        self.send_response(200 if body else 404)
        self.send_header("Content-Type", "application/cesr")
        self.send_header("Content-Length", str(len(body or b"")))
        self.end_headers()
        self.wfile.write(body or b"")

    def log_message(self, format, *args):
        pass


def _server(served: dict[str, bytes]) -> ThreadingHTTPServer:
    handler = type("Kels", (_Kels,), {"served": served})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def grade(error) -> str:
    code = getattr(error, "code", "") or ""
    if getattr(error, "retryable", False) or code.startswith(INCOMPLETE_PREFIXES):
        return "incomplete"
    return "invalid"


async def _judge(home: pathlib.Path, served, schemas, regs, far, presented, given=None,
                 kel_streams=(), strict=True) -> dict:
    server = _server(served)
    box = Lockbox.create(path=home, passcode=PASSCODE, recovery=new_recovery_code())
    try:
        for raw in schemas:
            try:
                box.learn_schema(raw=raw)
            except Exception as exc:  # noqa: BLE001 - a schema heti refuses is not in its world
                print(f"heti refused a schema: {type(exc).__name__}: {exc}", file=sys.stderr)
        port = server.server_address[1]
        for aid in served:
            try:
                await box.add_other(oobi=f"http://127.0.0.1:{port}/oobi/{aid}")
            except Exception as exc:  # noqa: BLE001 - a KEL heti refuses is not in its world
                print(f"heti refused the KEL of {aid}: {type(exc).__name__}: {exc}",
                      file=sys.stderr)
        acdc, *rest = evidence(presented, regs)
        tel = rest[0] if rest else None
        blinders = rest[1] if len(rest) > 1 else None
        try:
            verdict = await box.verify_acdc(acdc=acdc, tel=tel, recency=RECENCY,
                                            blinders=blinders, far=far or None,
                                            strict_direct=strict)
        except Exception as exc:
            code = getattr(exc, "code", None)
            if code is None:
                raise
            return {"verdict": grade(exc), "reason": f"{code}: {exc}", "registry": None,
                    "edges": []}
        head = None
        if verdict.registry is not None:
            head = {"rd": verdict.registry, "n": verdict.head_sn, "d": verdict.head_said,
                    "td": verdict.said, "ts": verdict.state}
        # heti reports which far nodes it walked, not whether each edge held: in an OR group one
        # member may fail while the group holds. So no edge is reported (the protocol asks only
        # for what was evaluated, and heti does not expose a result per edge).
        if given is not None:
            from kcs_adapter_heti import presentation
            problem = presentation.judge(given, presented, list(kel_streams))
            if problem is not None:
                return {"verdict": problem[0], "reason": problem[1], "registry": head,
                        "edges": []}
        return {"verdict": "valid", "reason": "heti verified the ACDC", "registry": head,
                "edges": []}
    finally:
        box.close()
        server.shutdown()
        server.server_close()


def verify(request) -> dict:
    kel_streams = _streams(request, "kels")
    registry_streams = _streams(request, "registry")
    acdc_streams = _streams(request, "acdcs")
    schemas = _schemas(request)
    presented = _presented(request)
    from kcs_adapter_heti import presentation  # it reads this module's helpers
    given = presentation.context(request)
    regs = registries(registry_streams)
    far = [evidence(s, regs) for s in acdc_streams]
    with tempfile.TemporaryDirectory(prefix="kcs-adapter-heti-") as home:
        return asyncio.run(_judge(pathlib.Path(home) / "lockbox", kels(kel_streams), schemas,
                                  regs, far, presented, given, kel_streams,
                                  strict_direct(request)))
