"""Adapter protocol v1 over stdio: one JSON request per line in, one JSON response per line out.

handle_line never raises: whatever happens, it returns exactly one response line.
"""

import json
import re
import sys

from kcs_adapter_keripy import cesr, kel, keripy_api
from kcs_adapter_keripy.errors import Unsupported

PROTOCOL = 1
ADAPTER = {"name": "kcs-adapter-keripy", "version": "0.1.0"}
OPERATIONS = ["cesr.parse", "cesr.encode"]
# keri.process is declared only where keripy validates the KERI bodies the cases carry (2.XX):
# keripy main. keripy 1.2.14 reads only 1.XX bodies.
KEL_GENERATIONS = ("main",)
HEX = re.compile(r"(?:[0-9a-f]{2})*")

# The longest request line the adapter reads, in bytes, not counting its newline. A longer line
# is answered with an error whose id is null and is skipped without being held in memory.
MAX_REQUEST_LINE = 64 * 1024 * 1024
_DISCARD_CHUNK = 64 * 1024

E_OVERSIZE = "e.input.range.request-size.f"
E_MALFORMED = "e.input.format.request.f"
E_UNKNOWN_OP = "e.input.range.unknown-op.f"
E_UNDECLARED_OP = "e.feature.unsupported.undeclared-op.f"
E_VERSION = "e.feature.unsupported.protocol-version.f"
E_INTERNAL = "e.self.unknown.f"


class Malformed(Exception):
    pass


def _error(rid, kind, message):
    return {"id": rid, "error": {"kind": kind, "message": message}}


def _hex(request, field):
    value = request.get(field)
    if not isinstance(value, str) or not HEX.fullmatch(value):
        raise Malformed(f'{E_MALFORMED}: "{field}" must be a lowercase hex string.')
    return bytes.fromhex(value)


def hello(request):
    supported = request.get("supported")
    if not isinstance(supported, list):
        supported = [request.get("protocol")]
    if PROTOCOL not in supported:
        raise Unsupported(f"{E_VERSION}: This adapter implements adapter protocol version "
                          f"{PROTOCOL} only, and the runner offered {supported}.")
    keripy = cesr.api()
    operations, features = list(OPERATIONS), list(keripy.features)
    if keripy.generation in KEL_GENERATIONS:
        operations.append("keri.process")
        features += [f for f in kel.FEATURES if f not in features]
    return {"protocol": PROTOCOL, "adapter": dict(ADAPTER),
            "implementation": keripy_api.implementation(), "operations": operations,
            "features": features, "composes": []}


def _parse(request):
    return cesr.parse(_hex(request, "stream"))


def _encode(request):
    code, domain = request.get("code"), request.get("domain")
    if not isinstance(code, str) or not code:
        raise Malformed(f'{E_MALFORMED}: "code" must be a non-empty string.')
    if domain not in ("text", "binary"):
        raise Malformed(f'{E_MALFORMED}: "domain" must be "text" or "binary".')
    raw = _hex(request, "raw")
    return cesr.encode(code, raw.hex(), domain)


def _process(request):
    if cesr.api().generation not in KEL_GENERATIONS:
        raise Undeclared(request.get("op"))
    return kel.process(request)


class Undeclared(Exception):
    pass


OPS = {"hello": hello, "cesr.parse": _parse, "cesr.encode": _encode, "keri.process": _process}


def handle(request):
    rid = request.get("id")
    op = request.get("op")
    if not isinstance(op, str):  # checked first: a list or object cannot be a dictionary key
        return _error(rid, "harness", f'{E_MALFORMED}: The request has no string "op".')
    try:
        if op in OPS:
            return {"id": rid, "result": OPS[op](request)}
        if op == "keri.emit":
            raise Undeclared(op)
        return _error(rid, "harness", f"{E_UNKNOWN_OP}: {op!r} is not an operation of adapter "
                                      f"protocol version {PROTOCOL}.")
    except Undeclared:
        return _error(rid, "unsupported", f"{E_UNDECLARED_OP}: This adapter does not "
                                          f"implement {op} and did not declare it in hello.")
    except (Malformed, kel.Malformed, kel.NotQuiescent) as exc:
        return _error(rid, "harness", str(exc))
    except Unsupported as exc:
        return _error(rid, "unsupported", str(exc))
    except Exception as exc:  # noqa: BLE001 - an adapter bug must still produce one response
        return _error(rid, "harness", f"{E_INTERNAL}: The adapter failed with "
                                      f"{type(exc).__name__}: {exc}")


def _usable_id(rid) -> bool:
    return type(rid) is int and rid >= 0


def _oversize() -> bytes:
    return json.dumps(_error(None, "harness", f"{E_OVERSIZE}: The request line is longer than "
                                              f"{MAX_REQUEST_LINE} bytes, the most this adapter "
                                              "reads."), separators=(",", ":")).encode()


def handle_line(line: bytes) -> bytes:
    if len(line.rstrip(b"\n")) > MAX_REQUEST_LINE:
        return _oversize()
    try:
        request = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        request = None
    if not isinstance(request, dict):
        response = _error(None, "harness", f"{E_MALFORMED}: The request line is not a UTF-8 "
                                           "JSON object.")
    elif not _usable_id(request.get("id")):
        # The protocol: a request with no usable id is answered with an error whose id is null.
        response = _error(None, "harness", f'{E_MALFORMED}: The request has no usable "id"; '
                                           "it must be a non-negative integer.")
    else:
        response = handle(request)
    return json.dumps(response, separators=(",", ":")).encode()


def serve(stdin, stdout):
    """Answer each request line until end of file. A blank line is not JSON, so it is answered
    like any other unreadable request, with an error whose id is null. A line is read at most
    MAX_REQUEST_LINE bytes (plus its newline) at a time, so an oversize line is never held whole."""
    while True:
        line = stdin.readline(MAX_REQUEST_LINE + 1)
        if not line:
            break
        if len(line) > MAX_REQUEST_LINE and not line.endswith(b"\n"):
            while line and not line.endswith(b"\n"):  # skip the rest of the oversize line
                line = stdin.readline(_DISCARD_CHUNK)
            response = _oversize()
        else:
            response = handle_line(line)
        stdout.write(response + b"\n")
        stdout.flush()
    print("kcs-adapter-keripy: end of input, exiting", file=sys.stderr)
