"""Adapter protocol v1 over stdio: one JSON request per line in, one JSON response per line out.

handle_line never raises: whatever happens, it returns exactly one response line.
"""

import importlib.metadata
import json
import sys

from kcs_adapter_heti import issue, process, verify

PROTOCOL = 1
ADAPTER = {"name": "kcs-adapter-heti", "version": "0.1.0"}
OPERATIONS = ["acdc.verify", "acdc.issue", "keri.process"]
# What heti does itself inside acdc.verify and keri.process (README.md, "Declared features").
# heti refuses upd registries by name, so acdc.registry.upd is not declared.
FEATURES = sorted({"acdc.edges", "acdc.registry.bup", "acdc.version-2.x", *process.FEATURES})

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
# Operations of protocol version 1 this adapter does not implement.
UNDECLARED = ("cesr.parse", "cesr.encode", "keri.emit", "exn.verify", "acdc.present")


class Unsupported(Exception):
    pass


def _error(rid, kind, message):
    return {"id": rid, "error": {"kind": kind, "message": message}}


def implementation():
    """Name, version and commit of the installed heti distribution."""
    dist = importlib.metadata.distribution("heti")
    direct = dist.read_text("direct_url.json")
    vcs = json.loads(direct).get("vcs_info", {}) if direct else {}
    return {"name": "heti", "version": dist.version, "commit": vcs.get("commit_id", "unknown")}


def hello(request):
    supported = request.get("supported")
    if not isinstance(supported, list):
        supported = [request.get("protocol")]
    if PROTOCOL not in supported:
        raise Unsupported(f"{E_VERSION}: This adapter implements adapter protocol version "
                          f"{PROTOCOL} only, and the runner offered {supported}.")
    return {"protocol": PROTOCOL, "adapter": dict(ADAPTER), "implementation": implementation(),
            "operations": list(OPERATIONS), "features": list(FEATURES), "composes": []}


OPS = {"hello": hello, "acdc.verify": verify.verify, "acdc.issue": issue.issue,
       "keri.process": process.process}


def handle(request):
    rid = request.get("id")
    op = request.get("op")
    if not isinstance(op, str):  # checked first: a list or object cannot be a dictionary key
        return _error(rid, "harness", f'{E_MALFORMED}: The request has no string "op".')
    try:
        if op in OPS:
            return {"id": rid, "result": OPS[op](request)}
        if op in UNDECLARED:
            return _error(rid, "unsupported", f"{E_UNDECLARED_OP}: This adapter does not "
                                              f"implement {op} and did not declare it in hello.")
        return _error(rid, "harness", f"{E_UNKNOWN_OP}: {op!r} is not an operation of adapter "
                                      f"protocol version {PROTOCOL}.")
    except verify.Malformed as exc:
        return _error(rid, "harness", str(exc))
    except (Unsupported, process.Unsupported) as exc:
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
    """Answer each request line until end of file. A line is read at most MAX_REQUEST_LINE bytes
    (plus its newline) at a time, so an oversize line is never held whole."""
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
    print("kcs-adapter-heti: end of input, exiting", file=sys.stderr)
