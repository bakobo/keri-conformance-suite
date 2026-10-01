"""`kcs check-adapter`: probe an adapter's protocol behaviour without running a case.

The probes check what the runner can check from the outside with no KERI material: that hello is
valid, that ids are echoed, that a malformed request line gets an error response (or is survived),
and that an unknown op gets an error. The statelessness and quiescence probes need real KERI
streams from the keripy generator, which does not exist yet, so they are reported as not yet
available rather than faked.
"""

import json
from dataclasses import dataclass

from keri_conformance.contracts import ERROR
from keri_conformance.errors import HelloRefused
from keri_conformance.session import AdapterSession, Failure, parse_response

PROBES = ("hello", "id-echo", "malformed-request", "unknown-op", "statelessness", "quiescence")
ECHO_ID = 7919
UNKNOWN_OP = "kcs.probe.no-such-op"
NOT_YET = ("This probe needs real KERI event streams from the keripy generator, which does not "
           "exist yet.")


@dataclass(frozen=True)
class Probe:
    name: str
    status: str  # pass, fail, not-run or not-yet-available
    reason: str


def _line(message: dict) -> bytes:
    return json.dumps(message, separators=(",", ":")).encode() + b"\n"


def _answered(outcome) -> bool:
    """A result or an error response, either of which echoed the request's id."""
    return not isinstance(outcome, Failure) or outcome.kind.startswith("error-")


def _probe_echo(session: AdapterSession) -> tuple[bool, str]:
    line = session.exchange(_line({"id": ECHO_ID, "op": "cesr.parse", "stream": "2d4b"}))
    if isinstance(line, Failure):
        return False, line.detail
    # The op is deliberately not passed: this probe checks the id, not the result's shape.
    outcome = parse_response(line, ECHO_ID, "")
    if _answered(outcome):
        return True, f"The adapter echoed the request id {ECHO_ID}."
    return False, outcome.detail


def _null_id_error(line: bytes) -> bool:
    try:
        message = json.loads(line.decode("utf-8"))
    except (ValueError, RecursionError):
        return False
    return (isinstance(message, dict) and set(message) == {"id", "error"}
            and message["id"] is None and ERROR(message["error"], "error") is None)


def _probe_malformed(session: AdapterSession) -> tuple[bool, str]:
    rid = session.next_id()
    line = session.exchange(b"this line is not JSON\n" + _line(
        {"id": rid, "op": "cesr.parse", "stream": "2d4b"}))
    if isinstance(line, Failure):
        return False, line.detail
    if _answered(parse_response(line, rid, "")):
        return True, ("The adapter survived a line that is not JSON and answered the next "
                      "request.")
    if not _null_id_error(line):
        return False, ("The adapter answered a line that is not JSON with something other than "
                       'an error response whose "id" is null.')
    line = session.exchange(b"")
    if isinstance(line, Failure):
        return False, line.detail
    outcome = parse_response(line, rid, "")
    if _answered(outcome):
        return True, ("The adapter answered a line that is not JSON with an error and then "
                      "answered the next request.")
    return False, outcome.detail


def _probe_unknown_op(session: AdapterSession) -> tuple[bool, str]:
    rid = session.next_id()
    line = session.exchange(_line({"id": rid, "op": UNKNOWN_OP}))
    if isinstance(line, Failure):
        return False, line.detail
    outcome = parse_response(line, rid, UNKNOWN_OP)
    if not isinstance(outcome, Failure):
        return False, f"The adapter answered the unknown op {UNKNOWN_OP} with a result."
    if outcome.kind.startswith("error-"):
        return True, "The adapter answered an unknown op with an error response."
    return False, outcome.detail


def check_adapter(session: AdapterSession) -> list[Probe]:
    """Run every probe. A runner fault (start failure, root) propagates as RunnerError."""
    try:
        session.open()
    except HelloRefused as refusal:
        return [Probe("hello", "fail", str(refusal)),
                *(Probe(name, "not-run", "The hello probe failed, so this probe was not run.")
                  for name in PROBES[1:4]),
                *(Probe(name, "not-yet-available", NOT_YET) for name in PROBES[4:])]
    results = [Probe("hello", "pass", "The adapter's hello is valid and its features are in "
                                      "the vocabulary.")]
    for name, probe in (("id-echo", _probe_echo), ("malformed-request", _probe_malformed),
                        ("unknown-op", _probe_unknown_op)):
        try:
            session.ensure_running()
            passed, reason = probe(session)
        except HelloRefused as refusal:
            passed, reason = False, str(refusal)
        if not passed:
            session.kill()
        results.append(Probe(name, "pass" if passed else "fail", reason))
    results += [Probe(name, "not-yet-available", NOT_YET) for name in PROBES[4:]]
    return results


def render(results: list[Probe]) -> str:
    return "\n".join(f"{p.status}  {p.name}: {p.reason}" for p in results)


def exit_code(results: list[Probe]) -> int:
    return 0 if all(p.status in ("pass", "not-yet-available") for p in results) else 1
