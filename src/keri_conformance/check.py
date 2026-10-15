"""`kcs check-adapter`: probe an adapter's protocol behaviour without running a case.

The probes check what the runner can check from the outside with no KERI material: that hello is
valid, that ids are echoed, that a request line that is not JSON gets an error response whose id
is null and the adapter then answers the next request, and that an unknown op gets an error; and,
for an adapter that lists acdc.issue or acdc.present, or declares acdc.presentation, that a request
the protocol cannot read gets an error rather than a result. The statelessness and quiescence probes need real KERI
streams from the keripy generator, which does not exist yet, so they are reported as not yet
available rather than faked.
"""

import json
from dataclasses import dataclass

from keri_conformance.contracts import ERROR
from keri_conformance.errors import HelloRefused
from keri_conformance.jsonfile import loads
from keri_conformance.session import AdapterSession, Failure, parse_response

PROBES = ("hello", "id-echo", "malformed-request", "unknown-op", "statelessness", "quiescence",
          "issue-malformed", "present-malformed", "presentation-malformed", "issue-determinism",
          "present-independence")
# The probes for the issuer and holder operations and the presentation context, each run only
# against an adapter that lists the operation (and declares the feature, where one is named), and
# the probes for them that need a real issuance to send.
OP_PROBES = (("issue-malformed", "acdc.issue", None), ("present-malformed", "acdc.present", None),
             ("presentation-malformed", "acdc.verify", "acdc.presentation"))
OP_NOT_YET = (("issue-determinism", "acdc.issue"), ("present-independence", "acdc.present"))
NOT_YET_ACDC = ("This probe sends a real issuance, taken from the suite's first acdc.issue case, "
                "which does not exist yet.")
# Requests this protocol cannot read: an issuance with no ACDC template, a presentation in a
# disclosure form the protocol does not define, and a verification whose presentation context
# names no message and no verifier.
_VERIFY = {"perspective": {"role": "validator"}, "kels": [], "registry": [], "schemas": [],
           "acdcs": [], "presented": {"stream": "2d4b"}}
_CONTEXT = {"messages": [{"stream": "2d4b", "source": "holder"}], "verifier": "EKcsProbeVerifier"}
# A well-formed request an op's malformed variants are measured against: an adapter must answer it
# with a result, so that an error on a variant shows the variant's own defect was read, not that
# the adapter refuses the request whatever its context.
CONTROL = {"acdc.verify": {**_VERIFY, "presentation": _CONTEXT}}
MALFORMED = {
    "acdc.verify": [
        {**_VERIFY, "presentation": {**_CONTEXT, "messages": []}},
        {**_VERIFY, "presentation": {**_CONTEXT, "verifier": ""}},
        {**_VERIFY, "presentation": {"messages": _CONTEXT["messages"]}},
        {**_VERIFY, "presentation": {"verifier": _CONTEXT["verifier"]}},
    ],
    "acdc.issue": {"kels": [], "seeds": {}, "registry": []},
    "acdc.present": {"perspective": {"role": "holder"}, "kels": [], "registry": [], "schemas": [],
                     "acdcs": [], "held": {"stream": "2d4b"},
                     "disclosure": {"form": "kcs-probe-no-such-form"}},
}
ECHO_ID = 7919
UNKNOWN_OP = "kcs.probe.no-such-op"
NOT_YET = ("This probe needs real KERI event streams from the keripy generator, which does not "
           "exist yet.")


@dataclass(frozen=True)
class Probe:
    name: str
    status: str  # pass, fail, not-run, not-applicable or not-yet-available
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
        message = loads(line.decode("utf-8"))
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
        return False, ("The adapter dropped a line that is not JSON without answering it; it "
                       'must answer such a line with an error response whose "id" is null.')
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


def _ask(session: AdapterSession, op: str, fields: dict):
    rid = session.next_id()
    line = session.exchange(_line({"id": rid, "op": op, **fields}))
    return line if isinstance(line, Failure) else parse_response(line, rid, op)


def _probe_malformed_op(session: AdapterSession, op: str) -> tuple[bool, str]:
    if op in CONTROL:
        outcome = _ask(session, op, CONTROL[op])
        if isinstance(outcome, Failure):
            return False, (f"The adapter did not answer a well-formed {op} request with a "
                           f"result, so its errors cannot show it reads the request's fields: "
                           f"{outcome.detail}")
    variants = MALFORMED[op] if isinstance(MALFORMED[op], list) else [MALFORMED[op]]
    for n, fields in enumerate(variants):
        outcome = _ask(session, op, fields)
        if not isinstance(outcome, Failure):
            return False, (f"The adapter answered a malformed {op} request (variant {n}) with a "
                           "result; a request the protocol cannot read gets an error response, "
                           "never a result or a refusal.")
        if not outcome.kind.startswith("error-"):
            return False, outcome.detail
    return True, f"The adapter answered every malformed {op} request with an error response."


def _op_probes(session: AdapterSession) -> list[Probe]:
    results = []
    for name, op, feature in OP_PROBES:
        if op not in session.hello["operations"]:
            results.append(Probe(name, "not-applicable", f"The adapter does not list {op}."))
            continue
        if feature is not None and feature not in session.hello["features"]:
            results.append(Probe(name, "not-applicable",
                                 f"The adapter does not declare {feature}."))
            continue
        try:
            session.ensure_running()
            passed, reason = _probe_malformed_op(session, op)
        except HelloRefused as refusal:
            passed, reason = False, str(refusal)
        if not passed:
            session.kill()
        results.append(Probe(name, "pass" if passed else "fail", reason))
    for name, op in OP_NOT_YET:
        if op not in session.hello["operations"]:
            results.append(Probe(name, "not-applicable", f"The adapter does not list {op}."))
        else:
            results.append(Probe(name, "not-yet-available", NOT_YET_ACDC))
    return results


def check_adapter(session: AdapterSession) -> list[Probe]:
    """Run every probe. A runner fault (start failure, root) propagates as RunnerError."""
    try:
        session.open()
    except HelloRefused as refusal:
        return [Probe("hello", "fail", str(refusal)),
                *(Probe(name, "not-run", "The hello probe failed, so this probe was not run.")
                  for name in PROBES[1:4]),
                *(Probe(name, "not-yet-available", NOT_YET) for name in PROBES[4:6]),
                *(Probe(name, "not-run", "The hello probe failed, so this probe was not run.")
                  for name in PROBES[6:9]),
                *(Probe(name, "not-yet-available", NOT_YET_ACDC) for name in PROBES[9:])]
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
    results += [Probe(name, "not-yet-available", NOT_YET) for name in PROBES[4:6]]
    return results + _op_probes(session)


def render(results: list[Probe]) -> str:
    return "\n".join(f"{p.status}  {p.name}: {p.reason}" for p in results)


def exit_code(results: list[Probe]) -> int:
    return 0 if all(p.status in ("pass", "not-applicable", "not-yet-available")
                    for p in results) else 1
