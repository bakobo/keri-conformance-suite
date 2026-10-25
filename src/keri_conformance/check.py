"""`kcs check-adapter`: probe an adapter's protocol behaviour without running a case.

The probes check what the runner can check from the outside with no KERI material: that hello is
valid, that ids are echoed, that a request line that is not JSON gets an error response whose id
is null and the adapter then answers the next request, and that an unknown op gets an error; and,
for an adapter that lists acdc.issue or acdc.present, or declares acdc.presentation, that a request
the protocol cannot read gets an error rather than a result; and, for an issuer, that two identical
plain issuances each verify. The statelessness and quiescence probes need real KERI
streams from the keripy generator, which does not exist yet, so they are reported as not yet
available rather than faked.
"""

import json
from dataclasses import dataclass

from keri_conformance import issued
from keri_conformance.contracts import ERROR
from keri_conformance.errors import HelloRefused
from keri_conformance.jsonfile import loads
from keri_conformance.session import AdapterSession, Failure, beyond_schema, parse_response

PROBES = ("hello", "id-echo", "malformed-request", "unknown-op", "statelessness", "quiescence",
          "issue-malformed", "present-malformed", "presentation-malformed", "issue-repeatable",
          "present-independence")
# The probes for the issuer and holder operations and the presentation context, each run only
# against an adapter that lists the operation (and declares the feature, where one is named), and
# the probes for them that need a real issuance to send.
OP_PROBES = (("issue-malformed", "acdc.issue", None), ("present-malformed", "acdc.present", None),
             ("presentation-malformed", "acdc.verify", "acdc.presentation"))
OP_NOT_YET = (("present-independence", "acdc.present"),)
NOT_YET_ACDC = ("This probe sends a real issuance, taken from the suite's first acdc.issue case, "
                "which does not exist yet.")
# Requests this protocol cannot read: an issuance that asks for no credential, a presentation in a
# disclosure form the protocol does not define, and a verification whose presentation context
# names no message and no verifier.
_VERIFY = {"perspective": {"role": "validator"}, "kels": [], "registry": [], "schemas": [],
           "acdcs": [], "presented": {"stream": "2d4b"}}
# The verifier is a well-formed Blake3-256 AID (code E, 44 characters), so a control the adapter
# refuses is refused for something other than an unreadable AID.
_CONTEXT = {"messages": [{"stream": "2d4b", "source": "holder"}], "verifier": "E" + "A" * 43}
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
    "acdc.issue": {"roles": ["issuer"], "schemas": [], "credentials": []},
    "acdc.present": {"perspective": {"role": "holder"}, "kels": [], "registry": [], "schemas": [],
                     "acdcs": [], "held": {"stream": "2d4b"},
                     "disclosure": {"form": "kcs-probe-no-such-form"}},
}
# One plain issuance, sent twice by the issue-repeatable probe: an issuer and a holder, and one
# credential under a schema that constrains nothing (this.i 2u2ps8mt).
_PROBE_SCHEMA = {"$id": issued.DUMMY, "$schema": "https://json-schema.org/draft/2020-12/schema",
                 "title": "T", "type": "object"}
_PROBE_SCHEMA["$id"] = issued.digest(issued.serialize(_PROBE_SCHEMA))
ISSUE_PROBE = {"roles": ["issuer", "holder"],
               "schemas": [issued.serialize(_PROBE_SCHEMA).hex()],
               "credentials": [{"name": "c", "issuer": "issuer", "issuee": "holder",
                                "schema": _PROBE_SCHEMA["$id"], "attributes": {"name": "Zoe"},
                                "registry": "bup"}]}
# The same issuance in keripy 1.x's forms, for an adapter that issues only into a 1.x registry. It
# asks for a.dt, since every 1.x issuer adds one whether asked or not (interop/two-wallets/
# INCOMPATIBILITIES.md entry 8), and the probe asks for an issuance it must make.
ISSUE_PROBE_1X = {**ISSUE_PROBE, "credentials": [
    {**ISSUE_PROBE["credentials"][0], "registry": issued.ONE_X,
     "attributes": {"dt": "2026-10-01T00:00:00.000000+00:00", "name": "Zoe"}}]}
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
    variants = MALFORMED[op] if isinstance(MALFORMED[op], list) else [MALFORMED[op]]
    for n, fields in enumerate(variants):
        # The control goes before every variant, so an error on the variant is shown to be the
        # variant's own, not an adapter that has stopped answering anything.
        if op in CONTROL:
            outcome = _ask(session, op, CONTROL[op])
            if isinstance(outcome, Failure):
                return False, (f"The adapter did not answer a well-formed {op} request with a "
                               f"result, so its errors cannot show it reads the request's "
                               f"fields: {outcome.detail}")
        outcome = _ask(session, op, fields)
        if not isinstance(outcome, Failure):
            return False, (f"The adapter answered a malformed {op} request (variant {n}) with a "
                           "result; a request the protocol cannot read gets an error response, "
                           "never a result or a refusal.")
        if not outcome.kind.startswith("error-"):
            return False, outcome.detail
    return True, f"The adapter answered every malformed {op} request with an error response."


def _issue_probe(hello: dict) -> dict:
    """The probe's issuance: in keripy 1.x's forms for an adapter that declares the 1.x registry
    and not the blindable one, and KERI 2.0's otherwise."""
    features = hello["features"]
    if "acdc.ptel-1x" in features and "acdc.registry.bup" not in features:
        return ISSUE_PROBE_1X
    return ISSUE_PROBE


def _probe_issue_repeatable(session: AdapterSession) -> tuple[bool, str]:
    """Two identical issuance requests each return an issuance that verifies: an issuer's output
    varies, so what repeats is that it verifies, not its bytes (this.i 2u2ps8mt)."""
    probe = _issue_probe(session.hello)
    for n in (1, 2):
        outcome = _ask(session, "acdc.issue", probe)
        if isinstance(outcome, Failure):
            return False, f"The adapter did not answer issuance {n} with a result: {outcome.detail}"
        if "refused" in outcome.result:
            return False, f"The adapter refused issuance {n}, a plain issuance it must make."
        shape = beyond_schema("acdc.issue", probe, outcome.result)
        if shape:
            return False, f"Issuance {n} does not answer the request: {shape}"
        problems = issued.grade(probe, outcome.result)
        if problems:
            return False, f"Issuance {n} does not verify: {problems[0]}."
    return True, "Two identical acdc.issue requests each returned an issuance that verifies."


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
    if "acdc.issue" not in session.hello["operations"]:
        results.append(Probe("issue-repeatable", "not-applicable",
                             "The adapter does not list acdc.issue."))
    else:
        try:
            session.ensure_running()
            passed, reason = _probe_issue_repeatable(session)
        except HelloRefused as refusal:
            passed, reason = False, str(refusal)
        if not passed:
            session.kill()
        results.append(Probe("issue-repeatable", "pass" if passed else "fail", reason))
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
                  for name in PROBES[6:10]),
                *(Probe(name, "not-yet-available", NOT_YET_ACDC) for name in PROBES[10:])]
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
