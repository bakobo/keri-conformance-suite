"""`kcs agree`: the cross-role agreement matrix (docs/profiles/sedi-test-plan.md, item 10; this.i
3ptj8hu9).

Each adapter that declares acdc.issue or acdc.present answers every such case, graded by the
case's own assertions as `kcs run` grades it. Its answer then becomes acdc.verify bundles, built
from what it returned and nothing else, and every adapter that declares acdc.verify judges each
bundle, the producer included. A cell records one verifier's verdict on one credential one
producer issued or presented, and whether that verdict is the one the case implies:

- valid, when the case expects an issuance or a presentation and the producer's answer passed
  every assertion of the case;
- not valid, when the case expects an issuer to refuse and the issuer issued anyway, since an
  issuer negative case is one whose fault a verifier sees in the bytes;
- none otherwise: a refusal yields no bundle, an answer that failed its own case is already
  graded by `kcs run`, and a holder that presented what it must refuse may have presented
  something valid in another form. Such a cell is recorded and never disagrees.

The matrix belongs to the evidence pack, not to a profile verdict.
"""

from contextlib import ExitStack

from keri_conformance import issued
from keri_conformance.assertions import evaluate
from keri_conformance.errors import E_ADAPTER_HELLO_CHANGED, HelloRefused
from keri_conformance.session import Failure

PRODUCERS = ("acdc.issue", "acdc.present")
REFUSALS = {"acdc.issue": "issue_refused", "acdc.present": "present_refused"}
VALID = "valid"
NOT_VALID = "not-valid"


def _count(code: str, big: str, text: str) -> str:
    """A group code with its quadlet count, in the big form when the small one cannot hold it."""
    quadlets = len(text) // 4
    if quadlets < 64 ** 2:
        return code + issued.int_b64(quadlets, 2) + text
    return big + issued.int_b64(quadlets, 5) + text


def disclosure_group(disclosure: str) -> str:
    """A head update's attachments: its disclosed blinded state as a -a group, wrapped in a -C
    attachments group. An issuer returns the state with or without its group code."""
    if not disclosure.startswith(("-a", "--a")):
        disclosure = _count("-a", "--a", disclosure)
    return _count("-C", "--C", disclosure)


def _streams(stream: bytes, protocol: bytes) -> list[bytes]:
    """Each message of a stream as a genus-pinned stream of its own, with its attachments."""
    return [issued.GENUS + raw + attachments
            for _, raw, attachments in issued.frames(stream, protocol)]


def _far(edges) -> list[str]:
    """The credentials an edge section names, by request name, in the order they appear."""
    out = []
    for value in (edges or {}).values():
        if isinstance(value, dict):
            out += [value["credential"]] if "credential" in value else _far(value)
    return out


def _dag(name: str, by_name: dict[str, dict]) -> list[str]:
    """Every credential reachable from one by its edges, each once, the credential excluded."""
    out, todo = [], list(_far(by_name[name].get("edges")))
    while todo:
        far = todo.pop(0)
        if far != name and far not in out and far in by_name:
            out.append(far)
            todo += _far(by_name[far].get("edges"))
    return out


def issue_bundles(request: dict, result: dict) -> dict[str, dict]:
    """An acdc.verify bundle per credential an issuer returned, by request name. Raises
    issued.Unread when a returned stream cannot be split into its messages."""
    kels = []
    for role in request["roles"]:
        stream = bytes.fromhex(result["kels"][role])
        kels += [{"stream": s.hex(), "source": role} for s in _streams(stream, b"KERI")]
    registries = {}
    for name, out in result["credentials"].items():
        events = _streams(bytes.fromhex(out["registry"]), b"ACDC")
        if events and isinstance(out.get("disclosure"), str):
            events[-1] += disclosure_group(out["disclosure"]).encode()
        registries[name] = [{"stream": e.hex()} for e in events]
    by_name = {c["name"]: c for c in request["credentials"]}
    bundles = {}
    for name, out in result["credentials"].items():
        dag = _dag(name, by_name)
        bundles[name] = {
            "perspective": {"role": "validator"},
            "kels": kels,
            "registry": [e for n in [name, *dag] for e in registries[n]],
            "schemas": list(request["schemas"]),
            "acdcs": [{"stream": result["credentials"][n]["acdc"]} for n in dag],
            "presented": {"stream": out["acdc"]},
        }
    return bundles


def present_bundle(request: dict, result: dict) -> dict:
    """The acdc.verify bundle of a presentation: the holder's bundle with what it presented in
    place of what it held."""
    bundle = {k: v for k, v in request.items() if k not in ("held", "disclosure")}
    return {**bundle, "perspective": {"role": "validator"},
            "presented": {"stream": result["presented"]["stream"]}}


def _produce(session, case: dict) -> tuple[str, dict | None, str | None, bool]:
    """What one producer made of a case: produced (issued, presented, refused or error), its
    result, a detail, and whether it passed every assertion of the case."""
    reply = session.request(case["operation"], case["input"])
    session.take_stderr()
    if isinstance(reply, Failure):
        return "error", None, f"{reply.kind}: {reply.detail}", False
    passed = all(evaluate(a, reply.result, case["input"]).outcome == "pass"
                 for a in case["assertions"])
    if "refused" in reply.result:
        return "refused", reply.result, reply.result["refused"].get("reason"), passed
    return ("issued" if case["operation"] == "acdc.issue" else "presented"), reply.result, None, \
        passed


def _expected(case: dict, passed: bool) -> str | None:
    refusal = any(a["check"] == REFUSALS[case["operation"]] for a in case["assertions"])
    if not refusal:
        return VALID if passed else None
    return NOT_VALID if case["operation"] == "acdc.issue" else None


def _agrees(expected: str | None, verdict: str | None) -> bool | None:
    if expected is None:
        return None
    if verdict is None:
        return False
    return (verdict == VALID) == (expected == VALID)


def _cell(case, producer, verifier=None, credential=None, **fields) -> dict:
    return {"case": case["id"], "producer": producer, "verifier": verifier,
            "credential": credential, "produced": None, "producer_passed": None,
            "expected": None, "verdict": None, "detail": None, "agrees": None, **fields}


def _supports(hello: dict, op: str, case: dict) -> bool:
    return op in hello["operations"] and all(f in hello["features"]
                                             for f in case["targets"]["features"])


def matrix(sessions: dict, verifying: dict, cases: list[dict]) -> list[dict]:
    """Every cell, for opened sessions by adapter name and the cases to draw from. ``verifying``
    holds a second session of each adapter, so no verdict can rest on what a producer's own
    session kept from producing."""
    cells = []
    verifiers = {n: s for n, s in verifying.items() if "acdc.verify" in s.hello["operations"]}
    for case in cases:
        if case["operation"] not in PRODUCERS or case["status"] == "deprecated":
            continue
        for producer, session in sessions.items():
            if not _supports(session.hello, case["operation"], case):
                continue
            produced, result, detail, passed = _produce(session, case)
            if produced in ("error", "refused"):
                cells.append(_cell(case, producer, produced=produced, producer_passed=passed,
                                   detail=detail))
                continue
            expected = _expected(case, passed)
            try:
                bundles = (issue_bundles(case["input"], result) if produced == "issued"
                           else {"presented": present_bundle(case["input"], result)})
            except (issued.Unread, KeyError, TypeError, ValueError) as exc:
                cells.append(_cell(case, producer, produced=produced, producer_passed=passed,
                                   expected=expected, agrees=_agrees(expected, None),
                                   detail=f"no bundle could be built from the answer: {exc}"))
                continue
            judged = False
            for verifier, vsession in verifiers.items():
                for credential, bundle in bundles.items():
                    cell = _cell(case, producer, verifier, credential, produced=produced,
                                 producer_passed=passed, expected=expected)
                    if not _supports(vsession.hello, "acdc.verify", case):
                        cell["detail"] = "the verifier does not declare the case's features"
                        cells.append(cell)
                        continue
                    reply = vsession.request("acdc.verify", bundle)
                    vsession.take_stderr()
                    if isinstance(reply, Failure):
                        cell["detail"] = f"{reply.kind}: {reply.detail}"
                    else:
                        cell["verdict"] = reply.result["verdict"]
                        cell["detail"] = reply.result.get("reason")
                    cell["agrees"] = _agrees(expected, cell["verdict"])
                    cells.append(cell)
                    judged = True
            if expected is not None and not judged:
                # Something had to be verified and nothing could verify it: that is no agreement.
                cells.append(_cell(case, producer, produced=produced, producer_passed=passed,
                                   expected=expected, agrees=False,
                                   detail="no adapter that declares acdc.verify and the case's "
                                          "features verified it"))
    return cells


def run_agreement(open_session, adapters: dict[str, str], cases: list[dict],
                  suite_version: str) -> dict:
    """The agreement report: open_session(command) gives an unopened AdapterSession."""
    with ExitStack() as stack:
        sessions, verifying = {}, {}
        for name, command in adapters.items():
            for held in (sessions, verifying):
                session = stack.enter_context(open_session(command))
                session.open()
                held[name] = session
            if verifying[name].hello != sessions[name].hello:
                # Both processes must be the one implementation the report names.
                raise HelloRefused(E_ADAPTER_HELLO_CHANGED,
                                   f"The adapter {name} answered hello differently in its second "
                                   "process, so its verdicts could not be credited to the "
                                   "implementation that produced.", ["The hello changed."])
        cells = matrix(sessions, verifying, cases)
        implementations = {n: s.hello["implementation"] for n, s in sessions.items()}
    judged = [c for c in cells if c["agrees"] is not None]
    return {"suite_version": suite_version, "adapters": implementations, "cells": cells,
            "summary": {"cells": len(cells), "judged": len(judged),
                        "disagree": sum(1 for c in judged if not c["agrees"])}}


def human_summary(report: dict) -> str:
    s = report["summary"]
    lines = [(f"Agreement: {s['cells']} cells, {s['judged']} with an expectation, "
              f"{s['disagree']} disagreeing.")]
    for c in report["cells"]:
        if c["agrees"] is False:
            lines.append(f"  {c['case']} {c['credential']}: {c['producer']} {c['produced']}, "
                         f"{c['verifier']} said {c['verdict'] or 'nothing'} where "
                         f"{c['expected']} was expected"
                         + (f" ({c['detail']})" if c["detail"] else ""))
    return "\n".join(lines)
