"""Compare a fresh conformance report with the committed result for the same implementation,
version and profile, outcome by outcome.

A shipped adapter's committed result (results/<implementation>/<version>/<profile>.json, labelled
maintainer-run) records what a run of that adapter at its pin produced. scripts/reproduce-results
check reruns the adapter and calls compare here, and the keripy refs check
(adapters/keripy/src/kcs_adapter_keripy/refs.py) does the same for other keripy refs. What is
compared is the verdict, every case's outcome and failure kind (how the adapter failed to answer,
if it did: timeout, exited, malformed, ...), and every assertion's outcome; timestamps, stderr and
detail text are not. Any difference fails, in either direction:

- Regressions: a different profile; a different implementation name or version; an aborted run; a verdict change other than to conformant
  (or, for a non-normative profile, to interoperable); a case outcome or assertion outcome that
  changed to anything but pass; a failure kind that appeared or changed (a case that starts
  crashing, though it still fails); a case or assertion that disappeared.
- Improvements: a verdict that became conformant or interoperable; a new pass; a failure kind
  that went away; a new case or assertion; a different implementation commit. An improvement is
  recorded by refreshing the committed result in the same change.

These were the semantics of the per-adapter baseline files this replaces. Standard library only,
so the keripy refs check can import it from an adapter's own environment.
"""

import errno
import json

E_MISSING_FILE = "e.input.missing.file.f"
E_READ = "e.env.filesystem.read.r"
E_FILE_SIZE = "e.input.range.file-size.f"
E_REPORT_FORMAT = "e.input.format.report.f"
E_COMMITTED_FORMAT = "e.input.format.committed-result.f"

# Read failures that may clear on their own; retrying could succeed.
TRANSIENT_ERRNOS = frozenset({errno.EAGAIN, errno.EWOULDBLOCK, errno.EINTR, errno.EBUSY,
                              errno.ENOSPC, errno.EDQUOT, errno.EIO, errno.ETIMEDOUT})
# The largest report or result this module reads. A report of the whole suite is about 150 KB.
MAX_FILE_BYTES = 64 * 1024 * 1024
ABORTED = "aborted"
NONE = "none"  # how a missing failure kind is written in a comparison line

# The values a kcs conformance report can hold (src/keri_conformance/run.py and session.py). A
# value outside these sets makes the report malformed: the comparison fails closed rather than guess.
VERDICTS = frozenset({"conformant", "not-conformant", "aborted", "incomplete", "no-evidence",
                      "interoperable", "not-interoperable"})
# The verdicts a run can improve to: conformance, or interoperability for a non-normative profile.
HELD = frozenset({"conformant", "interoperable"})
CASE_OUTCOMES = frozenset({"pass", "fail", "incomplete", "not-supported", "skipped"})
ASSERTION_OUTCOMES = frozenset({"pass", "fail", "not-applicable", "not-implemented",
                                "not-supported", "skipped"})
FAILURE_KINDS = frozenset({"timeout", "oversize", "exited", "malformed", "error-harness",
                           "error-unsupported"})


class InputError(Exception):
    """A file the comparison was given cannot be used; the message starts with its code."""


def summarize(report: dict) -> dict:
    """The part of a conformance report the comparison looks at."""
    cases = {}
    for entry in report["cases"]:
        failure = entry.get("failure")
        cases[entry["id"]] = {
            "outcome": entry["outcome"],
            "failure": None if failure is None else failure["kind"],
            "assertions": dict(sorted((a["id"], a["outcome"]) for a in entry["assertions"])),
        }
    return {"profile": report["filters"]["profile"],
            "implementation": report["hello"]["implementation"],
            "verdict": report["verdict"],
            "cases": dict(sorted(cases.items()))}


def _compare_case(cid, was, now, regressions, improvements):
    if was["outcome"] != now["outcome"]:
        line = f"{cid}: outcome {was['outcome']} -> {now['outcome']}"
        (improvements if now["outcome"] == "pass" else regressions).append(line)
    if was["failure"] != now["failure"]:
        line = f"{cid}: failure {was['failure'] or NONE} -> {now['failure'] or NONE}"
        (improvements if now["failure"] is None else regressions).append(line)
    for aid in sorted(set(was["assertions"]) | set(now["assertions"])):
        before = was["assertions"].get(aid, "absent")
        after = now["assertions"].get(aid, "absent")
        if before == after:
            continue
        line = f"{cid}/{aid}: {before} -> {after}"
        (improvements if before == "absent" or after == "pass" else regressions).append(line)


def compare(base: dict, report: dict) -> tuple[list[str], list[str]]:
    """(regressions, improvements) of report against base, the summary of the committed run."""
    now = summarize(report)
    regressions, improvements = [], []
    if now["profile"] != base["profile"]:
        regressions.append(f"profile: {base['profile']} -> {now['profile']}")
    if now["verdict"] == ABORTED:
        # An aborted run is never accepted, whatever the committed result records.
        regressions.append(f"verdict: {ABORTED} (an aborted run never matches a committed result)")
    elif now["verdict"] != base["verdict"]:
        # Any other change of verdict is a regression unless the run now holds (conformant, or
        # interoperable), so an abnormal run cannot match even when every assertion it recorded
        # does.
        line = f"verdict: {base['verdict']} -> {now['verdict']}"
        (improvements if now["verdict"] in HELD else regressions).append(line)
    # A run that names another implementation, or another version of it, is not evidence about
    # the committed one, however its outcomes compare; a new commit of the same version is.
    for field in ("name", "version"):
        if now["implementation"][field] != base["implementation"][field]:
            regressions.append(f"implementation {field}: {base['implementation'][field]} -> "
                               f"{now['implementation'][field]}")
    if now["implementation"]["commit"] != base["implementation"]["commit"]:
        improvements.append(f"implementation commit: {base['implementation']['commit']} -> "
                            f"{now['implementation']['commit']}")
    for cid in sorted(set(base["cases"]) | set(now["cases"])):
        if cid not in now["cases"]:
            regressions.append(f"{cid}: absent from the run")
        elif cid not in base["cases"]:
            improvements.append(f"{cid}: new case")
        else:
            _compare_case(cid, base["cases"][cid], now["cases"][cid], regressions, improvements)
    return regressions, improvements


def _load(path, what, malformed):
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_FILE_BYTES + 1)
    except FileNotFoundError as exc:
        raise InputError(f"{E_MISSING_FILE}: The {what} {path} does not exist; check the path, "
                         "or produce it first.") from exc
    except OSError as exc:
        raise InputError(f"{E_READ}: The {what} {path} could not be read ({exc}); check that it "
                         "is a readable file and try again.") from exc
    if len(data) > MAX_FILE_BYTES:
        raise InputError(f"{E_FILE_SIZE}: The {what} {path} is larger than {MAX_FILE_BYTES} "
                         "bytes, the most this comparison reads; it is not a report of a "
                         "profile this suite has.")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InputError(f"{malformed}: The {what} {path} is not UTF-8 text.") from exc
    try:
        return json.loads(text)
    except ValueError as exc:
        raise InputError(f"{malformed}: The {what} {path} is not JSON ({exc}).") from exc


def _is_str(value):
    return isinstance(value, str)


def _one_of(value, allowed) -> bool:
    """value is one of the strings in allowed. A JSON array or object is unhashable, so it is
    ruled out before the set lookup rather than raising TypeError from it."""
    return isinstance(value, str) and value in allowed


def _implementation_problem(implementation):
    if not isinstance(implementation, dict):
        return "the implementation is not an object"
    for field in ("name", "version", "commit"):
        if not _is_str(implementation.get(field)):
            return f"the implementation {field} is not a string"
    return None


def _assertions_problem(where, assertions):
    if not isinstance(assertions, list):
        return f"{where}'s assertions are not a list"
    seen = set()
    for assertion in assertions:
        if not isinstance(assertion, dict) or not _is_str(assertion.get("id")):
            return f"{where} has an assertion that is not an object with a string id"
        if assertion["id"] in seen:
            return f"{where} has the assertion {assertion['id']} twice"
        seen.add(assertion["id"])
        if not _one_of(assertion.get("outcome"), ASSERTION_OUTCOMES):
            return f"{where}/{assertion['id']} has an unknown outcome"
    return None


def _case_problem(entry, seen):
    if not isinstance(entry, dict) or not _is_str(entry.get("id")):
        return "a case is not an object with a string id"
    cid = entry["id"]
    if cid in seen:
        return f"the case {cid} appears twice"
    seen.add(cid)
    if not _one_of(entry.get("outcome"), CASE_OUTCOMES):
        return f"the case {cid} has an unknown outcome"
    failure = entry.get("failure")
    if failure is not None and (not isinstance(failure, dict)
                                or not _one_of(failure.get("kind"), FAILURE_KINDS)):
        return f"the case {cid} has a failure that is not an object with a known kind"
    return _assertions_problem(cid, entry.get("assertions"))


def report_problem(report):
    """None if report is well-formed enough to compare, else what is wrong with it."""
    if not isinstance(report, dict):
        return "it is not a JSON object"
    filters, hello = report.get("filters"), report.get("hello")
    if not isinstance(filters, dict) or not _is_str(filters.get("profile")):
        return "it has no string filters.profile"
    if not isinstance(hello, dict):
        return "its hello is not an object"
    problem = _implementation_problem(hello.get("implementation"))
    if problem:
        return problem
    if not _one_of(report.get("verdict"), VERDICTS):
        return "its verdict is not one kcs reports"
    if not isinstance(report.get("cases"), list):
        return "its cases are not a list"
    seen = set()
    for entry in report["cases"]:
        problem = _case_problem(entry, seen)
        if problem:
            return problem
    return None


def read_report(path) -> dict:
    """The kcs run report at path, refused with an InputError if it cannot be compared."""
    report = _load(path, "report", E_REPORT_FORMAT)
    problem = report_problem(report)
    if problem:
        raise InputError(f"{E_REPORT_FORMAT}: The report {path} is not a kcs conformance report "
                         f"({problem}); pass the file kcs run --report wrote.")
    return report


def read_committed(path, *, kind: str | None = None) -> dict:
    """The summary of the committed result at path (a report inside a provenance envelope),
    refused with an InputError if it cannot be compared. With `kind`, the result must also carry
    that provenance kind, so a fresh run is never measured against another kind of result that
    happens to sit at the same path."""
    doc = _load(path, "committed result", E_COMMITTED_FORMAT)
    report = doc.get("report") if isinstance(doc, dict) else None
    problem = "it has no report" if report is None else report_problem(report)
    if not problem and kind is not None:
        provenance = doc.get("provenance")
        found = provenance.get("kind") if isinstance(provenance, dict) else None
        if found != kind:
            problem = f"it is labelled {json.dumps(found)}, not {kind}"
    if problem:
        raise InputError(f"{E_COMMITTED_FORMAT}: The committed result {path} cannot be compared "
                         f"({problem}); scripts/results check names what is wrong with it.")
    return summarize(report)
