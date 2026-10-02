"""CI level 2 for this adapter: compare a conformance report with the committed baseline.

    python -m kcs_adapter_keripy.baseline compare BASELINE REPORT
    python -m kcs_adapter_keripy.baseline write BASELINE REPORT

The baseline records the run's verdict, every case's outcome and failure kind (how the adapter
failed to answer, if it did: timeout, exited, malformed, ...), and every assertion's outcome.
compare exits 0 when the run matches it exactly. It exits 1 on a regression and also on an
improvement, because an improvement must be recorded by updating the baseline in the same change.

- Regressions: a different profile; an aborted run; a verdict change other than to conformant; a
  case outcome or assertion outcome that changed to anything but pass; a failure kind that
  appeared or changed (a case that starts crashing, though it still fails); a case or assertion
  that disappeared.
- Improvements: a verdict that became conformant; a new pass; a failure kind that went away; a
  new case or assertion; a different keripy commit.

write records REPORT as the new baseline. Standard library only.
"""

import errno
import json
import sys
from pathlib import Path

E_REGRESSION = "e.state.conflict.baseline-regression.f"
E_STALE = "e.state.conflict.baseline-stale.f"
E_USAGE = "e.input.format.usage.f"
E_ABORTED = "e.input.range.aborted-report.f"
E_MISSING_FILE = "e.input.missing.file.f"
E_READ = "e.env.filesystem.read.r"
E_WRITE_TRANSIENT = "e.env.filesystem.write.r"
E_WRITE = "e.env.filesystem.write.f"
E_FILE_SIZE = "e.input.range.file-size.f"
E_REPORT_FORMAT = "e.input.format.report.f"
E_BASELINE_FORMAT = "e.input.format.baseline.f"


# Write failures that may clear on their own; retrying the write could succeed.
TRANSIENT_ERRNOS = frozenset({errno.EAGAIN, errno.EWOULDBLOCK, errno.EINTR, errno.EBUSY,
                              errno.ENOSPC, errno.EDQUOT, errno.EIO, errno.ETIMEDOUT})
FORMAT = 2
# The largest report or baseline this tool reads. A cesr-1.0 report is well under 1 MiB.
MAX_FILE_BYTES = 64 * 1024 * 1024
ABORTED = "aborted"
NONE = "none"  # how a missing failure kind is written in a comparison line

# The values a kcs conformance report can hold (src/keri_conformance/run.py and session.py). A
# value outside these sets makes the report malformed: the tool fails closed rather than guess.
VERDICTS = frozenset({"conformant", "not-conformant", "aborted", "incomplete", "no-evidence"})
CASE_OUTCOMES = frozenset({"pass", "fail", "incomplete", "not-supported", "skipped"})
ASSERTION_OUTCOMES = frozenset({"pass", "fail", "not-implemented", "not-supported", "skipped"})
FAILURE_KINDS = frozenset({"timeout", "oversize", "exited", "malformed", "error-harness",
                           "error-unsupported"})


class InputError(Exception):
    """A file the tool was given cannot be used; the message starts with its code."""


def summarize(report: dict) -> dict:
    """The part of a conformance report the baseline keeps."""
    cases = {}
    for entry in report["cases"]:
        failure = entry.get("failure")
        cases[entry["id"]] = {
            "outcome": entry["outcome"],
            "failure": None if failure is None else failure["kind"],
            "assertions": dict(sorted((a["id"], a["outcome"]) for a in entry["assertions"])),
        }
    return {"format": FORMAT,
            "profile": report["filters"]["profile"],
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
    """(regressions, improvements) of report against the baseline summary base."""
    now = summarize(report)
    regressions, improvements = [], []
    if now["profile"] != base["profile"]:
        regressions.append(f"profile: {base['profile']} -> {now['profile']}")
    if now["verdict"] == ABORTED:
        # An aborted run is never accepted, whatever the baseline records.
        regressions.append(f"verdict: {ABORTED} (an aborted run never satisfies the baseline)")
    elif now["verdict"] != base["verdict"]:
        # Any other change of verdict is a regression unless the run is now conformant, so an
        # abnormal run cannot satisfy the gate even when every assertion it recorded matches.
        line = f"verdict: {base['verdict']} -> {now['verdict']}"
        (improvements if now["verdict"] == "conformant" else regressions).append(line)
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
                         "bytes, the most this tool reads; it is not a report or baseline of a "
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
        if assertion.get("outcome") not in ASSERTION_OUTCOMES:
            return f"{where}/{assertion['id']} has an unknown outcome"
    return None


def _case_problem(entry, seen):
    if not isinstance(entry, dict) or not _is_str(entry.get("id")):
        return "a case is not an object with a string id"
    cid = entry["id"]
    if cid in seen:
        return f"the case {cid} appears twice"
    seen.add(cid)
    if entry.get("outcome") not in CASE_OUTCOMES:
        return f"the case {cid} has an unknown outcome"
    failure = entry.get("failure")
    if failure is not None and (not isinstance(failure, dict)
                                or failure.get("kind") not in FAILURE_KINDS):
        return f"the case {cid} has a failure that is not an object with a known kind"
    return _assertions_problem(cid, entry.get("assertions"))


def report_problem(report):
    """None if report is a well-formed kcs conformance report, else what is wrong with it."""
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
    if report.get("verdict") not in VERDICTS:
        return "its verdict is not one kcs reports"
    if not isinstance(report.get("cases"), list):
        return "its cases are not a list"
    seen = set()
    for entry in report["cases"]:
        problem = _case_problem(entry, seen)
        if problem:
            return problem
    return None


def baseline_problem(base):
    """None if base is a well-formed baseline of the current format, else what is wrong."""
    if not isinstance(base, dict) or base.get("format") != FORMAT:
        return f"it is not a format-{FORMAT} baseline"
    if not _is_str(base.get("profile")) or base.get("verdict") not in VERDICTS:
        return "its profile or verdict is missing or unknown"
    problem = _implementation_problem(base.get("implementation"))
    if problem:
        return problem
    if not isinstance(base.get("cases"), dict):
        return "its cases are not an object"
    for cid, entry in base["cases"].items():
        if (not isinstance(entry, dict) or entry.get("outcome") not in CASE_OUTCOMES
                or (entry.get("failure") is not None
                    and entry.get("failure") not in FAILURE_KINDS)
                or not isinstance(entry.get("assertions"), dict)
                or not all(o in ASSERTION_OUTCOMES for o in entry["assertions"].values())):
            return f"its entry for {cid} is malformed"
    return None


def _report(path):
    report = _load(path, "report", E_REPORT_FORMAT)
    problem = report_problem(report)
    if problem:
        raise InputError(f"{E_REPORT_FORMAT}: The report {path} is not a kcs conformance report "
                         f"({problem}); pass the file kcs run --report wrote.")
    return report


def _baseline(path):
    base = _load(path, "baseline", E_BASELINE_FORMAT)
    problem = baseline_problem(base)
    if problem:
        raise InputError(f"{E_BASELINE_FORMAT}: The baseline {path} is not one this tool wrote "
                         f"({problem}); regenerate it with `write`.")
    return base


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 3 or argv[0] not in ("compare", "write"):
        print(f"{E_USAGE}: usage: python -m kcs_adapter_keripy.baseline compare|write "
              "BASELINE REPORT", file=sys.stderr)
        return 2
    command, base_path, report_path = argv
    try:
        report = _report(report_path)
        base = None if command == "write" else _baseline(base_path)
    except InputError as exc:
        print(exc, file=sys.stderr)
        return 2
    if command == "write":
        if report.get("verdict") == ABORTED:
            print(f"{E_ABORTED}: {report_path} is the report of an aborted run, which cannot be "
                  "a baseline; rerun to completion and write the baseline from that report.",
                  file=sys.stderr)
            return 1
        try:
            Path(base_path).write_text(json.dumps(summarize(report), indent=2) + "\n",
                                       encoding="utf-8")
        except OSError as exc:
            transient = exc.errno in TRANSIENT_ERRNOS
            code = E_WRITE_TRANSIENT if transient else E_WRITE
            advice = ("this may clear; try again" if transient
                      else "check that the directory exists and is writable")
            print(f"{code}: The baseline {base_path} could not be written ({exc}); {advice}.",
                  file=sys.stderr)
            return 2
        print(f"Wrote the baseline {base_path} from {report_path}.")
        return 0
    regressions, improvements = compare(base, report)
    for line in regressions:
        print(f"{E_REGRESSION}: {line}")
    for line in improvements:
        print(f"{E_STALE}: {line} (an improvement; update the baseline in this change with "
              f"`python -m kcs_adapter_keripy.baseline write {base_path} <report>`)")
    if regressions or improvements:
        return 1
    print(f"The run matches the baseline {base_path}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
