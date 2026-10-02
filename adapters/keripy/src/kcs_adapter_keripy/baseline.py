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

import json
import sys
from pathlib import Path

E_REGRESSION = "e.state.conflict.baseline-regression.f"
E_STALE = "e.state.conflict.baseline-stale.f"
E_USAGE = "e.input.format.usage.f"
E_ABORTED = "e.input.range.aborted-report.f"
E_MISSING_FILE = "e.input.missing.file.f"
E_READ = "e.env.filesystem.read.r"
E_REPORT_FORMAT = "e.input.format.report.f"
E_BASELINE_FORMAT = "e.input.format.baseline.f"


FORMAT = 2
ABORTED = "aborted"
NONE = "none"  # how a missing failure kind is written in a comparison line


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
        text = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise InputError(f"{E_MISSING_FILE}: The {what} {path} does not exist; check the path, "
                         "or produce it first.") from exc
    except UnicodeDecodeError as exc:
        raise InputError(f"{malformed}: The {what} {path} is not UTF-8 text.") from exc
    except OSError as exc:
        raise InputError(f"{E_READ}: The {what} {path} could not be read ({exc}); check that it "
                         "is a readable file and try again.") from exc
    try:
        return json.loads(text)
    except ValueError as exc:
        raise InputError(f"{malformed}: The {what} {path} is not JSON ({exc}).") from exc


def _report(path):
    report = _load(path, "report", E_REPORT_FORMAT)
    try:
        summarize(report)
    except (KeyError, TypeError, AttributeError) as exc:
        raise InputError(f"{E_REPORT_FORMAT}: The report {path} is not a kcs conformance report "
                         f"(it lacks or misshapes {exc}); pass the file kcs run --report wrote."
                         ) from exc
    return report


def _baseline(path):
    base = _load(path, "baseline", E_BASELINE_FORMAT)
    shaped = (isinstance(base, dict) and base.get("format") == FORMAT
              and {"profile", "implementation", "verdict", "cases"} <= set(base)
              and isinstance(base["implementation"], dict) and "commit" in base["implementation"]
              and isinstance(base["cases"], dict)
              and all(isinstance(c, dict) and {"outcome", "failure", "assertions"} <= set(c)
                      for c in base["cases"].values()))
    if not shaped:
        raise InputError(f"{E_BASELINE_FORMAT}: The baseline {path} is not one this tool wrote; "
                         "regenerate it with `write`.")
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
        Path(base_path).write_text(json.dumps(summarize(report), indent=2) + "\n",
                                   encoding="utf-8")
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
