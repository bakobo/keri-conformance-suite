"""CI level 2 for this adapter: compare a conformance report with the committed baseline.

    python -m kcs_adapter_keripy.baseline compare BASELINE REPORT
    python -m kcs_adapter_keripy.baseline write BASELINE REPORT

compare exits 0 when every assertion has the outcome the baseline records. It exits 1 on a
regression (an assertion whose outcome is no longer what the baseline says, a missing assertion,
a different profile, a verdict other than the recorded one unless it is now conformant) and also on an improvement (a new pass, a new assertion, a different keripy
commit, a verdict that became conformant), because an improvement must be recorded by updating the baseline in the same change.
write records REPORT as the new baseline. Standard library only.
"""

import json
import sys
from pathlib import Path

E_REGRESSION = "e.state.conflict.baseline-regression.f"
E_STALE = "e.state.conflict.baseline-stale.f"
E_USAGE = "e.input.format.usage.f"
E_ABORTED = "e.input.range.aborted-report.f"

ABORTED = "aborted"


def summarize(report: dict) -> dict:
    """The part of a conformance report the baseline keeps."""
    assertions = {}
    for case in report["cases"]:
        for assertion in case["assertions"]:
            assertions[f"{case['id']}/{assertion['id']}"] = assertion["outcome"]
    return {"profile": report["filters"]["profile"],
            "implementation": report["hello"]["implementation"],
            "verdict": report["verdict"],
            "assertions": dict(sorted(assertions.items()))}


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
    for key in sorted(set(base["assertions"]) | set(now["assertions"])):
        was = base["assertions"].get(key, "absent")
        is_ = now["assertions"].get(key, "absent")
        if was == is_:
            continue
        line = f"{key}: {was} -> {is_}"
        if was == "absent" or (is_ == "pass"):
            improvements.append(line)
        else:
            regressions.append(line)
    return regressions, improvements


def _load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 3 or argv[0] not in ("compare", "write"):
        print(f"{E_USAGE}: usage: python -m kcs_adapter_keripy.baseline compare|write "
              "BASELINE REPORT", file=sys.stderr)
        return 2
    command, base_path, report_path = argv
    report = _load(report_path)
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
    regressions, improvements = compare(_load(base_path), report)
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
