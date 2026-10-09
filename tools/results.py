"""Published conformance results: the one door they are read through, and the command that makes one.

A published result is a runner report, exactly as `kcs run --report` wrote it, inside a provenance
envelope that says who produced it (schema/result.schema.json; docs/publishing-results.md). Its
place is fixed by its content: results/<implementation>/<version>/<profile>.json, where the first
two segments are slugs of the implementation name and version the adapter reported in hello.

Results are untrusted input: a submitted one arrives by pull request from outside the project.
load_results is the door, and it works in the order the input-handling standard requires. Size
first: the walk counts the files and adds up their sizes before any is read, and refuses anything
that is not a plain file or directory where the layout expects one. Then shape: each file is read
with a byte bound and checked against a hand-written mirror of the schema, which
tests/test_result_schema.py proves agrees with the schema. Then meaning: the file must sit at the
path its report implies, its provenance must be a kind the directory may hold (the committed
results/ tree holds only submitted results, so no pull request can claim that CI reproduced it),
and the report must agree with itself: every case in the named profile, each case's outcome what
its assertions imply, and the summary and verdict what the runner's own summarize computes from
the cases. A hand-edited verdict is therefore refused rather than published.
"""

import argparse
import contextlib
import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from keri_conformance.errors import (
    E_USAGE_INVALID,
    E_USAGE_MISSING,
    EXIT_FAULT,
    EXIT_USAGE,
    RunnerError,
)
from keri_conformance.jsonfile import TRANSIENT_ERRNOS, JsonFileError, read_json
from keri_conformance.run import summarize
from keri_conformance.shapes import (
    Check,
    all_of,
    array,
    enum,
    integer,
    mapping,
    nullable,
    obj,
    predicate,
    string,
    tagged,
)

E_RESULTS_MISSING = "e.input.missing.results.f"
E_RESULT_PATH = "e.input.format.result-path.f"
E_RESULT_FORMAT = "e.input.format.result.f"
E_RESULT_SIZE = "e.input.range.result-size.f"
E_RESULTS_COUNT = "e.input.range.result-count.f"
E_RESULTS_BYTES = "e.input.range.result-bytes.f"
E_RESULT_PROVENANCE = "e.rule.result.provenance.f"
E_RESULT_READ = "e.env.filesystem.result.f"
E_RESULT_READ_TRANSIENT = "e.env.filesystem.result.r"
E_RESULT_EXISTS = "e.state.conflict.result.f"
E_RESULT_WRITE = "e.env.filesystem.result-write.f"
E_RESULT_WRITE_TRANSIENT = "e.env.filesystem.result-write.r"

# Flood guards, not opinions about what a result weighs. A report of the whole suite today is
# about 150 KB; a file is allowed a hundred times that, and the tree as a whole enough for several
# hundred such files, while staying far below what would trouble the site build.
MAX_RESULT_BYTES = 16 * 1024 * 1024
MAX_RESULT_FILES = 2_000
MAX_RESULTS_BYTES = 128 * 1024 * 1024
MAX_SLUG = 64
MAX_LABEL = 256

KINDS = ("reproduced", "submitted")
CASE_ID = "^(CESR|KERI|ACDC|IPEX)-[0-9]{4}$"
PROFILE = "^[a-z0-9][a-z0-9.-]{0,63}$"
# Components are sorted as integers, so each is short, and a suffix cannot start with a digit.
SUITE_VERSION = r"^[0-9]{1,9}(\.[0-9]{1,9}){1,3}([A-Za-z+-][A-Za-z0-9.+-]{0,31})?$"
DATE = "^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])$"
RUN_URL = r"^https://github\.com/[A-Za-z0-9-]+/[A-Za-z0-9._-]+/actions/runs/[0-9]+(/attempts/[0-9]+)?$"
PR_URL = r"^https://github\.com/[A-Za-z0-9-]+/[A-Za-z0-9._-]+/pull/[0-9]+$"
VERDICTS = ("conformant", "not-conformant", "incomplete", "no-evidence", "aborted")
CASE_OUTCOMES = ("pass", "fail", "incomplete", "not-supported", "skipped")
ASSERTION_OUTCOMES = ("pass", "fail", "not-applicable", "not-implemented", "not-supported",
                      "skipped")


def _anything(value, path):
    return None


LABEL = all_of(string(min_length=1),
               predicate(lambda v: len(v) <= MAX_LABEL, f"at most {MAX_LABEL} characters"))
STRINGS = array(string())
COUNT = integer(minimum=0)
TALLY = mapping(COUNT)
POSITIVE = integer(minimum=1)

PROVENANCE = tagged("kind", {
    "reproduced": obj({"kind": enum("reproduced"), "run": string(RUN_URL),
                       "commit": string("^[0-9a-f]{40}$"), "date": string(DATE)}),
    "submitted": obj({"kind": enum("submitted"), "submitter": LABEL,
                      "pull_request": string(PR_URL), "date": string(DATE)}),
})

ASSERTION = obj({"id": string("^a[0-9]+$"), "check": string(),
                 "level": enum("MUST", "SHOULD", "MAY", "INTEROP"),
                 "outcome": enum(*ASSERTION_OUTCOMES), "expected": _anything,
                 "actual": _anything, "detail": nullable(string()),
                 "self_agreement": enum(True, False)})

CASE = obj({"id": string(CASE_ID), "status": enum("active", "draft", "disputed", "deprecated"),
            "profile": string(), "operation": string(),
            "failure": nullable(obj({"kind": string(), "detail": string()})),
            "stderr": string(), "outcome": enum(*CASE_OUTCOMES),
            "assertions": array(ASSERTION)},
           {"missing_operation": string(), "missing_features": STRINGS})

HELLO = obj({"protocol": POSITIVE,
             "adapter": obj({"name": LABEL, "version": LABEL}),
             "implementation": obj({"name": LABEL, "version": LABEL, "commit": LABEL}),
             "operations": array(string(), min_items=1), "features": STRINGS},
            {"composes": STRINGS})

SUMMARY = obj({"counts": mapping(mapping(TALLY)), "should": TALLY, "should_failed": COUNT,
               "should_warning": nullable(string()), "not_supported_active": STRINGS,
               "self_agreement_passes": COUNT})

REPORT = obj({
    "report_version": enum(1), "runner_version": LABEL, "suite_version": string(SUITE_VERSION),
    "protocol_version": POSITIVE, "supported_protocols": array(POSITIVE, min_items=1),
    "negotiated_protocol": POSITIVE, "hello": HELLO, "declared_features": STRINGS,
    "composes": STRINGS,
    "filters": obj({"profile": string(PROFILE), "cases_dir": string()}),
    "session_stderr": string(), "verdict": enum(*VERDICTS),
    "aborted": nullable(obj({"code": string(), "reason": string(), "problems": STRINGS,
                             "at_case": string(), "exit_code": integer()})),
    "probes": mapping(string()), "summary": SUMMARY, "cases": array(CASE),
})

RESULT: Check = obj({"result_version": enum(1), "provenance": PROVENANCE, "report": REPORT})


def shape_problem(doc) -> str | None:
    """None if `doc` satisfies schema/result.schema.json, else what is wrong with it."""
    return RESULT(doc, "")


def slug(text: str) -> str | None:
    """The path segment for an implementation name or version: lowercase, every run of other
    characters replaced by one hyphen, and no leading or trailing hyphen or dot. None if nothing
    usable is left or the result is longer than MAX_SLUG, since such a name cannot be placed."""
    value = re.sub(r"[^a-z0-9.+_-]+", "-", text.lower()).strip("-.")
    if not value or len(value) > MAX_SLUG or not value[0].isalnum():
        return None
    if value == "index" or value.endswith(".md"):
        return None  # results/index.md and every page are markdown files the site writes
    return value


def result_path(doc: dict) -> Path:
    """Where a well-formed result belongs, relative to the results directory."""
    report = doc["report"]
    impl = report["hello"]["implementation"]
    return Path(slug(impl["name"]), slug(impl["version"]),
                f"{report['filters']['profile']}.json")


def _case_outcome(entry: dict) -> str:
    outcomes = {r["outcome"] for r in entry["assertions"]}
    if entry["outcome"] in ("skipped", "not-supported"):
        return entry["outcome"] if outcomes <= {entry["outcome"]} else "inconsistent"
    if "fail" in outcomes:
        return "fail"
    if "not-implemented" in outcomes:
        return "incomplete"
    return "pass" if outcomes <= {"pass", "not-applicable"} else "inconsistent"


def _meaning_problem(report: dict) -> str | None:
    impl = report["hello"]["implementation"]
    for field in ("name", "version"):
        if slug(impl[field]) is None:
            return (f"the implementation {field} {json.dumps(impl[field][:80])} leaves no "
                    f"usable path segment of at most {MAX_SLUG} letters, digits and . + _ -")
    profile = report["filters"]["profile"]
    seen = set()
    for entry in report["cases"]:
        if entry["id"] in seen:
            return f"the case {entry['id']} is listed twice"
        seen.add(entry["id"])
        if entry["profile"] != profile:
            return (f"the case {entry['id']} is in the profile {json.dumps(entry['profile'])}, "
                    f"but the report was run for {profile}")
        assertion_ids: set[str] = set()
        for record in entry["assertions"]:
            if record["id"] in assertion_ids:
                return f"the case {entry['id']} lists the assertion {record['id']} twice"
            assertion_ids.add(record["id"])
        if entry["failure"] is not None and any(r["outcome"] != "fail"
                                                for r in entry["assertions"]):
            return (f"the case {entry['id']} records an adapter failure, but not every one of "
                    "its assertions failed")
        if _case_outcome(entry) != entry["outcome"]:
            return (f"the case {entry['id']} has the outcome {entry['outcome']}, which its "
                    "assertions' outcomes do not imply")
    summary, verdict = summarize(report["cases"])
    if report["aborted"] is not None:
        verdict = "aborted"
    if report["summary"] != summary:
        return "its summary is not the one its cases imply"
    if report["verdict"] != verdict:
        return f"its verdict is {report['verdict']}, but its cases imply {verdict}"
    return None


def result_problem(doc) -> str | None:
    """None if `doc` may be published, else a sentence fragment saying why not. Shape is checked
    before meaning, so the meaning checks can rely on every field being present and typed."""
    problem = shape_problem(doc)
    if problem:
        return problem
    try:
        json.dumps(doc, ensure_ascii=False).encode("utf-8")
    except UnicodeEncodeError:
        # JSON escapes can spell a lone surrogate, which no UTF-8 file or page can hold.
        return "it carries text that is not valid Unicode"
    # The schema's date pattern is syntax only; whether the day exists is meaning. Every kind of
    # provenance has exactly one date, and the shape check guarantees it.
    try:
        date.fromisoformat(doc["provenance"]["date"])
    except ValueError:
        return f"provenance.date {doc['provenance']['date']} is not a day on the calendar"
    return _meaning_problem(doc["report"])


@dataclass(frozen=True)
class Result:
    path: Path  # relative to the results directory it was loaded from
    doc: dict


def _read_error(path: Path, exc: JsonFileError) -> RunnerError:
    if exc.kind in ("missing", "io"):
        code = E_RESULT_READ_TRANSIENT if exc.transient else E_RESULT_READ
    else:
        code = E_RESULT_SIZE if exc.kind == "size" else E_RESULT_FORMAT
    return RunnerError(code, f"The result file {path} {exc.sentence}.")


def _layout_error(path: Path, why: str) -> RunnerError:
    return RunnerError(E_RESULT_PATH, f"The results directory holds {path}, {why}. A results "
                                      "directory holds only README.md and files at "
                                      "<implementation>/<version>/<profile>.json.")


def _discover(root: Path, max_files: int, max_total_bytes: int) -> list[Path]:
    """Every result file under `root`, refusing anything outside the layout and stopping, before
    any file is read, at more than `max_files` files or `max_total_bytes` bytes."""
    found, total = [], 0
    def unreadable(exc: OSError):
        transient = exc.errno in TRANSIENT_ERRNOS
        raise RunnerError(E_RESULT_READ_TRANSIENT if transient else E_RESULT_READ,
                          f"The results directory {exc.filename} could not be scanned: "
                          f"{exc.strerror or exc}.") from exc

    for directory, dirnames, filenames in os.walk(root, onerror=unreadable):
        dirnames.sort()
        depth = len(Path(directory).relative_to(root).parts)
        for name in sorted(dirnames + filenames):
            path = Path(directory) / name
            if path.is_symlink():
                raise _layout_error(path, "which is a symbolic link")
            if name in dirnames:
                if depth >= 2:
                    raise _layout_error(path, "a directory nested deeper than a version")
                continue
            if depth == 0 and name == "README.md":
                continue
            if depth != 2 or not name.endswith(".json") or name.startswith("."):
                raise _layout_error(path, "which is not a result file in its place")
            if len(found) == max_files:
                raise RunnerError(E_RESULTS_COUNT, f"The results directory {root} holds more "
                                                   f"than {max_files} result files, the most "
                                                   "the site build will read.")
            try:
                total += os.path.getsize(path)
            except OSError as exc:
                transient = exc.errno in TRANSIENT_ERRNOS
                raise RunnerError(E_RESULT_READ_TRANSIENT if transient else E_RESULT_READ,
                                  f"The result file {path} could not be sized: "
                                  f"{exc.strerror or exc}.") from exc
            if total > max_total_bytes:
                raise RunnerError(E_RESULTS_BYTES, f"The result files under {root} add up to "
                                                   f"more than {max_total_bytes} bytes, the most "
                                                   "the site build will read.")
            found.append(path)
    return sorted(found)


def load_results(root, *, kinds: tuple[str, ...], max_bytes: int = MAX_RESULT_BYTES,
                 max_files: int = MAX_RESULT_FILES,
                 max_total_bytes: int = MAX_RESULTS_BYTES) -> list[Result]:
    """Every result under `root`, sorted by path, each of a provenance kind in `kinds`."""
    root = Path(root)
    if not root.is_dir():
        raise RunnerError(E_RESULTS_MISSING, f"The results directory {root} does not exist.")
    loaded = []
    for path in _discover(root, max_files, max_total_bytes):
        try:
            doc = read_json(path, max_bytes)
        except JsonFileError as exc:
            raise _read_error(path, exc) from exc
        problem = result_problem(doc)
        if problem:
            raise RunnerError(E_RESULT_FORMAT, f"The result file {path} cannot be published: "
                                               f"{problem}.")
        kind = doc["provenance"]["kind"]
        if kind not in kinds:
            raise RunnerError(E_RESULT_PROVENANCE,
                              f"The result file {path} is labelled {kind}, which {root} may not "
                              f"hold; it holds only {' and '.join(kinds)} results. A reproduced "
                              "result is written by this repository's CI at build time and is "
                              "never committed.")
        relative = path.relative_to(root)
        expected = result_path(doc)
        if relative != expected:
            raise RunnerError(E_RESULT_PATH, f"The result file {path} is at {relative.as_posix()}, "
                                             f"but its report places it at "
                                             f"{expected.as_posix()}.")
        loaded.append(Result(relative, doc))
    return loaded


def wrap(report_path, provenance: dict, into) -> Path:
    """Put the report at `report_path` into an envelope with `provenance` and write it under
    `into` at the path its content implies. Refuses to overwrite, and writes nothing on refusal."""
    report_path, into = Path(report_path), Path(into)
    try:
        report = read_json(report_path, MAX_RESULT_BYTES)
    except JsonFileError as exc:
        raise _read_error(report_path, exc) from exc
    doc = {"result_version": 1, "provenance": provenance, "report": report}
    problem = result_problem(doc)
    if problem:
        raise RunnerError(E_RESULT_FORMAT, f"The report {report_path} cannot be published with "
                                           f"this provenance: {problem}.")
    target = into / result_path(doc)
    exists = RunnerError(E_RESULT_EXISTS, f"A result already exists at {target}. A published "
                                          "result is not replaced in place; remove it in the "
                                          "same change if it is meant to go.")
    if target.exists():
        raise exists
    text = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
    target.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary = tempfile.mkstemp(dir=target.parent, suffix=".tmp")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as f:
            f.write(text)
        # A hard link, unlike a rename, fails rather than replace a file that appeared after
        # the check above, and the target still appears whole or not at all.
        os.link(temporary, target)
    except OSError as exc:
        # The write's own error is the one to report, so cleanup here is best effort.
        with contextlib.suppress(OSError):
            os.unlink(temporary)
        if isinstance(exc, FileExistsError):
            raise exists from exc
        code = (E_RESULT_WRITE_TRANSIENT if exc.errno in TRANSIENT_ERRNOS
                else E_RESULT_WRITE)
        raise RunnerError(code, f"The result could not be written to {target}: {exc}.") from exc
    try:
        os.unlink(temporary)
    except OSError as exc:
        # The result is published, but the leftover file would make the next results check
        # refuse the directory, so it is reported with a code.
        code = E_RESULT_WRITE_TRANSIENT if exc.errno in TRANSIENT_ERRNOS else E_RESULT_WRITE
        raise RunnerError(code, f"The result was written to {target}, but its temporary file "
                                f"{temporary} could not be removed: {exc}. Remove it before the "
                                "next results check.") from exc
    return target


class _UsageError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise _UsageError(message)


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="scripts/results",
                     description="Check published results, or wrap a report for publication.")
    commands = parser.add_subparsers(dest="command")
    check = commands.add_parser("check", help="validate a directory of submitted results")
    check.add_argument("directory")
    wrap_ = commands.add_parser("wrap", help="put a kcs run report into a provenance envelope")
    wrap_.add_argument("report", help="the JSON report written by kcs run --report")
    wrap_.add_argument("--into", required=True, help="the results directory to write under")
    wrap_.add_argument("--date", required=True, help="the date of the run, YYYY-MM-DD")
    kind = wrap_.add_mutually_exclusive_group(required=True)
    kind.add_argument("--submitted", action="store_true",
                      help="a maintainer's claim, sent by pull request")
    kind.add_argument("--reproduced", action="store_true",
                      help="a run by this repository's CI (used by the Pages workflow)")
    wrap_.add_argument("--submitter", help="with --submitted: who submits it")
    wrap_.add_argument("--pull-request", help="with --submitted: the pull request's URL")
    wrap_.add_argument("--run", help="with --reproduced: the CI run's URL")
    wrap_.add_argument("--commit", help="with --reproduced: the suite commit the run used")
    return parser


def _provenance(args) -> dict:
    if args.submitted:
        fields = {"submitter": args.submitter, "pull_request": args.pull_request}
        kind = "submitted"
    else:
        fields = {"run": args.run, "commit": args.commit}
        kind = "reproduced"
    missing = [f"--{name.replace('_', '-')}" for name, value in fields.items() if value is None]
    if missing:
        raise _UsageError(f"--{kind} needs {' and '.join(missing)}")
    return {"kind": kind, **fields, "date": args.date}


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    try:
        args = parser.parse_args(argv)
        if args.command is None:
            print(f"{E_USAGE_MISSING}: No command was given; use check or wrap.", file=sys.stderr)
            return EXIT_USAGE
        provenance = _provenance(args) if args.command == "wrap" else None
    except _UsageError as exc:
        print(f"{E_USAGE_INVALID}: The command line could not be understood ({exc}). Retrying "
              "the same command will not help; correct the arguments.", file=sys.stderr)
        return EXIT_USAGE
    try:
        if args.command == "check":
            loaded = load_results(args.directory, kinds=("submitted",))
            print(f"{len(loaded)} result{'' if len(loaded) == 1 else 's'} under "
                  f"{args.directory} can be published.")
        else:
            print(f"wrote {wrap(args.report, provenance, args.into)}")
    except RunnerError as err:
        print(f"scripts/results: {err}", file=sys.stderr)
        return EXIT_FAULT
    return 0
