"""Run the adapters shipped in adapters/ and keep the committed results of those runs current.

The site publishes only committed results, and CI never runs an adapter (docs/publishing-results.md,
"Results of the shipped adapters"). Each shipped adapter's outcomes for each profile it is meant
for live in one committed file, results/<implementation>/<version>/<profile>.json, labelled
maintainer-run. This module is the one tool that writes and checks them:

    scripts/reproduce-results refresh [--adapter NAME ...] [--maintainer NAME] [--date YYYY-MM-DD]
    scripts/reproduce-results check [--adapter NAME ...]
    scripts/reproduce-results readmes [--check]
    scripts/reproduce-results reproduce OUT --run URL --commit SHA [--date YYYY-MM-DD]

refresh runs the selected adapters (all by default) and replaces their committed results, then
rewrites the generated results table in each adapter's README. It refuses a working tree with
changes outside results/ and the adapter READMEs, so the suite commit a result names is the code
that produced it. check reruns them and compares each run, outcome by outcome, with the committed
result (tools/outcomes.py); any difference fails, an improvement included, until a refresh
records it. readmes renders the README tables from the committed results without running
anything; with --check it fails when one is stale, which CI checks. reproduce is for the
on-demand workflow: it runs every adapter and writes the results labelled reproduced into OUT,
which is never committed.

Every adapter must already be built at its pin, as its README says; an adapter that is not built
is refused rather than skipped, because a run that silently leaves one out would look complete.

Exit status: 0 on success; 1 when check or readmes --check finds a difference; 2 on a usage error;
4 when the tool could not do its job (an adapter not built, a dirty tree, a report that could not
be published).
"""

import argparse
import contextlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from keri_conformance.errors import E_USAGE_INVALID, EXIT_FAULT, EXIT_USAGE, RunnerError
from tools import outcomes
from tools.results import (
    COMMITTED_KINDS,
    E_RESULT_WRITE,
    E_RESULT_WRITE_TRANSIENT,
    load_results,
    result_path,
    result_problem,
    wrap,
)

E_NOT_BUILT = "e.env.dependency.adapter-not-built.f"
E_DIRTY = "e.state.conflict.dirty-tree.f"
E_NO_REPORT = "e.env.command.no-report.f"
E_ABORTED = "e.input.range.aborted-report.f"
E_GIT = "e.env.command.git.f"
E_README = "e.self.config.readme-markers.f"
E_REGRESSION = "e.state.conflict.result-regression.f"
E_STALE = "e.state.conflict.result-stale.f"
E_UNCOMMITTED = "e.state.missing.committed-result.f"

BEGIN = ("<!-- BEGIN generated results: scripts/reproduce-results writes this table from "
         "results/; do not edit it -->")
END = "<!-- END generated results -->"
# Paths a refresh may find changed: what it writes itself.
REFRESHABLE = ("results/",)


@dataclass(frozen=True)
class Instance:
    """One shipped adapter build: what to call it, the executable its README builds, the profiles
    it is run against, and the README whose results table lists its committed results."""
    name: str
    executable: str
    profiles: tuple[str, ...]
    adapter: str  # the adapter name its hello reports
    readme: str


INSTANCES = (
    Instance("keripy", "adapters/keripy/.venv/bin/kcs-adapter-keripy",
             ("cesr-v1.0", "keri-v1.0.1", "keri-escrow", "acdc-v1.0"),
             "kcs-adapter-keripy", "adapters/keripy/README.md"),
    Instance("keripy-1.2.14", "adapters/keripy/keripy-1.2.14/.venv/bin/kcs-adapter-keripy",
             ("keripy-1x-interop",), "kcs-adapter-keripy", "adapters/keripy/README.md"),
    Instance("keriox", "adapters/keriox/target/debug/kcs-adapter-keriox",
             ("cesr-v1.0", "keripy-1x-interop"), "kcs-adapter-keriox",
             "adapters/keriox/README.md"),
    Instance("affinidi", "adapters/affinidi/target/debug/kcs-adapter-affinidi",
             ("cesr-v1.0", "keripy-1x-interop"), "kcs-adapter-affinidi",
             "adapters/affinidi/README.md"),
    Instance("signify-ts", "adapters/signify-ts/bin/kcs-adapter-signify-ts",
             ("cesr-v1.0", "keripy-1x-interop"), "kcs-adapter-signify-ts",
             "adapters/signify-ts/README.md"),
)


def _today() -> str:
    return datetime.now(UTC).date().isoformat()


def kcs_run(repo: Path, executable: Path, profile: str, report: Path) -> None:
    """Run one profile against one adapter with this environment's runner. kcs exits non-zero
    for every verdict but conformant, which is a result rather than a failure here; whether a
    report was written is what the callers judge. The suite is named relative to the checkout,
    so the report records its cases directory as `cases` rather than a path on this machine."""
    subprocess.run([sys.executable, "-m", "keri_conformance", "run", "--suite", ".",
                    "--adapter", str(executable), "--profile", profile, "--report", str(report)],
                   cwd=repo, check=False)


def _git(repo: Path, *args: str) -> str:
    try:
        done = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                              check=False)
    except OSError as exc:
        raise RunnerError(E_GIT, f"git could not be started: {exc}.") from exc
    if done.returncode != 0:
        raise RunnerError(E_GIT, f"git {' '.join(args)} failed in {repo}: "
                                 f"{done.stderr.strip() or done.returncode}.")
    return done.stdout


def selected(names) -> tuple[Instance, ...]:
    return tuple(i for i in INSTANCES if not names or i.name in names)


def _run_all(repo: Path, instances, work: Path, run) -> list[tuple[Instance, str, dict]]:
    """Every (instance, profile, report) of the selected instances, refusing before it runs
    anything if one of them is not built."""
    missing = [i for i in instances if not os.access(repo / i.executable, os.X_OK)]
    if missing:
        names = ", ".join(f"{i.name} ({i.executable})" for i in missing)
        raise RunnerError(E_NOT_BUILT, f"These adapters are not built: {names}. Build each as its "
                                       "README says, or choose others with --adapter.")
    runs = []
    for instance in instances:
        for profile in instance.profiles:
            report = work / f"{instance.name}.{profile}.json"
            run(repo, repo / instance.executable, profile, report)
            try:
                runs.append((instance, profile, outcomes.read_report(report)))
            except outcomes.InputError as exc:
                raise RunnerError(E_NO_REPORT, f"{instance.name} produced no usable report for "
                                               f"{profile}: {exc}") from exc
    return runs


def _clean_commit(repo: Path) -> str:
    """HEAD, after making sure the working tree holds nothing a run could depend on that HEAD
    does not."""
    status = _git(repo, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    dirty = []
    for entry in filter(None, status.split("\0")):
        path = entry[3:]
        readme = path.startswith("adapters/") and path.endswith("/README.md")
        if not (path.startswith(REFRESHABLE) or readme):
            dirty.append(path)
    if dirty:
        shown = ", ".join(sorted(dirty)[:5]) + (" and more" if len(dirty) > 5 else "")
        raise RunnerError(E_DIRTY, f"The working tree has changes outside results/ and the "
                                   f"adapter READMEs ({shown}). A refreshed result names the "
                                   "suite commit it ran, so commit those changes first.")
    return _git(repo, "rev-parse", "HEAD").strip()


def _envelope(report: dict, provenance: dict) -> dict:
    return {"result_version": 1, "provenance": provenance, "report": report}


def refresh(repo, names=(), *, maintainer: str, day: str, run=kcs_run) -> list[str]:
    """Replace the committed results of the selected instances with fresh runs, and remove the
    results their new runs supersede. Returns the paths written and removed, for printing."""
    repo = Path(repo)
    provenance = {"kind": "maintainer-run", "maintainer": maintainer,
                  "commit": _clean_commit(repo), "date": day}
    results = repo / "results"
    with tempfile.TemporaryDirectory() as scratch:
        work = Path(scratch)
        runs = _run_all(repo, selected(names), work, run)
        for instance, profile, report in runs:
            if report["verdict"] == outcomes.ABORTED:
                raise RunnerError(E_ABORTED, f"The {profile} run of {instance.name} was aborted, "
                                             "and an aborted run is never committed; rerun it to "
                                             "completion. Nothing was written.")
        staged = []
        for n, (_, _, report) in enumerate(runs):
            source = work / f"{n}.report.json"
            source.write_text(json.dumps(report), encoding="utf-8")
            # wrap checks the report as the site build will and refuses to overwrite, so each run
            # is staged in its own directory and moved into place only once all of them passed.
            staged.append(wrap(source, provenance, work / f"{n}.out").relative_to(work / f"{n}.out"))
        written = []
        for n, relative in enumerate(staged):
            _install(work / f"{n}.out" / relative, results / relative)
            written.append(f"wrote results/{relative.as_posix()}")
    removed = _remove_superseded(results, runs, {s.as_posix() for s in staged})
    return written + removed + update_readmes(repo)


def _install(source: Path, target: Path) -> None:
    """Put source at target, replacing it whole or not at all. The staging directory may be on
    another filesystem than the repository (/tmp is often tmpfs), so the file is copied to a
    temporary file beside target first and renamed over it there."""
    temporary = None
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        handle, temporary = tempfile.mkstemp(dir=target.parent, suffix=".tmp")
        os.close(handle)
        shutil.copyfile(source, temporary)
        os.replace(temporary, target)
    except OSError as exc:
        if temporary:
            with contextlib.suppress(OSError):
                os.unlink(temporary)
        code = (E_RESULT_WRITE_TRANSIENT if exc.errno in outcomes.TRANSIENT_ERRNOS
                else E_RESULT_WRITE)
        raise RunnerError(code, f"The result could not be written to {target}: {exc}. Results "
                                "already moved into place stay; rerun the refresh.") from exc


def _remove_superseded(results: Path, runs, kept: set[str]) -> list[str]:
    """Committed maintainer-run results that a run just replaced under a new version: the same
    implementation and profile, from the same adapter, at another path."""
    ran = {(r["hello"]["adapter"]["name"], r["hello"]["implementation"]["name"],
            r["filters"]["profile"]) for _, _, r in runs}
    removed = []
    for result in load_results(results, kinds=COMMITTED_KINDS):
        report = result.doc["report"]
        key = (report["hello"]["adapter"]["name"], report["hello"]["implementation"]["name"],
               report["filters"]["profile"])
        if (result.doc["provenance"]["kind"] == "maintainer-run" and key in ran
                and result.path.as_posix() not in kept):
            (results / result.path).unlink()
            with contextlib.suppress(OSError):
                (results / result.path).parent.rmdir()
            removed.append(f"removed results/{result.path.as_posix()}, superseded")
    return removed


def check(repo, names=(), *, run=kcs_run) -> list[str]:
    """Every way a fresh run of the selected instances differs from the committed results, as
    lines starting with a code; empty when they all match."""
    repo = Path(repo)
    lines = []
    probe = {"kind": "maintainer-run", "maintainer": "check", "commit": "0" * 40,
             "date": _today()}
    with tempfile.TemporaryDirectory() as scratch:
        runs = _run_all(repo, selected(names), Path(scratch), run)
    for instance, profile, report in runs:
        where = f"{instance.name} {profile}"
        doc = _envelope(report, probe)
        problem = result_problem(doc)
        if problem:
            lines.append(f"{E_REGRESSION}: {where}: the run's report could not be published: "
                         f"{problem}")
            continue
        relative = result_path(doc).as_posix()
        committed = repo / "results" / relative
        if not committed.exists():
            lines.append(f"{E_UNCOMMITTED}: {where}: no committed result at results/{relative}")
            continue
        try:
            base = outcomes.read_committed(committed)
        except outcomes.InputError as exc:
            lines.append(f"{E_UNCOMMITTED}: {where}: {exc}")
            continue
        regressions, improvements = outcomes.compare(base, report)
        lines += [f"{E_REGRESSION}: {where}: {line}" for line in regressions]
        lines += [f"{E_STALE}: {where}: {line} (an improvement; record it with "
                  f"scripts/reproduce-results refresh --adapter {instance.name})"
                  for line in improvements]
    return lines + check_readmes(repo)


def reproduce(repo, out, *, run_url: str, commit: str, day: str, run=kcs_run) -> list[str]:
    """Run every instance and write each result, labelled reproduced, under `out`."""
    repo, out = Path(repo), Path(out)
    provenance = {"kind": "reproduced", "run": run_url, "commit": commit, "date": day}
    written = []
    with tempfile.TemporaryDirectory() as scratch:
        work = Path(scratch)
        for n, (_, _, report) in enumerate(_run_all(repo, INSTANCES, work, run)):
            source = work / f"{n}.report.json"
            source.write_text(json.dumps(report), encoding="utf-8")
            written.append(f"wrote {wrap(source, provenance, out)}")
    return written


# --- the README tables ---------------------------------------------------------------------------

def _cell(text: str) -> str:
    return text.replace("|", "\\|")


def _counts(report: dict, level: str) -> str:
    tally = report["summary"]["counts"].get("active", {}).get(level, {})
    return f"{tally.get('pass', 0)} / {tally.get('fail', 0)}"


def render_table(results, readme: str) -> str:
    """The generated block for `readme`: one row per committed maintainer-run result whose
    adapter is one of that README's."""
    adapters = {i.adapter for i in INSTANCES if i.readme == readme}
    rows = [BEGIN, "",
            ("| Implementation | Profile | Verdict | Active MUST pass / fail | "
             "Active SHOULD pass / fail | Active INTEROP pass / fail | "
             "Active cases not supported | Result |"),
            "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for result in results:
        report, provenance = result.doc["report"], result.doc["provenance"]
        if provenance["kind"] != "maintainer-run" or report["hello"]["adapter"]["name"] not in adapters:
            continue
        impl = report["hello"]["implementation"]
        rows.append(f"| {_cell(impl['name'])} {_cell(impl['version'])} | "
                    f"`{report['filters']['profile']}` | {report['verdict']} | "
                    f"{_counts(report, 'MUST')} | {_counts(report, 'SHOULD')} | "
                    f"{_counts(report, 'INTEROP')} | "
                    f"{len(report['summary']['not_supported_active'])} | "
                    f"[{provenance['date']}, suite {provenance['commit'][:8]}]"
                    f"(../../results/{result.path.as_posix()}) |")
    return "\n".join([*rows, "", END])


def _readmes(repo: Path) -> dict[str, tuple[str, str]]:
    """Each adapter README's current text and the text it should have."""
    results = load_results(repo / "results", kinds=COMMITTED_KINDS)
    found = {}
    for readme in sorted({i.readme for i in INSTANCES}):
        text = (repo / readme).read_text(encoding="utf-8")
        if text.count(BEGIN) != 1 or text.count(END) != 1 or text.index(BEGIN) > text.index(END):
            raise RunnerError(E_README, f"{readme} must hold the generated results table's "
                                        "markers exactly once each, BEGIN before END, so the "
                                        "table has one place to go.")
        head, rest = text.split(BEGIN)
        tail = rest.split(END)[1]
        found[readme] = (text, head + render_table(results, readme) + tail)
    return found


def update_readmes(repo) -> list[str]:
    changed = []
    for readme, (text, wanted) in _readmes(Path(repo)).items():
        if text != wanted:
            (Path(repo) / readme).write_text(wanted, encoding="utf-8")
            changed.append(f"rewrote the results table in {readme}")
    return changed


def check_readmes(repo) -> list[str]:
    return [f"{E_STALE}: the results table in {readme} does not match results/; rewrite it with "
            "scripts/reproduce-results readmes"
            for readme, (text, wanted) in _readmes(Path(repo)).items() if text != wanted]


# --- command line --------------------------------------------------------------------------------

class _UsageError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise _UsageError(message)


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="scripts/reproduce-results",
                     description="Run the shipped adapters and keep their committed results "
                                 "current.")
    parser.add_argument("--repo", default=str(Path(__file__).resolve().parent.parent),
                        help=argparse.SUPPRESS)
    commands = parser.add_subparsers(dest="command", required=True)
    names = [i.name for i in INSTANCES]
    refresh_ = commands.add_parser("refresh", help="rerun adapters and replace their committed "
                                                   "results")
    check_ = commands.add_parser("check", help="rerun adapters and compare with the committed "
                                               "results")
    for sub in (refresh_, check_):
        sub.add_argument("--adapter", action="append", choices=names, default=[],
                         help="only this adapter build (repeatable; default: every one)")
    refresh_.add_argument("--maintainer", help="who ran it (default: git config user.name)")
    refresh_.add_argument("--date", default=_today(), help="YYYY-MM-DD")
    readmes = commands.add_parser("readmes", help="rewrite the adapter READMEs' results tables "
                                                  "from results/")
    readmes.add_argument("--check", action="store_true", help="fail if one is stale; write nothing")
    reproduce_ = commands.add_parser("reproduce", help="run every adapter and write reproduced "
                                                       "results into a directory (workflow use)")
    reproduce_.add_argument("out")
    reproduce_.add_argument("--run", required=True, help="the workflow run's URL")
    reproduce_.add_argument("--commit", required=True, help="the suite commit the run used")
    reproduce_.add_argument("--date", default=_today(), help="YYYY-MM-DD")
    return parser


def _maintainer(args) -> str:
    if args.maintainer:
        return args.maintainer
    name = _git(Path(args.repo), "config", "--default", "", "user.name").strip()
    if not name:
        raise _UsageError("no --maintainer was given and git config user.name is empty")
    return name


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        repo = Path(args.repo)
        if args.command == "refresh":
            maintainer = _maintainer(args)
    except _UsageError as exc:
        print(f"{E_USAGE_INVALID}: The command line could not be understood ({exc}). Retrying "
              "the same command will not help; correct the arguments.", file=sys.stderr)
        return EXIT_USAGE
    except RunnerError as err:
        print(f"scripts/reproduce-results: {err}", file=sys.stderr)
        return EXIT_FAULT
    try:
        if args.command == "refresh":
            lines = refresh(repo, args.adapter, maintainer=maintainer, day=args.date)
        elif args.command == "reproduce":
            lines = reproduce(repo, args.out, run_url=args.run, commit=args.commit,
                              day=args.date)
        elif args.command == "readmes" and not args.check:
            lines = update_readmes(repo)
        else:
            found = (check(repo, args.adapter) if args.command == "check"
                     else check_readmes(repo))
            for line in found:
                print(line)
            if found:
                return 1
            print("The runs match the committed results." if args.command == "check"
                  else "The README results tables match results/.")
            return 0
    except RunnerError as err:
        print(f"scripts/reproduce-results: {err}", file=sys.stderr)
        return EXIT_FAULT
    for line in lines:
        print(line)
    return 0

