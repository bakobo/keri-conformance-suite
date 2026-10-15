"""Run the adapters shipped in adapters/ and keep the committed results of those runs current.

The site publishes only committed results, and CI never runs an adapter (docs/publishing-results.md,
"Results of the shipped adapters"). Each shipped adapter's outcomes for each profile it is meant
for live in one committed file, results/<implementation>/<version>/<profile>.json, labelled
maintainer-run. This module is the one tool that writes and checks them:

    scripts/reproduce-results refresh [--adapter NAME ...] [--maintainer NAME] [--date YYYY-MM-DD]
    scripts/reproduce-results check [--adapter NAME ...]
    scripts/reproduce-results readmes [--check]
    scripts/reproduce-results reproduce OUT --run URL --commit SHA [--date YYYY-MM-DD]

Every command that runs adapters first builds each selected one from its lockfile, with the
command its README and CI use, so a run never uses a build left over from other code. The
toolchains (uv with Python 3.14 and 3.12, the Rust toolchains rust-toolchain.toml names, Node,
libsodium) must already be installed.

refresh builds and runs the selected adapters (all by default) and replaces their committed
results, then rewrites the generated results table in each adapter's README. It refuses a working
tree with changes outside results/ and the adapter READMEs, before the runs and again after them,
so the suite commit a result names is the code that produced it. check builds and reruns them
and compares each run, outcome by outcome, with the committed maintainer-run result
(tools/outcomes.py); any difference fails, an improvement included, until a refresh records it.
readmes renders the README tables from the committed results without running anything; with
--check it fails when one is stale, when a maintainer-run result names an adapter this
repository does not ship, or when a shipped adapter build lacks a committed result for one of its
profiles, which CI checks. reproduce is for the on-demand workflow: it builds and
runs every adapter, writes the results labelled reproduced into OUT, which is never committed,
and compares those same runs with the committed results.

Exit status: 0 on success; 1 when check, reproduce or readmes --check finds a difference; 2 on a
usage error; 4 when the tool could not do its job (an adapter that would not build, a dirty
tree, a report that could not be published, a file it could not read or write).
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

E_BUILD = "e.env.dependency.adapter-build.f"
E_NOT_BUILT = "e.env.dependency.adapter-not-built.f"
E_DIRTY = "e.state.conflict.dirty-tree.f"
E_NO_REPORT = "e.env.command.no-report.f"
E_ABORTED = "e.input.range.aborted-report.f"
E_GIT = "e.env.command.git.f"
E_README = "e.self.config.readme-markers.f"
E_README_IO = "e.env.filesystem.readme.f"
E_README_IO_TRANSIENT = "e.env.filesystem.readme.r"
E_REGRESSION = "e.state.conflict.result-regression.f"
E_STALE = "e.state.conflict.result-stale.f"
E_UNCOMMITTED = "e.state.missing.committed-result.f"
E_UNSHIPPED = "e.rule.result.unshipped-adapter.f"

BEGIN = ("<!-- BEGIN generated results: scripts/reproduce-results writes this table from "
         "results/; do not edit it -->")
END = "<!-- END generated results -->"
# Environment variables that move where a build puts what the runs execute.
REDIRECTS = frozenset({"VIRTUAL_ENV", "UV_PROJECT_ENVIRONMENT", "CARGO_TARGET_DIR",
                       "CARGO_BUILD_TARGET_DIR", "CARGO_BUILD_TARGET"})
# Paths a refresh may find changed: what it writes itself.
REFRESHABLE = ("results/",)


@dataclass(frozen=True)
class Instance:
    """One shipped adapter build: what to call it, how to build it (each step a directory, a
    command and extra environment), the executable that build leaves, the profiles it is run
    against, the adapter name its hello reports, and the README whose results table lists its
    committed results."""
    name: str
    build: tuple[tuple[str, tuple[str, ...], tuple[tuple[str, str], ...]], ...]
    executable: str
    profiles: tuple[str, ...]
    adapter: str
    readme: str


def _step(directory: str, *argv: str, **env: str):
    return (directory, argv, tuple(sorted(env.items())))


INSTANCES = (
    Instance("keripy", (_step("adapters/keripy", "uv", "sync", "--locked"),),
             "adapters/keripy/.venv/bin/kcs-adapter-keripy",
             ("cesr-v1.0", "keri-v1.0.1", "keri-escrow", "acdc-v1.0"),
             "kcs-adapter-keripy", "adapters/keripy/README.md"),
    Instance("keripy-1.2.14",
             (_step("adapters/keripy/keripy-1.2.14", "uv", "sync", "--locked", UV_PYTHON="3.12"),),
             "adapters/keripy/keripy-1.2.14/.venv/bin/kcs-adapter-keripy",
             ("keripy-1x-interop",), "kcs-adapter-keripy", "adapters/keripy/README.md"),
    Instance("keriox", (_step("adapters/keriox", "cargo", "build", "--locked"),),
             "adapters/keriox/target/debug/kcs-adapter-keriox",
             ("cesr-v1.0", "keripy-1x-interop"), "kcs-adapter-keriox",
             "adapters/keriox/README.md"),
    Instance("affinidi", (_step("adapters/affinidi", "cargo", "build", "--locked"),),
             "adapters/affinidi/target/debug/kcs-adapter-affinidi",
             ("cesr-v1.0", "keripy-1x-interop"), "kcs-adapter-affinidi",
             "adapters/affinidi/README.md"),
    Instance("signify-ts",
             (_step("adapters/signify-ts", "npm", "ci", "--no-audit", "--no-fund"),),
             "adapters/signify-ts/bin/kcs-adapter-signify-ts",
             ("cesr-v1.0", "keripy-1x-interop"), "kcs-adapter-signify-ts",
             "adapters/signify-ts/README.md"),
)


def _today() -> str:
    return datetime.now(UTC).date().isoformat()


def build_adapter(repo: Path, instance: Instance) -> None:
    """Build `instance` from its lockfile, as its README and CI do. Each step's output goes to
    this process's own, so a failure explains itself. Variables that would send a build's output
    somewhere other than the executable path the runs use are not passed on, or a build could
    succeed elsewhere while a stale executable runs; that includes the suite's own virtual
    environment, since an adapter's uv project has its own."""
    inherited = {k: v for k, v in os.environ.items() if k not in REDIRECTS}
    for directory, argv, env in instance.build:
        try:
            done = subprocess.run(list(argv), cwd=repo / directory,
                                  env={**inherited, **dict(env)}, check=False)
        except OSError as exc:
            raise RunnerError(E_BUILD, f"{instance.name} could not be built: {argv[0]} could not "
                                       f"be started ({exc}). Install the toolchain its README "
                                       "names.") from exc
        if done.returncode != 0:
            raise RunnerError(E_BUILD, f"{instance.name} could not be built: {' '.join(argv)} "
                                       f"exited {done.returncode} in {directory}; its output "
                                       "above says why.")


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


def _run_all(repo: Path, instances, work: Path, run, build) -> list[tuple[Instance, str, dict]]:
    """Every (instance, profile, report) of the selected instances, building each first and
    refusing before any runs if one of them did not leave its executable."""
    for instance in instances:
        build(repo, instance)
    missing = [i for i in instances if not os.access(repo / i.executable, os.X_OK)]
    if missing:
        names = ", ".join(f"{i.name} ({i.executable})" for i in missing)
        raise RunnerError(E_NOT_BUILT, f"These adapters built without leaving their executable: "
                                       f"{names}.")
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


def _clean_commit(repo: Path) -> str:  # ~4my7
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


def refresh(repo, names=(), *, maintainer: str, day: str, run=kcs_run,
            build=build_adapter) -> list[str]:
    """Replace the committed results of the selected instances with fresh runs, and remove the
    results their new runs supersede. Returns the paths written and removed, for printing."""
    repo = Path(repo)
    commit = _clean_commit(repo)
    _readmes(repo)  # a README the tables cannot be written into is refused before any result moves
    provenance = {"kind": "maintainer-run", "maintainer": maintainer, "commit": commit,
                  "date": day}
    results = repo / "results"
    with tempfile.TemporaryDirectory() as scratch:
        work = Path(scratch)
        runs = _run_all(repo, selected(names), work, run, build)
        if _clean_commit(repo) != commit:
            raise RunnerError(E_DIRTY, f"HEAD moved from {commit} while the adapters ran, so the "
                                       "runs cannot be attributed to one commit. Nothing was "
                                       "written; rerun the refresh.")
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


def _compare(repo: Path, runs) -> list[str]:
    """Every way `runs` differ from the committed maintainer-run results, as lines starting with
    a code."""
    lines = []
    probe = {"kind": "maintainer-run", "maintainer": "check", "commit": "0" * 40,
             "date": _today()}
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
            base = outcomes.read_committed(committed, kind="maintainer-run")
        except outcomes.InputError as exc:
            lines.append(f"{E_UNCOMMITTED}: {where}: {exc}")
            continue
        regressions, improvements = outcomes.compare(base, report)
        lines += [f"{E_REGRESSION}: {where}: {line}" for line in regressions]
        lines += [f"{E_STALE}: {where}: {line} (an improvement; record it with "
                  f"scripts/reproduce-results refresh --adapter {instance.name})"
                  for line in improvements]
    return lines


def check(repo, names=(), *, run=kcs_run, build=build_adapter) -> list[str]:
    """Every way a fresh run of the selected instances differs from the committed results, and
    every stale README table, as lines starting with a code; empty when they all match."""
    repo = Path(repo)
    with tempfile.TemporaryDirectory() as scratch:
        runs = _run_all(repo, selected(names), Path(scratch), run, build)
    return _compare(repo, runs) + check_readmes(repo)


def reproduce(repo, out, *, run_url: str, commit: str, day: str, run=kcs_run,
              build=build_adapter) -> tuple[list[str], list[str]]:
    """Build and run every instance, write each result, labelled reproduced, under `out`, and
    compare those same runs with the committed results. Returns (lines written, differences)."""
    repo, out = Path(repo), Path(out)
    provenance = {"kind": "reproduced", "run": run_url, "commit": commit, "date": day}
    written = []
    with tempfile.TemporaryDirectory() as scratch:
        work = Path(scratch)
        runs = _run_all(repo, INSTANCES, work, run, build)
        for n, (_, _, report) in enumerate(runs):
            source = work / f"{n}.report.json"
            source.write_text(json.dumps(report), encoding="utf-8")
            written.append(f"wrote {wrap(source, provenance, out)}")
    return written, _compare(repo, runs)


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


def _readme_error(path: Path, exc: OSError, verb: str) -> RunnerError:
    code = E_README_IO_TRANSIENT if exc.errno in outcomes.TRANSIENT_ERRNOS else E_README_IO
    return RunnerError(code, f"The README {path} could not be {verb}: {exc}.")


def _readmes(repo: Path) -> dict[str, tuple[str, str]]:
    """Each adapter README's current text and the text it should have."""
    results = load_results(repo / "results", kinds=COMMITTED_KINDS)
    found = {}
    for readme in sorted({i.readme for i in INSTANCES}):
        try:
            text = (repo / readme).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            if isinstance(exc, UnicodeDecodeError):
                raise RunnerError(E_README, f"The README {repo / readme} is not UTF-8 text.") \
                    from exc
            raise _readme_error(repo / readme, exc, "read") from exc
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
            try:
                (Path(repo) / readme).write_text(wanted, encoding="utf-8")
            except OSError as exc:
                raise _readme_error(Path(repo) / readme, exc, "written") from exc
            changed.append(f"rewrote the results table in {readme}")
    return changed


def _unshipped(repo: Path) -> list[str]:  # ~3loh
    """A maintainer-run result says the suite's maintainer ran an adapter this repository ships;
    one naming any other adapter is a claim mislabelled, so it is refused."""
    shipped = {i.adapter for i in INSTANCES}
    return [f"{E_UNSHIPPED}: results/{r.path.as_posix()} is labelled maintainer-run but names the "
            f"adapter {json.dumps(r.doc['report']['hello']['adapter']['name'][:80])}, which this "
            "repository does not ship; a result from any other adapter is submitted"
            for r in load_results(repo / "results", kinds=COMMITTED_KINDS)
            if r.doc["provenance"]["kind"] == "maintainer-run"
            and r.doc["report"]["hello"]["adapter"]["name"] not in shipped]


def _missing(repo: Path) -> list[str]:
    """Every shipped adapter build has a committed maintainer-run result for each profile it is
    run against. CI never reruns the adapters, so without this a pull request could delete one
    and regenerate the README table to match, and nothing would notice."""
    have = {(r.doc["report"]["hello"]["adapter"]["name"], r.doc["report"]["filters"]["profile"])
            for r in load_results(repo / "results", kinds=COMMITTED_KINDS)
            if r.doc["provenance"]["kind"] == "maintainer-run"}
    return [f"{E_UNCOMMITTED}: {i.name} {profile}: results/ holds no maintainer-run result from "
            f"{i.adapter} for {profile}; restore it with scripts/reproduce-results refresh "
            f"--adapter {i.name}"
            for i in INSTANCES for profile in i.profiles if (i.adapter, profile) not in have]


def check_readmes(repo) -> list[str]:
    repo = Path(repo)
    return _unshipped(repo) + _missing(repo) + [
        f"{E_STALE}: the results table in {readme} does not match results/; rewrite it with "
        "scripts/reproduce-results readmes"
        for readme, (text, wanted) in _readmes(repo).items() if text != wanted]


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
    refresh_ = commands.add_parser("refresh", help="rebuild and rerun adapters and replace their "
                                                   "committed results")
    check_ = commands.add_parser("check", help="rebuild and rerun adapters and compare with the "
                                               "committed results")
    for sub in (refresh_, check_):
        sub.add_argument("--adapter", action="append", choices=names, default=[],
                         help="only this adapter build (repeatable; default: every one)")
    refresh_.add_argument("--maintainer", help="who ran it (default: git config user.name)")
    refresh_.add_argument("--date", default=_today(), help="YYYY-MM-DD")
    readmes = commands.add_parser("readmes", help="rewrite the adapter READMEs' results tables "
                                                  "from results/")
    readmes.add_argument("--check", action="store_true", help="fail if one is stale; write nothing")
    reproduce_ = commands.add_parser("reproduce", help="rebuild and rerun every adapter, write "
                                                       "reproduced results into a directory and "
                                                       "compare them (workflow use)")
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


def _differences(found: list[str], matched: str) -> int:
    for line in found:
        print(line)
    if found:
        return 1
    print(matched)
    return 0


def main(argv: list[str] | None = None) -> int:
    maintainer = ""
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
            lines, found = reproduce(repo, args.out, run_url=args.run, commit=args.commit,
                                     day=args.date)
            for line in lines:
                print(line)
            return _differences(found, "The runs match the committed results.")
        elif args.command == "readmes" and not args.check:
            lines = update_readmes(repo)
        elif args.command == "check":
            return _differences(check(repo, args.adapter), "The runs match the committed results.")
        else:
            return _differences(check_readmes(repo), "The README results tables match results/.")
    except RunnerError as err:
        print(f"scripts/reproduce-results: {err}", file=sys.stderr)
        return EXIT_FAULT
    for line in lines:
        print(line)
    return 0
