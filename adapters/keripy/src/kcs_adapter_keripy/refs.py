"""The weekly check of this adapter against other keripy refs (this.i, "The keripy adapter is
checked weekly against other keripy refs").

    python -m kcs_adapter_keripy.refs run --refs FILE --state FILE --inputs HASH --suite DIR --work DIR

Reads the list of refs (adapters/keripy/refs.json), resolves each to a commit with git
ls-remote, and skips a ref whose commit and suite inputs (HASH, computed by the workflow over
cases, profiles, runner and adapter) both match the last completed run in the state file. Any
other ref gets a fresh virtualenv with keripy at that commit and this adapter installed without
its own keripy pin, and each of its profiles is run with kcs and compared with the committed
baseline, ignoring only the implementation's commit. Any other difference fails the check, and
so does a skipped ref whose last run differed. Exits 0 when every ref matched, 1 when any
differed or could not be checked, 2 on a usage error. Standard library only.
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

from kcs_adapter_keripy import baseline

E_USAGE = "e.input.format.usage.f"
E_REFS_FORMAT = "e.input.format.keripy-refs.f"
E_MISSING_FILE = "e.input.missing.file.f"
E_READ = "e.env.filesystem.read.r"
E_FILE_SIZE = "e.input.range.file-size.f"
E_MISSING_REF = "e.input.missing.keripy-ref.f"
E_COMMAND = "e.env.command.failed.r"
E_INSTALL = "e.env.dependency.keripy-ref.r"
E_DIFFERS = "e.state.conflict.keripy-ref-differs.f"
E_WRITE_TRANSIENT = "e.env.filesystem.write.r"
E_WRITE = "e.env.filesystem.write.f"
W_STATE = "w.input.format.keripy-refs-state.f"

MAX_FILE_BYTES = 1024 * 1024
STATE_FORMAT = 1
# A command that has not finished in this long is stuck; a keripy install takes a few minutes.
COMMAND_TIMEOUT = 1800
FIELDS = ("name", "source", "ref", "python", "profiles")
NAME = re.compile(r"[a-z0-9][a-z0-9.-]*")
SOURCE = re.compile(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
# A ref starting with '-' could be read by git as an option.
REF = re.compile(r"[A-Za-z0-9_.][A-Za-z0-9_./-]*")
PYTHON = re.compile(r"3\.\d+")
PROFILE = re.compile(r"[a-z0-9][a-z0-9.-]*")
SHA = re.compile(r"[0-9a-f]{40}")
IDENTITY = "implementation commit:"


class UsageError(Exception):
    """The check was given something it cannot use; the message starts with its code."""


class CommandError(Exception):
    """A command the check ran failed; the message starts with its code."""


def run_command(cmd, *, check=True):
    """Run cmd and return its standard output. With check, a non-zero exit is a CommandError."""
    try:
        # errors="replace": output that is not UTF-8 is read, never a crash. Nothing here trusts
        # it beyond matching commit hashes, which replacement characters cannot forge.
        done = subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                              timeout=COMMAND_TIMEOUT, check=False)
    except FileNotFoundError as exc:
        raise CommandError(f"{E_COMMAND}: {cmd[0]} could not start ({exc}).") from exc
    except subprocess.TimeoutExpired as exc:
        raise CommandError(f"{E_COMMAND}: {' '.join(cmd)} did not finish within "
                           f"{COMMAND_TIMEOUT} seconds.") from exc
    if check and done.returncode != 0:
        raise CommandError(f"{E_COMMAND}: {' '.join(cmd)} exited {done.returncode}: "
                           f"{done.stderr.strip()[-2000:]}")
    return done.stdout


def _read_json(path, what, code):
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_FILE_BYTES + 1)
    except FileNotFoundError as exc:
        raise UsageError(f"{E_MISSING_FILE}: The {what} {path} does not exist.") from exc
    except OSError as exc:
        raise UsageError(f"{E_READ}: The {what} {path} could not be read ({exc}).") from exc
    if len(data) > MAX_FILE_BYTES:
        raise UsageError(f"{E_FILE_SIZE}: The {what} {path} is larger than {MAX_FILE_BYTES} "
                         "bytes, the most this tool reads.")
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise UsageError(f"{code}: The {what} {path} is not JSON ({exc}).") from exc


def _entry_problem(item, seen):
    if not isinstance(item, dict):
        return "an entry is not an object"
    if set(item) != set(FIELDS):
        return f"an entry's fields are {sorted(item)}, not {sorted(FIELDS)}"
    if not isinstance(item["name"], str) or not NAME.fullmatch(item["name"]):
        return f"the name {item['name']!r} is not lowercase letters, digits, dots and hyphens"
    if item["name"] in seen:
        return f"the name {item['name']} appears twice"
    if not isinstance(item["source"], str) or not SOURCE.fullmatch(item["source"]):
        return f"{item['name']}: the source must be an https://github.com/<owner>/<repo> URL"
    if not isinstance(item["ref"], str) or not REF.fullmatch(item["ref"]):
        return f"{item['name']}: the ref must be a branch, tag or commit name"
    if not isinstance(item["python"], str) or not PYTHON.fullmatch(item["python"]):
        return f"{item['name']}: python must be a version such as 3.14"
    profiles = item["profiles"]
    if not isinstance(profiles, list) or not profiles:
        return f"{item['name']}: profiles must be a non-empty list"
    for profile in profiles:
        if not isinstance(profile, str) or not PROFILE.fullmatch(profile):
            return f"{item['name']}: the profile name {profile!r} is not a profile name"
    return None


def load_refs(path):
    """The validated list of refs to check."""
    data = _read_json(path, "list of keripy refs", E_REFS_FORMAT)
    if not isinstance(data, list) or not data:
        raise UsageError(f"{E_REFS_FORMAT}: The list of keripy refs {path} must be a non-empty "
                         "JSON list.")
    seen = set()
    for item in data:
        problem = _entry_problem(item, seen)
        if problem:
            raise UsageError(f"{E_REFS_FORMAT}: The list of keripy refs {path} is malformed: "
                             f"{problem}.")
        seen.add(item["name"])
    return data


def _state_ok(data):
    if not isinstance(data, dict) or data.get("format") != STATE_FORMAT:
        return False
    entries = data.get("refs")
    return isinstance(entries, dict) and all(
        isinstance(v, dict) and isinstance(v.get("keripy"), str)
        and isinstance(v.get("inputs"), str) and isinstance(v.get("differences"), list)
        for v in entries.values())


def load_state(path):
    """The last run's record per ref. A missing state is empty; an unreadable one is treated as
    empty, which costs a full run and nothing else, and is said on standard error."""
    try:
        data = _read_json(path, "state", W_STATE)
    except UsageError as exc:
        if str(exc).startswith(E_MISSING_FILE):
            return {}
        data = None
        print(f"{W_STATE}: {exc}", file=sys.stderr)
    if not _state_ok(data):
        print(f"{W_STATE}: The state {path} is not one this tool wrote, so every ref is "
              "checked as if new.", file=sys.stderr)
        return {}
    return data["refs"]


def save_state(path, state):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"format": STATE_FORMAT, "refs": state}, indent=2) + "\n",
                    encoding="utf-8")


def resolve(source, ref, run):
    """The commit ref names in source. A tag wins over a branch of the same name, and an
    annotated tag resolves to the commit it points at."""
    if SHA.fullmatch(ref):
        return ref
    listed = {}
    for line in run(["git", "ls-remote", source, ref]).splitlines():
        sha, _, name = line.partition("\t")
        if SHA.fullmatch(sha):
            listed[name] = sha
    for name in (f"refs/tags/{ref}^{{}}", f"refs/tags/{ref}", f"refs/heads/{ref}"):
        if name in listed:
            return listed[name]
    raise CommandError(f"{E_MISSING_REF}: {source} has no branch or tag named {ref}.")


def fingerprint(item):
    """The entry as recorded in the state, so a changed entry (another profile, another Python)
    is checked again even when its commit and the suite's inputs did not move."""
    return json.dumps(item, sort_keys=True)


def differences(base, report, sha):
    """Every way report differs from the baseline summary base, except that it ran another
    keripy commit. The report must also say it ran keripy at sha, or nothing it says counts."""
    found = []
    implementation = report["hello"]["implementation"]
    if implementation.get("name") != "keripy" or implementation.get("commit") != sha:
        found.append(f"implementation: the report names {implementation.get('name')} at "
                     f"{implementation.get('commit')}, not keripy at {sha}")
    regressions, improvements = baseline.compare(base, report)
    return found + regressions + [line for line in improvements if not line.startswith(IDENTITY)]


def check_ref(item, sha, suite, work, run):
    """Install keripy at sha with this adapter and compare each profile with its baseline."""
    suite, work = Path(suite), Path(work)
    venv = work / item["name"]
    python = venv / "bin" / "python"
    adapter = suite / "adapters" / "keripy"
    try:
        work.mkdir(parents=True, exist_ok=True)
        run(["uv", "venv", "-q", "--clear", "-p", item["python"], str(venv)])
        run(["uv", "pip", "install", "-q", "-p", str(python),
             f"keri @ git+{item['source']}@{sha}"])
        # --no-deps: the adapter's own keripy pin must not replace the keripy under test.
        run(["uv", "pip", "install", "-q", "-p", str(python), "--no-deps", str(adapter)])
    except (CommandError, OSError) as exc:
        raise CommandError(f"{E_INSTALL}: {item['name']}: keripy {sha} could not be installed "
                           f"with the adapter: {exc}") from exc
    found = []
    for profile in item["profiles"]:
        report_path = work / f"{item['name']}.{profile}.json"
        try:
            report_path.unlink(missing_ok=True)
        except OSError as exc:
            raise CommandError(f"{E_INSTALL}: {item['name']}: the stale report {report_path} "
                               f"could not be removed: {exc}") from exc
        # kcs run exits non-zero for any verdict but conformant; the report is what is judged.
        run(["uv", "run", "--project", str(suite), "kcs", "run", "--suite", str(suite),
             "--adapter", str(venv / "bin" / "kcs-adapter-keripy"), "--profile", profile,
             "--report", str(report_path)], check=False)
        try:
            base = baseline._baseline(adapter / f"baseline-{profile}.json")
            report = baseline._report(report_path)
        except baseline.InputError as exc:
            raise CommandError(f"{E_INSTALL}: {item['name']}: {profile} produced no usable "
                               f"report: {exc}") from exc
        found += [f"{profile}: {line}" for line in differences(base, report, sha)]
    return found


def check_all(refs, state, inputs, suite, work, run):
    """(exit code, new state, lines to print). Refs that could not be checked keep their old
    state, so they are checked again next time."""
    state = dict(state)
    lines, failed = [], False
    for item in refs:
        name = item["name"]
        try:
            sha = resolve(item["source"], item["ref"], run)
            prior = state.get(name)
            if (prior and prior["keripy"] == sha and prior["inputs"] == inputs
                    and prior.get("config") == fingerprint(item)):
                if prior["differences"]:
                    failed = True
                    lines.append(f"{E_DIFFERS}: {name}: unchanged at {sha} since the last run, "
                                 "which differed from the baselines:")
                    lines += [f"    {d}" for d in prior["differences"]]
                else:
                    lines.append(f"{name}: unchanged at {sha}; matched the baselines last run.")
                continue
            found = check_ref(item, sha, suite, work, run)
        except CommandError as exc:
            failed = True
            lines.append(f"{exc}" if str(exc).startswith(E_INSTALL)
                         else f"{E_INSTALL}: {name}: {exc}")
            continue
        state[name] = {"keripy": sha, "inputs": inputs, "differences": found,
                       "config": fingerprint(item)}
        if found:
            failed = True
            lines.append(f"{E_DIFFERS}: {name} at {sha} differs from the baselines:")
            lines += [f"    {d}" for d in found]
        else:
            lines.append(f"{name}: keripy {sha} matches the baselines of "
                         f"{', '.join(item['profiles'])}.")
    return (1 if failed else 0), state, lines


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m kcs_adapter_keripy.refs")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="check every ref in the list")
    for flag in ("--refs", "--state", "--inputs", "--suite", "--work"):
        run.add_argument(flag, required=True)
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    try:
        refs = load_refs(args.refs)
    except UsageError as exc:
        print(exc, file=sys.stderr)
        return 2
    code, state, lines = check_all(refs, load_state(args.state), args.inputs, args.suite,
                                   args.work, run_command)
    for line in lines:
        print(line)
    try:
        save_state(args.state, state)
    except OSError as exc:
        transient = exc.errno in baseline.TRANSIENT_ERRNOS
        print(f"{E_WRITE_TRANSIENT if transient else E_WRITE}: The state {args.state} could not "
              f"be written ({exc}).", file=sys.stderr)
        return 2
    return code


if __name__ == "__main__":
    raise SystemExit(main())
