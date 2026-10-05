"""Refuse a push whose new commits mention anything on the private embargo list.

Embargoed cases (docs/design.md, Security) live in a private repository, and so does the list of
identifiers and phrases that would disclose them. This guard reads that list and checks the lines a
push adds and the messages of the commits it carries. It is a local safety net for maintainers who
hold the private list; without the list it says so and lets the push through.

Exit statuses: 0 nothing found, 1 something on the list was found, 2 the range could not be read.
"""

import argparse
import pathlib
import re
import subprocess
import sys

E_EMBARGO = "e.rule.embargo.f"
E_RANGE = "e.input.format.embargo-range.f"
W_NO_PATTERNS = "w.rule.embargo.patterns-missing.f"
ZERO = "0" * 40


def default_patterns(repo: pathlib.Path) -> pathlib.Path:
    """The list's home in the standard Bakobo checkout layout: the private reviews repo beside the
    main checkout, found through git's common directory so a worktree resolves to the same place."""
    common = pathlib.Path(_git(repo, "rev-parse", "--path-format=absolute",
                               "--git-common-dir").strip())
    main_checkout = common.parent
    return main_checkout.parent / "reviews" / main_checkout.name / "embargoed" / "patterns.txt"


def load_patterns(path: pathlib.Path) -> list[re.Pattern]:
    lines = path.read_text(encoding="utf-8").splitlines()
    return [re.compile(re.escape(line.strip()), re.IGNORECASE)
            for line in lines if line.strip() and not line.lstrip().startswith("#")]


def ranges_from_hook(lines, default_base: str) -> list[str]:
    """Commit ranges from git's pre-push input: '<local ref> <local sha> <remote ref> <remote sha>'
    per line. A deleted ref pushes nothing; a new branch is checked against the default base."""
    out = []
    for line in lines:
        parts = line.split()
        if len(parts) != 4:
            continue
        _, local, _, remote = parts
        if local == ZERO:
            continue
        out.append(f"{default_base if remote == ZERO else remote}..{local}")
    return out


def _git(repo: pathlib.Path, *args) -> str:
    # Plain, machine-readable output whatever the user's git configuration says.
    return subprocess.run(["git", "-C", str(repo), "-c", "color.ui=false", "-c", "core.pager=cat",
                           *args], check=True, capture_output=True, text=True).stdout


def findings(repo: pathlib.Path, rng: str, patterns: list[re.Pattern]) -> list[str]:
    """Where a listed item appears in the range: an added line (by file) or a commit message."""
    found = []
    messages = _git(repo, "log", "--format=%H%x00%B%x01", rng)
    for record in filter(None, (r.strip() for r in messages.split("\x01"))):
        sha, _, body = record.partition("\x00")
        if any(p.search(body) for p in patterns):
            found.append(f"the commit message of {sha[:12]}")
    current = None
    diff_range = rng if "..." in rng else rng.replace("..", "...", 1)  # changes since the base
    for line in _git(repo, "diff", "--no-ext-diff", "--no-color", "--no-textconv", "--unified=0",
                     diff_range).splitlines():
        if line.startswith("+++ "):
            current = line[6:] if line.startswith("+++ b/") else line[4:]
        elif line.startswith("+") and any(p.search(line[1:]) for p in patterns):
            found.append(f"an added line in {current or '(unknown file)'}")
    return found


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", type=pathlib.Path, default=pathlib.Path.cwd())
    parser.add_argument("--patterns", type=pathlib.Path, default=None)
    which = parser.add_mutually_exclusive_group(required=True)
    which.add_argument("--range", dest="rng", help="a range such as main..HEAD or main...HEAD")
    which.add_argument("--hook", action="store_true", help="read ranges from pre-push input")
    parser.add_argument("--base", default="origin/main", help="base for a newly pushed branch")
    args = parser.parse_args(argv)
    repo = args.repo.resolve()
    try:
        path = args.patterns or default_patterns(repo)
    except (subprocess.CalledProcessError, OSError):
        path = None
    if path is None or not path.is_file():
        where = f"at {path}" if path is not None else "(not a git checkout in the usual layout)"
        print(f"{W_NO_PATTERNS}: The private embargo list was not found {where}, so this "
              "push was not checked against it.", file=sys.stderr)
        return 0
    patterns = load_patterns(path)
    ranges = ranges_from_hook(sys.stdin.read().splitlines(), args.base) if args.hook else [args.rng]
    found = []
    for rng in ranges:
        try:
            found += findings(repo, rng, patterns)
        except subprocess.CalledProcessError as exc:
            print(f"{E_RANGE}: The commit range {rng!r} could not be read ({exc.stderr.strip()}). "
                  "Fetch the remote and try again.", file=sys.stderr)
            return 2
    if found:
        places = "; ".join(found)
        print(f"{E_EMBARGO}: This push mentions something on the private embargo list, in "
              f"{places}. Remove it from the files and rewrite the commit messages before "
              "pushing; do not push embargoed details to this public repository.",
              file=sys.stderr)
        return 1
    return 0

