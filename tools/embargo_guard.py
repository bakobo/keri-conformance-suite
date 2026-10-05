"""Refuse a push whose new commits mention anything on the private embargo list.

Embargoed cases (docs/design.md, Security) live in a private repository, and so does the list of
identifiers and phrases that would disclose them. This guard reads that list and checks the lines a
push adds and the messages of the commits it carries. It is a local safety net for maintainers who
hold the private list; without the list it says so and lets the push through.

It reads each pushed commit on its own and needs git 2.31 or later (--diff-merges).

Exit statuses: 0 nothing found, 1 something on the list was found, 2 the range, the pre-push input
or the list could not be read.
"""

import argparse
import pathlib
import re
import subprocess
import sys

E_EMBARGO = "e.rule.embargo.f"
E_RANGE = "e.input.format.embargo-range.f"
E_HOOK = "e.input.format.embargo-hook-input.f"
E_PATTERNS = "e.input.format.embargo-patterns.f"
W_NO_PATTERNS = "w.rule.embargo.patterns-missing.f"
ZERO = "0" * 40  # SHA-1 only; ~5ail


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


class HookInputError(ValueError):
    """A pre-push input line that is not the four fields git writes."""


def ranges_from_hook(lines, default_base: str) -> list[str]:
    """Commit ranges from git's pre-push input: '<local ref> <local sha> <remote ref> <remote sha>'
    per line. A deleted ref pushes nothing; a new branch is checked against the default base. Any
    other shape is refused rather than skipped, so a damaged input cannot pass unchecked."""
    out = []
    for line in lines:
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) != 4:
            raise HookInputError(line)
        _, local, _, remote = parts
        if local == ZERO:
            continue
        out.append(f"{default_base if remote == ZERO else remote}..{local}")
    return out


def _git_bytes(repo: pathlib.Path, *args) -> bytes:
    # Plain output whatever the user's git configuration says: no colour, no pager, messages in
    # UTF-8, and the objects themselves rather than any replacement refs.
    return subprocess.run(["git", "--no-replace-objects", "-C", str(repo), "-c", "color.ui=false",
                           "-c", "core.pager=cat", "-c", "i18n.logOutputEncoding=utf-8", *args],
                          check=True, capture_output=True).stdout


def _git(repo: pathlib.Path, *args) -> str:
    return _git_bytes(repo, *args).decode("utf-8", errors="replace")


def _readings(raw: bytes) -> tuple[str, str]:
    """Two readings of bytes whose encoding is not known: UTF-8, and Latin-1, which maps every byte,
    so a listed string stored in a legacy encoding is still found."""
    return raw.decode("utf-8", errors="replace"), raw.decode("latin-1")


def _matches(raw: bytes, patterns: list[re.Pattern]) -> bool:
    return any(p.search(text) for text in _readings(raw) for p in patterns)


def _commits(repo: pathlib.Path, rng: str) -> list[str]:
    """The commits a range pushes. For a three-dot range, only those on its right-hand side."""
    side = ["--right-only"] if "..." in rng else []
    return _git(repo, "rev-list", *side, rng).split()


def _added_lines(diff: bytes):
    """(file, raw bytes) for every line a patch adds. A line is split only at a newline, and a
    '+++ ' line is a file header only inside a file's header, never inside a hunk."""
    current, in_header = None, False
    for line in diff.split(b"\n"):
        if line.startswith(b"diff --git "):
            in_header = True
        elif in_header and line.startswith(b"+++ "):
            name = line[6:] if line.startswith(b"+++ b/") else line[4:]
            current = name.decode("utf-8", errors="replace")
        elif line.startswith(b"@@"):
            in_header = False
        elif not in_header and line.startswith(b"+"):
            yield current, line[1:]


def findings(repo: pathlib.Path, rng: str, patterns: list[re.Pattern]) -> list[str]:
    """Where a listed item appears in the commits a range pushes: in a line any one of them adds
    (by file), or in its message. Each commit is read on its own, so text that one commit adds and a
    later one removes is still found: the earlier commit carries it."""
    found = []
    for sha in _commits(repo, rng):  # three git processes per commit; ~2qxn
        if _matches(_git_bytes(repo, "show", "-s", "--format=%B", sha), patterns):
            found.append(f"the commit message of {sha[:12]}")
        # A merge is read against its first parent: what it brings onto the pushed branch. --text
        # shows a file git would call binary, or one a pushed .gitattributes marks -diff.
        diff = _git_bytes(repo, "diff-tree", "-p", "--text", "--diff-merges=first-parent",
                          "--root", "--no-commit-id", "--no-ext-diff", "--no-color",
                          "--no-textconv", "--unified=0", sha)
        for name, raw in _added_lines(diff):
            if _matches(raw, patterns):
                found.append(f"an added line in {name or '(unknown file)'} in {sha[:12]}")
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
    try:
        patterns = load_patterns(path)
    except (OSError, UnicodeDecodeError) as exc:
        print(f"{E_PATTERNS}: The private embargo list at {path} could not be read as UTF-8 text "
              f"({exc}). Repair it before pushing.", file=sys.stderr)
        return 2
    try:
        hook_input = sys.stdin.buffer.read().decode("utf-8", errors="replace") if args.hook else ""
        ranges = ranges_from_hook(hook_input.split("\n"), args.base) if args.hook else [args.rng]
    except HookInputError as exc:
        print(f"{E_HOOK}: git's pre-push input had a line that is not four fields ({exc}), so "
              "the push could not be checked. Push again.", file=sys.stderr)
        return 2
    found = []
    for rng in ranges:
        try:
            found += findings(repo, rng, patterns)
        except subprocess.CalledProcessError as exc:
            reason = exc.stderr.decode("utf-8", errors="replace").strip()
            print(f"{E_RANGE}: The commit range {rng!r} could not be read ({reason}). "
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

