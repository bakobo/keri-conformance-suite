"""The documentation site's markdown source: the README as the home page, docs/ beside it, and pages
generated from the published results.

The site generator (Zensical, pinned in pyproject.toml's site group) reads only the tree this
writes, which is plain markdown, so replacing the generator means replacing one build step. The
tree is assembled rather than pointed at docs/ directly because the home page is the README, which
lives at the repository root, and because the results pages are generated at build time and never
committed. Links are rewritten for the new layout: a link to a file under docs/ points at its new
place, and a link to any other file in the repository points at it on GitHub.

Text taken from a result file is untrusted, so every piece of it passes through `text`, which
turns HTML's special characters into entities and backslash-escapes markdown's, in one pass, and
bounds its length. Everything is sorted, so the same results always give the same bytes.
"""

import argparse
import json
import os
import posixpath
import re
import shutil
import sys
from collections import defaultdict
from pathlib import Path

from keri_conformance.errors import E_USAGE_INVALID, EXIT_FAULT, EXIT_USAGE, RunnerError
from tools.results import (
    E_RESULT_FORMAT,
    E_RESULT_PATH,
    Result,
    load_results,
    result_path,
    result_problem,
)

REPO_URL = "https://github.com/bakobo/keri-conformance-suite"
MARKER = ".kcs-site-source"
RESULTS_DIR = "results"
E_SITE_OUT = "e.state.conflict.site-out.f"
E_SITE_COLLISION = "e.self.config.site-collision.f"

LABELS = {"reproduced": "Reproduced by CI", "submitted": "Submitted claim, not reproduced"}
ADMONITION = {"reproduced": "success", "submitted": "warning"}
KIND_ORDER = {"reproduced": 0, "submitted": 1}
DETAIL_LIMIT = 300

_ENTITIES = {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}
# Python-Markdown's escapable characters, with "|" from its tables extension.
_MARKDOWN = set("\\`*_{}[]()>#+-.!|")
_LINK = re.compile(r"\]\(([^()\s]+)((?:\s+\"[^\"]*\")?)\)")
_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")


def text(value: str, limit: int | None = None) -> str:
    """`value` made inert for a markdown page: control characters become spaces, HTML specials
    become entities, markdown specials are backslash-escaped, and anything past `limit` characters
    is cut and marked with an ellipsis."""
    cut = limit is not None and len(value) > limit
    value = value[:limit] if cut else value
    out = []
    for char in value:
        if char in _ENTITIES:
            out.append(_ENTITIES[char])
        elif char in _MARKDOWN:
            out.append("\\" + char)
        elif ord(char) < 32 or ord(char) == 127:
            out.append(" ")
        else:
            out.append(char)
    return "".join(out) + ("…" if cut else "")


def _rewrite_target(url: str, source: str, target: str) -> str:
    if url.startswith(("#", "/")) or _SCHEME.match(url):
        return url
    path, hash_, fragment = url.partition("#")
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(source), path))
    if resolved.startswith("../") or resolved == "..":
        return url
    if resolved == "README.md":
        new = "index.md"
    elif resolved.startswith("docs/"):
        new = resolved[len("docs/"):]
    else:
        return f"{REPO_URL}/blob/main/{resolved}{hash_}{fragment}"
    start = posixpath.dirname(target) or "."
    return posixpath.relpath(new, start) + hash_ + fragment


def rewrite_links(markdown: str, source: str, target: str) -> str:
    """Rewrite the inline links in `markdown`, a file at repository path `source` that will live
    at `target` in the site source. Fenced code blocks are left as they are."""
    out, fenced = [], False
    for line in markdown.splitlines(keepends=True):
        if line.lstrip().startswith("```"):
            fenced = not fenced
        elif not fenced:
            line = _LINK.sub(lambda m: f"]({_rewrite_target(m.group(1), source, target)}"
                                       f"{m.group(2)})", line)
        out.append(line)
    return "".join(out)


def version_key(version: str):
    """Sorts suite versions numerically; a pre-release suffix sorts before the bare release."""
    match = re.match(r"^([0-9]+(?:\.[0-9]+)*)(.*)$", version)
    numbers = tuple(int(n) for n in match.group(1).split("."))
    return numbers, match.group(2) == "", match.group(2)


def _impl(result: Result) -> dict:
    return result.doc["report"]["hello"]["implementation"]


def _page(result: Result) -> str:
    """The detail page's path, relative to the results directory."""
    kind = result.doc["provenance"]["kind"]
    path = result.path
    return f"{path.parent.as_posix()}/{path.stem}-{kind}.md"


def _sort_key(result: Result):
    impl = _impl(result)
    return (result.path.parts[0], impl["name"], result.path.parts[1],
            KIND_ORDER[result.doc["provenance"]["kind"]], result.path.name)


def _n(value: int) -> str:
    """A number from a result, shown through the same escaping as its text."""
    return text(str(value))


def _tally(report: dict, level: str) -> tuple[str, str]:
    counts = report["summary"]["counts"].get("active", {}).get(level, {})
    return _n(counts.get("pass", 0)), _n(counts.get("fail", 0))


def _cell(report: dict, link: str) -> str:
    must, should = _tally(report, "MUST"), _tally(report, "SHOULD")
    cell = (f"[{text(report['verdict'])}]({link}) · MUST {must[0]} pass, {must[1]} fail · "
            f"SHOULD {should[0]} pass, {should[1]} fail")
    # A non-normative profile's assertions are INTEROP, so its verdict is always no-evidence and
    # these counts are its whole result.
    if "INTEROP" in report["summary"]["counts"].get("active", {}):
        interop = _tally(report, "INTEROP")
        cell += f" · INTEROP {interop[0]} pass, {interop[1]} fail"
    unsupported = len(report["summary"]["not_supported_active"])
    if unsupported:
        cell += f" · {_n(unsupported)} active case{'' if unsupported == 1 else 's'} not supported"
    return cell


def _row_label(result: Result, link: str) -> str:
    impl = _impl(result)
    return (f"[{text(impl['name'], 80)}]({link}) {text(impl['version'], 80)} · "
            f"{LABELS[result.doc['provenance']['kind']]}")


def _self_agreement(report: dict) -> str:
    n = report["summary"]["self_agreement_passes"]
    return "none" if n == 0 else text(f"{n} self-agreement pass{'' if n == 1 else 'es'}")


def _composes(report: dict) -> str:
    return text(", ".join(report["composes"])) if report["composes"] else "nothing"


def _version_tables(results: list[Result], prefix: str) -> list[str]:
    """The matrix and the detail table for results that all ran against one suite version."""
    profiles = sorted({r.doc["report"]["filters"]["profile"] for r in results})
    rows: dict[tuple, dict[str, Result]] = {}
    for result in sorted(results, key=_sort_key):
        key = (result.path.parts[0], result.path.parts[1], result.doc["provenance"]["kind"])
        rows.setdefault(key, {})[result.doc["report"]["filters"]["profile"]] = result
    lines = ["| Implementation | " + " | ".join(text(p) for p in profiles) + " |",
             "|---|" + "---|" * len(profiles)]
    for row in rows.values():
        first = next(iter(row.values()))
        label = _row_label(first, f"{prefix}{first.path.parts[0]}/index.md")
        cells = [_cell(row[p].doc["report"], prefix + _page(row[p])) if p in row else "not run"
                 for p in profiles]
        lines.append(f"| {label} | " + " | ".join(cells) + " |")
    lines += ["", "| Implementation | Profile | Adapter | Composes | Self-agreement | Date |",
              "|---|---|---|---|---|---|"]
    for result in sorted(results, key=_sort_key):
        report = result.doc["report"]
        adapter = report["hello"]["adapter"]
        lines.append(
            f"| {_row_label(result, f'{prefix}{result.path.parts[0]}/index.md')} | "
            f"[{text(report['filters']['profile'])}]({prefix}{_page(result)}) | "
            f"{text(adapter['name'], 80)} {text(adapter['version'], 80)} | "
            f"{_composes(report)} | {_self_agreement(report)} | "
            f"{text(result.doc['provenance']['date'])} |")
    return lines


def _by_suite_version(results: list[Result]) -> list[tuple[str, list[Result]]]:
    groups: dict[str, list[Result]] = defaultdict(list)
    for result in results:
        groups[result.doc["report"]["suite_version"]].append(result)
    return sorted(groups.items(), key=lambda item: version_key(item[0]), reverse=True)


INDEX_INTRO = """# Results

Each result below is a conformance report written by `kcs run --report`, published with a label saying who produced it. A result labelled *Reproduced by CI* was produced by this repository's CI from a pinned adapter and implementation, and the run that produced it is linked from its page. A result labelled *Submitted claim, not reproduced* was sent by an implementation's maintainer through a pull request; the suite checked that the report is well formed and agrees with itself, but it did not run it and cannot vouch for it.

Results are grouped by the suite version they ran against, and no table compares results from different suite versions. A verdict is never the whole claim: each cell also gives the active MUST and SHOULD assertions that passed and failed, because in the KERI layer a validator that accepts nothing passes every MUST. How results are produced and how to submit one is described in [Publishing results](../publishing-results.md).
"""


def _index(results: list[Result]) -> str:
    lines = [INDEX_INTRO]
    if not results:
        lines.append("No results have been published yet.\n")
        return "\n".join(lines)
    for version, group in _by_suite_version(results):
        lines += [f"## Suite version {text(version)}", ""]
        lines += _version_tables(group, "")
        lines.append("")
    return "\n".join(lines)


def _implementation_page(results: list[Result]) -> str:
    # Headings hold only path segments: Zensical 0.0.69 copies a page's first heading into <title>
    # with its entities decoded, so result text in a heading would reach the page unescaped.
    first = min(results, key=_sort_key)
    lines = [f"# {text(first.path.parts[0])}", "",
             f"Implementation name as reported: {text(_impl(first)['name'], 80)}.", "",
             ("Every published result for this implementation, by the suite version it ran "
             "against. The labels are explained on the [results page](../index.md)."), ""]
    for version, group in _by_suite_version(results):
        lines += [f"## Suite version {text(version)}", ""]
        own = f"](../{group[0].path.parts[0]}/"
        lines += [line.replace(own, "](") for line in _version_tables(group, "../")]
        lines.append("")
    return "\n".join(lines)


def _provenance_block(provenance: dict) -> list[str]:
    kind = provenance["kind"]
    lines = [f'!!! {ADMONITION[kind]} "{LABELS[kind]}"', ""]
    if kind == "reproduced":
        lines.append(f"    This repository's CI produced this result in [run]({provenance['run']}) "
                     f"on {text(provenance['date'])}, from suite commit "
                     f"{text(provenance['commit'])}.")
    else:
        lines.append(f"    {text(provenance['submitter'])} submitted this result in "
                     f"[a pull request]({provenance['pull_request']}), for a run on "
                     f"{text(provenance['date'])}. The suite checked that it is well formed and "
                     "agrees with itself, but did not reproduce it.")
    return lines + [""]


def _outcome_counts(report: dict, level: str) -> str:
    counts = report["summary"]["counts"].get("active", {}).get(level, {})
    return ", ".join(f"{_n(n)} {text(k)}" for k, n in sorted(counts.items())) or "none"


def _case_notes(entry: dict) -> str:
    notes = []
    if entry["failure"] is not None:
        notes.append(f"failure: {entry['failure']['kind']}")
    if "missing_operation" in entry:
        notes.append(f"missing operation {entry['missing_operation']}")
    if entry.get("missing_features"):
        notes.append(f"missing {', '.join(entry['missing_features'])}")
    for record in entry["assertions"]:
        detail = None
        if record["outcome"] in ("fail", "not-implemented"):
            detail = record["detail"] or record["outcome"]
        elif record["self_agreement"]:
            detail = "self-agreement"
        if detail is not None:
            notes.append(f"{record['id']} ({record['level']}): {detail[:DETAIL_LIMIT]}")
    return text("; ".join(notes), DETAIL_LIMIT * 4) if notes else ""


def _detail_page(result: Result) -> str:
    doc = result.doc
    report = doc["report"]
    impl, adapter = report["hello"]["implementation"], report["hello"]["adapter"]
    must, should = _tally(report, "MUST"), _tally(report, "SHOULD")
    lines = [(f"# {text(result.path.parts[0])} {text(result.path.parts[1])}, profile "
              f"{text(report['filters']['profile'])}"), ""]
    lines += _provenance_block(doc["provenance"])
    lines += [
        "| | |", "|---|---|",
        f"| Suite version | {text(report['suite_version'])} |",
        f"| Profile | {text(report['filters']['profile'])} |",
        f"| Verdict | {text(report['verdict'])} |",
        (f"| Active MUST assertions | {must[0]} passed, {must[1]} failed "
        f"({_outcome_counts(report, 'MUST')}) |"),
        (f"| Active SHOULD assertions | {should[0]} passed, {should[1]} failed "
        f"({_outcome_counts(report, 'SHOULD')}) |"),
    ]
    if "INTEROP" in report["summary"]["counts"].get("active", {}):
        interop = _tally(report, "INTEROP")
        lines.append(f"| Active INTEROP assertions | {interop[0]} passed, {interop[1]} failed "
                     f"({_outcome_counts(report, 'INTEROP')}) |")
    lines += [
        (f"| Implementation | {text(impl['name'], 80)} {text(impl['version'], 80)}, commit "
        f"{text(impl['commit'])} |"),
        f"| Adapter | {text(adapter['name'], 80)} {text(adapter['version'], 80)} |",
        f"| Composes | {_composes(report)} |",
        f"| Self-agreement | {_self_agreement(report)} |",
        (f"| Runner | {text(report['runner_version'])}, adapter protocol "
        f"{_n(report['negotiated_protocol'])} |"),
        "| Active cases not supported | "
        + (text(", ".join(report["summary"]["not_supported_active"]))
           if report["summary"]["not_supported_active"] else "none") + " |",
    ]
    if report["aborted"] is not None:
        lines.append(f"| Aborted | {text(report['aborted']['reason'], DETAIL_LIMIT)} |")
    stem = Path(_page(result)).stem
    lines += ["", (f"Every case, with its outcome, is below, and [the full report \\(JSON\\)]"
                  f"({stem}.json) has every assertion's expected and actual values."), "",
              "## Cases", "", "| Case | Status | Operation | Outcome | Notes |",
              "|---|---|---|---|---|"]
    for entry in sorted(report["cases"], key=lambda e: e["id"]):
        lines.append(f"| {text(entry['id'])} | {text(entry['status'])} | "
                     f"{text(entry['operation'], 80)} | {text(entry['outcome'])} | "
                     f"{_case_notes(entry)} |")
    return "\n".join(lines) + "\n"


def render_results(results: list[Result]) -> dict[str, str]:
    """Every results page, keyed by its path in the site source, with each result's file beside
    its page so a reader can check the page against it. Every result must have come through
    load_results; each is checked again here, so the links built from its provenance and its path
    rest on the patterns that door enforces rather than on the caller."""
    for result in results:
        problem = result_problem(result.doc)
        if problem:
            raise RunnerError(E_RESULT_FORMAT, f"The result for {result.path.as_posix()[:200]} "
                                               f"cannot be published: {problem}.")
        if result.path != result_path(result.doc):
            raise RunnerError(E_RESULT_PATH, f"The result at {result.path.as_posix()[:200]} "
                                             "is not at the path its report implies.")
    pages = {f"{RESULTS_DIR}/index.md": _index(results)}
    by_impl: dict[str, list[Result]] = defaultdict(list)
    for result in results:
        by_impl[result.path.parts[0]].append(result)
        page = _page(result)
        pages[f"{RESULTS_DIR}/{page}"] = _detail_page(result)
        pages[f"{RESULTS_DIR}/{page[:-3]}.json"] = json.dumps(
            result.doc, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    for impl, group in by_impl.items():
        pages[f"{RESULTS_DIR}/{impl}/index.md"] = _implementation_page(group)
    return dict(sorted(pages.items()))


def assemble(repo, out, results: list[Result]) -> None:
    """Write the site source for the repository at `repo` into `out`, replacing what a previous
    run wrote there. A directory this did not make is refused, never emptied."""
    repo, out = Path(repo), Path(out)
    if out.exists():
        if not (out / MARKER).exists():
            raise RunnerError(E_SITE_OUT, f"The output directory {out} exists and was not made "
                                          "by this tool, so it is left alone. Choose another "
                                          "directory or remove it.")
        shutil.rmtree(out)
    docs = repo / "docs"
    if (docs / RESULTS_DIR).exists():
        raise RunnerError(E_SITE_COLLISION, f"{docs / RESULTS_DIR} exists, but the site's "
                                            f"{RESULTS_DIR}/ pages are generated; move it.")
    out.mkdir(parents=True)
    (out / MARKER).write_text("Written by tools/site_source.py; safe to delete.\n")
    for path in sorted(docs.rglob("*")):
        if path.is_dir():
            continue
        relative = path.relative_to(docs).as_posix()
        target = out / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if path.suffix == ".md":
            target.write_text(rewrite_links(path.read_text(encoding="utf-8"),
                                            f"docs/{relative}", relative), encoding="utf-8")
        else:
            shutil.copyfile(path, target)
    readme = (repo / "README.md").read_text(encoding="utf-8")
    (out / "index.md").write_text(rewrite_links(readme, "README.md", "index.md"),
                                  encoding="utf-8")
    for relative, content in render_results(results).items():
        target = out / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")


class _UsageError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise _UsageError(message)


def main(argv: list[str] | None = None) -> int:
    repo_default = Path(__file__).resolve().parent.parent
    parser = _Parser(prog="scripts/site-source",
                     description="Assemble the documentation site's markdown source.")
    parser.add_argument("--repo", default=str(repo_default), help="the repository root")
    parser.add_argument("--out", default=None, help="where to write (default: REPO/_site/src)")
    parser.add_argument("--results", default=None,
                        help="the submitted results (default: REPO/results)")
    parser.add_argument("--reproduced", default=None,
                        help="results this run's CI reproduced, written by scripts/results wrap "
                             "--reproduced (default: none)")
    try:
        args = parser.parse_args(argv)
    except _UsageError as exc:
        print(f"{E_USAGE_INVALID}: The command line could not be understood ({exc}). Retrying "
              "the same command will not help; correct the arguments.", file=sys.stderr)
        return EXIT_USAGE
    repo = Path(args.repo)
    out = Path(args.out) if args.out else repo / "_site" / "src"
    try:
        results = load_results(args.results or repo / "results", kinds=("submitted",))
        if args.reproduced:
            results += load_results(args.reproduced, kinds=("reproduced",))
        assemble(repo, out, results)
    except RunnerError as err:
        print(f"scripts/site-source: {err}", file=sys.stderr)
        return EXIT_FAULT
    print(f"wrote the site source for {len(results)} result{'' if len(results) == 1 else 's'} "
          f"to {os.fspath(out)}")
    return 0
