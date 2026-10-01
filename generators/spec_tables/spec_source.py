"""Access to the pinned CESR specification text: its headings, their GitHub anchors, its tables,
and verbatim quotes.

The text is not part of this repository. Its licence (OWFa 1.0) differs from the suite's, so it is
fetched from the specification repository at the pinned commit into a local cache, by default
``~/.cache/kcs/specs/`` and otherwise the directory named by the environment variable
``KCS_SPEC_CACHE``. A cached or fetched file is used only if its SHA-256 is the one pinned here;
any other file is refused, never repaired or trusted.
"""

import hashlib
import os
import pathlib
import re
import urllib.error
import urllib.request
from dataclasses import dataclass

SPEC_REPO = "https://github.com/trustoverip/kswg-cesr-specification"
SPEC_TAG = "v1.0"
SPEC_COMMIT = "037129608b9e6960858b752019ac273d40d7386c"
SPEC_FILE = "spec/spec-body.md"
SPEC_SHA256 = "984ce5f08ce6bce81f102143e75389026afe5a425485bf118f0448c3c59a0610"
SPEC_RAW_URL = (
    "https://raw.githubusercontent.com/trustoverip/kswg-cesr-specification/"
    f"{SPEC_COMMIT}/{SPEC_FILE}"
)
CACHE_ENV = "KCS_SPEC_CACHE"
FETCH_TIMEOUT_SECONDS = 30
MAX_SPEC_BYTES = 4 * 1024 * 1024

# Error codes, per Bakobo's error-code standard: the obstacle, then whether retrying could help.
E_FETCH = "e.env.kcs-spec.fetch.r"
E_DIGEST = "e.proof.kcs-spec.digest.f"
E_OVERSIZE = "e.env.kcs-spec.oversize.f"

_HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")


@dataclass(frozen=True)
class Heading:
    line: int  # 1-based line number in the spec file
    level: int
    text: str  # as written, including any backticks
    anchor: str  # GitHub's anchor for it, disambiguated like GitHub does


class SpecUnavailable(Exception):
    """The pinned specification text could not be obtained or did not match its pinned hash."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code


def cache_dir() -> pathlib.Path:
    configured = os.environ.get(CACHE_ENV)
    if configured:
        return pathlib.Path(configured)
    return pathlib.Path.home() / ".cache" / "kcs" / "specs"


def cache_path() -> pathlib.Path:
    return cache_dir() / f"cesr-spec-body-{SPEC_COMMIT}.md"


def _verified(data: bytes, origin: str) -> bytes:
    digest = hashlib.sha256(data).hexdigest()
    if digest != SPEC_SHA256:
        raise SpecUnavailable(
            E_DIGEST,
            f"The CESR specification text from {origin} has SHA-256 {digest}, not the pinned "
            f"{SPEC_SHA256}. It was not used. Delete it if it is a stale or damaged cache "
            f"file; if it came from the network, the pinned commit's file has changed.",
        )
    return data


def fetch() -> bytes:
    """Download the pinned text, verify it, and store it in the cache."""
    try:
        with urllib.request.urlopen(SPEC_RAW_URL, timeout=FETCH_TIMEOUT_SECONDS) as response:
            data = response.read(MAX_SPEC_BYTES + 1)
    except (urllib.error.URLError, OSError) as e:
        raise SpecUnavailable(
            E_FETCH,
            f"The CESR specification text could not be fetched from {SPEC_RAW_URL} ({e}). "
            f"Retry when the network is available, or place the file at {cache_path()}.",
        ) from None
    if len(data) > MAX_SPEC_BYTES:
        raise SpecUnavailable(E_OVERSIZE, f"The response from {SPEC_RAW_URL} is larger than "
                                        f"{MAX_SPEC_BYTES} bytes and was not used.")
    _verified(data, SPEC_RAW_URL)
    path = cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes(data)
    tmp.replace(path)
    return data


def load_spec(allow_fetch: bool = True) -> str:
    """The pinned specification text, from the cache, fetching it first if the cache is empty
    and ``allow_fetch`` is true. Raises ``SpecUnavailable`` rather than return anything else."""
    path = cache_path()
    if path.exists():
        data = _verified(path.read_bytes(), str(path))
    elif allow_fetch:
        data = fetch()
    else:
        raise SpecUnavailable(E_FETCH, f"The CESR specification text is not cached at {path}.")
    return data.decode("utf-8")


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def slugify(heading: str) -> str:
    """GitHub's heading anchor: lowercase, drop everything but word characters, hyphens and
    spaces, then turn spaces into hyphens."""
    return re.sub(r"[^\w\- ]", "", heading.lower()).replace(" ", "-")


def headings(text: str) -> list[Heading]:
    seen: dict[str, int] = {}
    out = []
    fenced = False
    for number, line in enumerate(text.splitlines(), start=1):
        if line.startswith("```"):
            fenced = not fenced
            continue
        m = None if fenced else _HEADING.match(line)
        if not m:
            continue
        slug = slugify(m.group(2))
        count = seen.get(slug, 0)
        seen[slug] = count + 1
        anchor = slug if count == 0 else f"{slug}-{count}"
        out.append(Heading(number, len(m.group(1)), m.group(2), anchor))
    return out


def find_quote(text: str, quote: str) -> int:
    """The 1-based line on which ``quote`` appears verbatim. It must appear exactly once."""
    lines = [n for n, line in enumerate(text.splitlines(), start=1) if quote in line]
    if not lines:
        raise LookupError(f"Quote not found verbatim in the specification: {quote!r}")
    if len(lines) > 1:
        raise LookupError(f"Quote appears more than once (lines {lines}): {quote!r}")
    return lines[0]


def section_of_line(text: str, line: int) -> Heading:
    """The nearest heading at or before ``line``."""
    before = [h for h in headings(text) if h.line <= line]
    if not before:
        raise LookupError(f"Line {line} has no heading before it.")
    return before[-1]


def file_url(anchor: str) -> str:
    return f"{SPEC_REPO}/blob/{SPEC_COMMIT}/{SPEC_FILE}#{anchor}"


def table_after(text: str, heading_text: str) -> list[list[str]]:
    """The body rows of the first markdown table under the heading whose text is
    ``heading_text``, with backticks stripped and cells trimmed. The header and separator rows
    are dropped; the table ends at the first line that is not a table row."""
    lines = text.splitlines()
    starts = [h.line for h in headings(text) if h.text == heading_text]
    if not starts:
        raise LookupError(f"There is no heading {heading_text!r} in the specification.")
    rows = []
    in_table = False
    for line in lines[starts[0]:]:
        if line.startswith("|"):
            in_table = True
            rows.append([c.strip().replace("`", "").strip() for c in line.strip().strip("|").split("|")])
        elif in_table or _HEADING.match(line):
            break
    if not rows:
        raise LookupError(f"There is no table under the heading {heading_text!r}.")
    return rows[2:]
