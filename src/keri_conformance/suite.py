"""The version of the suite checkout the runner reads its cases from.

A conformance report states the suite version, which names the cases, and the runner version,
which names the code that ran them; they differ whenever an installed runner is pointed at another
checkout with --suite. The suite version is `[project].version` in the suite root's pyproject.toml.
"""

import tomllib
from pathlib import Path

from keri_conformance.errors import E_SUITE_VERSION, RunnerError

MAX_PYPROJECT_BYTES = 1024 * 1024


def read_suite_version(suite, max_bytes: int = MAX_PYPROJECT_BYTES) -> str:
    """`[project].version` from `<suite>/pyproject.toml`, or a coded refusal."""
    path = Path(suite) / "pyproject.toml"

    def refuse(why: str) -> RunnerError:
        return RunnerError(E_SUITE_VERSION, f"The suite version could not be read from {path}: "
                                            f"{why}. A conformance report must name the suite "
                                            "version, so pass --suite with the root of a suite "
                                            "checkout.")

    try:
        with path.open("rb") as f:
            data = f.read(max_bytes + 1)
    except OSError as exc:
        raise refuse(exc.strerror or str(exc)) from exc
    if len(data) > max_bytes:
        raise refuse(f"the file is larger than {max_bytes} bytes")
    try:
        doc = tomllib.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise refuse(f"the file is not UTF-8 TOML ({exc})") from exc
    project = doc.get("project")
    version = project.get("version") if isinstance(project, dict) else None
    if not isinstance(version, str) or not version:
        raise refuse("it has no [project] table with a non-empty string version")
    return version
