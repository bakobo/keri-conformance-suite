"""Shared fixtures. The same tests run in both adapter instances: keripy main (this project's
environment) and keripy 1.2.14 (keripy-1.2.14/'s environment). Tests that only make sense for one
keripy generation are marked and skipped in the other."""

import importlib.metadata
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from kcs_adapter_keripy import keripy_api

GENERATION = keripy_api.load().generation


def pytest_configure(config):
    config.addinivalue_line("markers", "main: needs keripy main (generation 'main')")
    config.addinivalue_line("markers", "onex: needs keripy 1.x (generation '1.x')")


def pytest_collection_modifyitems(config, items):
    for item in items:
        if "main" in item.keywords and GENERATION != "main":
            item.add_marker(pytest.mark.skip(reason="needs keripy main"))
        if "onex" in item.keywords and GENERATION != "1.x":
            item.add_marker(pytest.mark.skip(reason="needs keripy 1.x"))


@pytest.fixture
def api():
    return keripy_api.load()


@pytest.fixture
def keri_dist():
    return importlib.metadata.distribution("keri")


def locate_entry_point(executable, which=shutil.which):
    """The adapter's console script: the one beside the interpreter if it exists, else the one
    found on PATH (resolved). Fails the test explicitly when neither exists."""
    beside = Path(executable).with_name("kcs-adapter-keripy")
    if beside.exists():
        return str(beside)
    found = which("kcs-adapter-keripy")
    if found:
        return str(Path(found).resolve())
    pytest.fail(f"kcs-adapter-keripy is neither beside {executable} nor on PATH; install the "
                "adapter (uv sync) before running these tests.")


@pytest.fixture
def entry_point():
    """The installed console script of this environment."""
    return locate_entry_point(sys.executable)


def run_adapter(entry_point, lines, timeout=60):
    """Start the adapter, send these request lines, close stdin, and return (stdout lines, rc)."""
    proc = subprocess.run([entry_point], input=b"".join(lines), capture_output=True,
                          timeout=timeout, check=False)
    return proc.stdout.splitlines(), proc.returncode, proc.stderr
