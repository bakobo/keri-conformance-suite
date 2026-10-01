"""Shared helpers: where the fake adapters live and how to build a command that starts one."""

import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
FAKES = ROOT / "tests" / "fakes"


def good(*args):
    return [sys.executable, str(FAKES / "good.py"), *map(str, args)]


def bad(mode, arg=None):
    return [sys.executable, str(FAKES / "bad.py"), mode, *([] if arg is None else [str(arg)])]


@pytest.fixture
def vocabulary():
    from keri_conformance.session import load_vocabulary

    return load_vocabulary(ROOT)


@pytest.fixture
def write_json(tmp_path):
    def write(name, obj):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(obj), encoding="utf-8")
        return path

    return write
