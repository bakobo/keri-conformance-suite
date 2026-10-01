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


CLAUSE = {
    "spec": "cesr",
    "section": "Count codes",
    "url": "https://github.com/trustoverip/kswg-cesr-specification/blob/4df80aa/spec/spec.md#count-codes",
    "commit": "4df80aa",
}


def make_case(case_id, operation, case_input, assertions, *, status="active", profile="core-1.0",
              features=(), reference=None):
    """A hand-built case that validates against schema/case.schema.json."""
    case = {
        "schema_version": 1,
        "id": case_id,
        "title": f"Hand-built case {case_id}",
        "description": "Built by the runner's tests.",
        "status": status,
        "profile": profile,
        "targets": {"wire": ["CESR-2.00"], "features": list(features)},
        "operation": operation,
        "input": case_input,
        "assertions": [{"clause": CLAUSE, **a} if a.get("level") != "INTEROP" else a
                       for a in assertions],
        "provenance": {
            "scenario": "tests/hand-built",
            "generator": {"name": "hand", "version": "0"},
            "reference": reference,
        },
    }
    if status == "deprecated":
        case["superseded_by"] = "CESR-9999"
    if status == "disputed":
        case["dispute"] = {"clauses": [CLAUSE], "summary": "Two clauses disagree.",
                           "raised_at": "https://example.org/issue/1"}
    return case


def assertion(check, name="a1", level="MUST", **fields):
    return {"id": name, "check": check, "level": level, **fields}


@pytest.fixture
def cases_dir(tmp_path):
    def build(*cases):
        directory = tmp_path / "cases"
        for case in cases:
            layer = case["id"].split("-")[0].lower()
            path = directory / layer / f"{case['id']}.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(case), encoding="utf-8")
        directory.mkdir(exist_ok=True)
        return directory

    return build
