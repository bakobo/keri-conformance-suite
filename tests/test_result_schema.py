"""schema/result.schema.json and the hand-written mirror in tools/results.py accept the same things.

The mutation corpus is generated from rich valid documents: every field is removed, replaced with a
value of each JSON type, and joined by an unexpected sibling. Each mutant must get the same answer
from the schema and from the mirror, and the corpus must contain both answers.
"""

import copy
import json
import re

import pytest
from conftest import ROOT
from jsonschema import Draft202012Validator as _Draft202012
from jsonschema import ValidationError, validators
from result_docs import REPRODUCED, SUBMITTED, case, record, report, result

from tools.results import shape_problem


def _ecma_pattern(validator, pattern, instance, schema):
    # As in test_schema_agreement.py: "$" matches only at the true end of the string.
    if not validator.is_type(instance, "string"):
        return
    found = re.search(pattern, instance)
    if found is None or (pattern.endswith("$") and found.end() != len(instance)):
        yield ValidationError(f"{instance!r} does not match {pattern!r}")


Validator = validators.extend(_Draft202012, {"pattern": _ecma_pattern})
SCHEMA = json.loads((ROOT / "schema" / "result.schema.json").read_text(encoding="utf-8"))
VALIDATOR = Validator(SCHEMA)


def _rich():
    failed = case("CESR-0002", outcome="fail",
                  records=[record("a1", outcome="fail", detail="it accepted"),
                           record("a2", level="SHOULD", self_agreement=True)])
    failed["failure"] = {"kind": "timeout", "detail": "no answer"}
    unsupported = case("CESR-0003", outcome="not-supported",
                       records=[record(outcome="not-supported")])
    unsupported["missing_features"] = ["cesr.native"]
    unsupported["missing_operation"] = "cesr.encode"
    aborted = {"code": "e.x.f", "reason": "stopped", "problems": ["p"], "at_case": "CESR-0003",
               "exit_code": 3}
    return [result(report([case(), failed, unsupported], composes=["keri.escrow"]), SUBMITTED),
            result(report(aborted=aborted), REPRODUCED)]


SAMPLES = [1, 1.5, "x", "", None, True, [], {}, ["x"], {"x": 1}]


def _paths(value, path=()):
    yield path
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _paths(item, (*path, key))
    elif isinstance(value, list):
        for n, item in enumerate(value):
            yield from _paths(item, (*path, n))


def _set(doc, path, value):
    target = doc
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value


def _mutants():
    for doc in _rich():
        yield doc
        for path in _paths(doc):
            if not path:
                continue
            for sample in SAMPLES:
                mutant = copy.deepcopy(doc)
                _set(mutant, path, copy.deepcopy(sample))
                yield mutant
            parent = copy.deepcopy(doc)
            target = parent
            for key in path[:-1]:
                target = target[key]
            if isinstance(target, dict):
                del target[path[-1]]
                yield parent
                extra = copy.deepcopy(doc)
                holder = extra
                for key in path[:-1]:
                    holder = holder[key]
                holder["unexpected"] = 1
                yield extra
    for text in ["2026-02-30", "2026-13-01", "26-10-09", "2026-10-09\n", "2026-10-9"]:
        mutant = _rich()[0]
        mutant["provenance"]["date"] = text
        yield mutant
    for text in ["x" * 256, "x" * 257, "é" * 256]:
        mutant = _rich()[0]
        mutant["report"]["hello"]["implementation"]["name"] = text
        yield mutant
    for text in ["1.0", "0.0.1", "1.2.3.4.5", "1.0rc1", "v1", "1", "1.0\n", "1.0 beta"]:
        mutant = _rich()[0]
        mutant["report"]["suite_version"] = text
        yield mutant
    for url in ["https://github.com/a/b/pull/1", "http://github.com/a/b/pull/1",
                "https://github.com/a/b/pull/1/files", "https://example.com/a/b/pull/1",
                "https://github.com/a/b/pull/x"]:
        mutant = _rich()[0]
        mutant["provenance"]["pull_request"] = url
        yield mutant
    for url in ["https://github.com/a/b/actions/runs/1/attempts/2",
                "https://github.com/a/b/actions/runs/1/job/2", "https://github.com/a/b/runs/1"]:
        mutant = _rich()[1]
        mutant["provenance"]["run"] = url
        yield mutant
    for profile in ["cesr-1.0", "Cesr", "-x", "x" * 64, "x" * 65, "keripy-1x-interop", "a/b"]:
        mutant = _rich()[0]
        mutant["report"]["filters"]["profile"] = profile
        yield mutant


MUTANTS = list(_mutants())


@pytest.mark.parametrize("n", range(len(MUTANTS)))
def test_the_mirror_agrees_with_the_schema(n):
    doc = MUTANTS[n]
    assert VALIDATOR.is_valid(doc) == (shape_problem(doc) is None), json.dumps(doc)[:400]


def test_the_corpus_has_both_answers():
    answers = {shape_problem(doc) is None for doc in MUTANTS}
    assert answers == {True, False}


def test_the_schema_is_a_valid_schema():
    _Draft202012.check_schema(SCHEMA)
