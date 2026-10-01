"""Loading cases from disk, with the light structural checks the runner needs at runtime.

The full contract is `schema/case.schema.json`, which CI enforces on every case in this repository.
The runner has no runtime dependencies, so it cannot run that schema; instead it checks every field
it reads, so that a malformed case is a runner fault naming its file rather than a crash or, worse,
an adapter failure.
"""

import json
import re
from pathlib import Path

from keri_conformance.assertions import KEY_STATE_FIELDS
from keri_conformance.errors import E_CASE_FORMAT, E_CASES_MISSING, RunnerError
from keri_conformance.session import OPERATIONS

MAX_CASE_BYTES = 32 * 1024 * 1024
CASE_ID = re.compile(r"(CESR|KERI|ACDC|IPEX)-[0-9]{4}")
STATUSES = ("active", "draft", "disputed", "deprecated")
LEVELS = ("MUST", "SHOULD", "MAY", "INTEROP")
PHASES = ("initial", "final")
REQUIRED = ("schema_version", "id", "title", "description", "status", "profile", "targets",
            "operation", "input", "assertions", "provenance")
CHECK_FIELDS = {
    "decoded": ("expected",),
    "rejected": (),
    "encoded": ("expected",),
    "disposition": ("message", "phase", "expected"),
    "key_state": ("aid", "expected"),
    "emitted_body": ("expected",),
    "signatures_verify": (),
    "attachments_equivalent": ("expected",),
}


def _strings(value) -> bool:
    return isinstance(value, list) and all(isinstance(v, str) for v in value)


def _reference_ok(reference) -> bool:
    return reference is None or (isinstance(reference, dict)
                                 and isinstance(reference.get("implementation"), str))


CASE_RULES = (
    (lambda c: c["schema_version"] == 1 and type(c["schema_version"]) is int,
     '"schema_version" must be 1'),
    (lambda c: isinstance(c["id"], str) and CASE_ID.fullmatch(c["id"]),
     '"id" must look like CESR-0001'),
    (lambda c: c["status"] in STATUSES, f'"status" must be one of {", ".join(STATUSES)}'),
    (lambda c: isinstance(c["profile"], str), '"profile" must be a string'),
    (lambda c: isinstance(c["targets"], dict) and _strings(c["targets"].get("features")),
     '"targets.features" must be a list of strings'),
    (lambda c: c["operation"] in OPERATIONS, f'"operation" must be one of {", ".join(OPERATIONS)}'),
    (lambda c: isinstance(c["input"], dict) and not {"id", "op"} & set(c["input"]),
     '"input" must be an object that does not carry "id" or "op"'),
    (lambda c: isinstance(c["assertions"], list) and c["assertions"],
     '"assertions" must be a non-empty list'),
    (lambda c: isinstance(c["provenance"], dict)
     and _reference_ok(c["provenance"].get("reference")),
     '"provenance.reference" must be null or an object with a string "implementation"'),
)

ASSERTION_RULES = (
    (lambda a: isinstance(a.get("id"), str), '"id" must be a string'),
    (lambda a: a.get("check") in tuple(CHECK_FIELDS),
     f'"check" must be one of {", ".join(CHECK_FIELDS)}'),
    (lambda a: a.get("level") in LEVELS, f'"level" must be one of {", ".join(LEVELS)}'),
    (lambda a: all(f in a for f in CHECK_FIELDS[a["check"]]),
     "it lacks a field its check requires"),
    (lambda a: a["check"] != "disposition"
     or (type(a["message"]) is int and a["message"] >= 0 and a["phase"] in PHASES),
     'a disposition needs a non-negative integer "message" and a "phase" of initial or final'),
    (lambda a: a["check"] != "key_state"
     or (isinstance(a["aid"], str) and isinstance(a["expected"], dict)
         and all(f in a["expected"] for f in KEY_STATE_FIELDS)),
     f'a key_state needs a string "aid" and an "expected" with {", ".join(KEY_STATE_FIELDS)}'),
)


def case_problem(case) -> str | None:
    """None if the runner can read this case, else a sentence saying what is wrong."""
    if not isinstance(case, dict):
        return "It is not a JSON object."
    missing = [key for key in REQUIRED if key not in case]
    if missing:
        return f'It lacks the required field "{missing[0]}".'
    for rule, message in CASE_RULES:
        if not rule(case):
            return f"Its {message}."
    seen = set()
    for n, assertion in enumerate(case["assertions"]):
        if not isinstance(assertion, dict):
            return f"Its assertion {n} is not an object."
        for rule, message in ASSERTION_RULES:
            if not rule(assertion):
                return f"In its assertion {n}, {message}."
        if assertion["id"] in seen:
            return f'Its assertion id "{assertion["id"]}" is used twice.'
        seen.add(assertion["id"])
    return None


def _read(path: Path, max_bytes: int):
    with path.open("rb") as f:
        data = f.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise RunnerError(E_CASE_FORMAT, f"The case file {path} is larger than the {max_bytes} "
                                         "bytes the runner will read.")
    try:
        return json.loads(data.decode("utf-8"))
    except (ValueError, RecursionError) as exc:
        raise RunnerError(E_CASE_FORMAT,
                          f"The case file {path} is not UTF-8 JSON: {exc}.") from exc


def load_cases(directory, max_bytes: int = MAX_CASE_BYTES) -> list[dict]:
    """Every case under `directory`, recursively, sorted by id."""
    directory = Path(directory)
    if not directory.is_dir():
        raise RunnerError(E_CASES_MISSING, f"The cases directory {directory} does not exist; pass "
                                           "--cases, or --suite with the root of a suite checkout.")
    cases, origin = [], {}
    for path in sorted(directory.rglob("*.json")):
        case = _read(path, max_bytes)
        problem = case_problem(case)
        if problem:
            raise RunnerError(E_CASE_FORMAT, f"The case file {path} is malformed. {problem}")
        if case["id"] in origin:
            raise RunnerError(E_CASE_FORMAT, f"The case files {origin[case['id']]} and {path} both "
                                             f"have the id {case['id']}.")
        origin[case["id"]] = path
        cases.append(case)
    return sorted(cases, key=lambda c: c["id"])
