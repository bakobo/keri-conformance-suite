"""Loading cases from disk, checked against a hand-written mirror of the case schema.

The contract is `schema/case.schema.json`. The runner has no runtime dependencies, so it cannot
run that schema; CASE below mirrors it with the combinators in shapes.py, and
tests/test_schema_agreement.py proves the two agree. A schema-invalid case is therefore a runner
fault naming its file, never a case that gets scored.
"""

from pathlib import Path

from keri_conformance.contracts import HEX_STRING, ITEM, KEY_STATE
from keri_conformance.errors import (
    E_CASE_FORMAT,
    E_CASE_READ,
    E_CASE_READ_TRANSIENT,
    E_CASES_MISSING,
    RunnerError,
)
from keri_conformance.jsonfile import JsonFileError, read_json
from keri_conformance.session import OPERATIONS
from keri_conformance.shapes import (
    Check,
    anything_object,
    array,
    enum,
    integer,
    mapping,
    nullable,
    obj,
    string,
    tagged,
)

MAX_CASE_BYTES = 32 * 1024 * 1024
CASE_ID = "^(CESR|KERI|ACDC|IPEX)-[0-9]{4}$"
COMMIT = "^[0-9a-f]{7,40}$"
FEATURE = r"^[a-z0-9]+(\.[a-z0-9-]+)+$"
STATUSES = ("active", "draft", "disputed", "deprecated")
NORMATIVE = ("MUST", "SHOULD", "MAY")
LEVELS = (*NORMATIVE, "INTEROP")
EXPECTED_DISPOSITIONS = ("accepted", "not-accepted", "pending", "rejected", "duplicitous",
                         "superseded")

CLAUSE = obj({"spec": enum("cesr", "keri", "acdc", "ipex"), "section": string(min_length=1),
              "url": string("^https://"), "commit": string(COMMIT)},
             {"quote": string()})


def _assertion(check: str, **fields) -> Check:
    return obj({"id": string("^a[0-9]+$"), "check": enum(check), "level": enum(*LEVELS),
                **fields},
               {"clause": CLAUSE, "basis": string(min_length=1), "note": string()})


CHECK_FORMS = {
    "decoded": _assertion("decoded", expected=array(ITEM)),
    "rejected": _assertion("rejected"),
    "encoded": _assertion("encoded", expected=HEX_STRING),
    "disposition": _assertion("disposition", message=integer(minimum=0),
                              phase=enum("initial", "final"),
                              expected=enum(*EXPECTED_DISPOSITIONS)),
    "key_state": _assertion("key_state", aid=string(), expected=KEY_STATE),
    "emitted_body": _assertion("emitted_body", expected=HEX_STRING),
    "signatures_verify": _assertion("signatures_verify"),
    "attachments_equivalent": _assertion("attachments_equivalent",
                                         expected=array(anything_object)),
}

INPUTS = {
    "cesr.parse": obj({"stream": HEX_STRING}),
    "cesr.encode": obj({"code": string(), "raw": HEX_STRING, "domain": enum("text", "binary")}),
    "keri.process": obj({
        "perspective": obj({"role": enum("validator")}),
        "messages": array(obj({"stream": HEX_STRING, "source": string()}), min_items=1),
    }),
    "keri.emit": obj({"event": anything_object, "seeds": mapping(HEX_STRING)}),
}

CASE = obj(
    {
        "schema_version": enum(1),
        "id": string(CASE_ID),
        "title": string(min_length=1),
        "description": string(min_length=1),
        "status": enum(*STATUSES),
        "profile": string("^[a-z0-9][a-z0-9.-]*$"),
        "targets": obj({"wire": array(string(), min_items=1),
                        "features": array(string(FEATURE))}),
        "operation": enum(*OPERATIONS),
        "input": anything_object,
        "assertions": array(tagged("check", CHECK_FORMS), min_items=1),
        "provenance": obj({
            "scenario": string(),
            "generator": obj({"name": string(), "version": string()}),
            "reference": nullable(obj({"implementation": string(),
                                       "commit": string(COMMIT)})),
        }),
    },
    {
        "dispute": obj({"clauses": array(CLAUSE, min_items=1), "summary": string(min_length=1),
                        "raised_at": string()}),
        "superseded_by": string(CASE_ID),
    },
)


def _cross_field_problem(case: dict) -> str | None:
    """The schema's if/then rules, which tie one field's value to another's presence."""
    problem = INPUTS[case["operation"]](case["input"], "input")
    if problem:
        return problem
    for status, field in (("disputed", "dispute"), ("deprecated", "superseded_by")):
        if case["status"] == status and field not in case:
            return f'a {status} case needs "{field}"'
    for n, assertion in enumerate(case["assertions"]):
        needs, forbids = (("clause", "basis") if assertion["level"] in NORMATIVE
                          else ("basis", "clause"))
        if needs not in assertion or forbids in assertion:
            return (f'assertions[{n}] at level {assertion["level"]} needs "{needs}" and must '
                    f'not carry "{forbids}"')
        if assertion.get("expected") == "superseded" and assertion.get("phase") != "final":
            return f"assertions[{n}] expects superseded, which is a final disposition only"
    return None


def case_problem(case) -> str | None:
    """None if the case satisfies the case schema (and the runner's own rule that assertion ids
    are unique), else a sentence saying what is wrong."""
    if not isinstance(case, dict):
        return "It is not a JSON object."
    problem = CASE(case, "") or _cross_field_problem(case)
    if problem:
        return f"It does not satisfy the case schema: {problem}."
    ids = [a["id"] for a in case["assertions"]]
    for assertion_id in ids:
        if ids.count(assertion_id) > 1:
            return f'Its assertion id "{assertion_id}" is used twice.'
    return None


def _read(path: Path, max_bytes: int):
    try:
        return read_json(path, max_bytes)
    except JsonFileError as exc:
        if exc.transient:
            code = E_CASE_READ_TRANSIENT
        elif exc.kind in ("missing", "io"):
            code = E_CASE_READ
        else:
            code = E_CASE_FORMAT
        raise RunnerError(code, f"The case file {path} {exc.sentence}.") from exc


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
