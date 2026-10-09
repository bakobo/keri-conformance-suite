"""Loading cases from disk, checked against a hand-written mirror of the case schema.

The contract is `schema/case.schema.json`. The runner has no runtime dependencies, so it cannot
run that schema; CASE below mirrors it with the combinators in shapes.py, and
tests/test_schema_agreement.py proves the two agree. A schema-invalid case is therefore a runner
fault naming its file, never a case that gets scored.
"""

import os
from pathlib import Path

from keri_conformance.contracts import (
    EDGE_PATH,
    EXN_READINGS,
    HEX_STRING,
    ITEM,
    KEY_STATE,
    REGISTRY_STATE,
    SAID,
)
from keri_conformance.errors import (
    E_CASE_FORMAT,
    E_CASE_READ,
    E_CASE_READ_TRANSIENT,
    E_CASES_BYTES,
    E_CASES_COUNT,
    E_CASES_MISSING,
    RunnerError,
)
from keri_conformance.jsonfile import TRANSIENT_ERRNOS, JsonFileError, read_json
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
MAX_CASE_FILES = 10_000
MAX_CASES_BYTES = 256 * 1024 * 1024
MAX_DAG_ACDCS = 16
MAX_DAG_DEPTH = 8
CASE_ID = "^(CESR|KERI|ACDC|IPEX)-[0-9]{4}$"
COMMIT = "^[0-9a-f]{7,40}$"
FEATURE = r"^[a-z0-9]+(\.[a-z0-9-]+)+$"
STATUSES = ("active", "draft", "disputed", "deprecated")
NORMATIVE = ("MUST", "SHOULD", "MAY")
LEVELS = (*NORMATIVE, "INTEROP")
EXPECTED_READINGS = ("seen", "not-seen", "pending", "rejected", "duplicitous")
# Cases grade an ACDC as valid or not valid; invalid and incomplete are both not valid.
EXPECTED_VERDICTS = ("valid", "not-valid")

CLAUSE = obj({"spec": enum("cesr", "keri", "acdc", "ipex"), "section": string(min_length=1),
              "url": string("^https://"), "commit": string(COMMIT)},
             {"quote": string()})


SPEC_CONFLICT = obj({"quote": string(min_length=1), "section": string(min_length=1),
                     "line": integer(minimum=1), "why": string(min_length=1)})
INFERENCE = obj({"quote": string(min_length=1), "section": string(min_length=1),
                 "line": integer(minimum=1), "inference": string(min_length=1)})


def _assertion(check: str, **fields) -> Check:
    return obj({"id": string("^a[0-9]+$"), "check": enum(check), "level": enum(*LEVELS),
                **fields},
               {"clause": CLAUSE, "basis": string(min_length=1), "note": string(),
                "spec_conflicts": array(SPEC_CONFLICT, min_items=1),
                "inferred_from": INFERENCE})


CHECK_FORMS = {
    "decoded": _assertion("decoded", expected=array(ITEM)),
    "rejected": _assertion("rejected"),
    "encoded": _assertion("encoded", expected=HEX_STRING),
    "disposition": _assertion("disposition", message=integer(minimum=0),
                              phase=enum("initial", "final"),
                              expected=enum(*EXPECTED_READINGS)),
    "trunk": _assertion("trunk", message=integer(minimum=0), expected=enum(True, False)),
    "key_state": _assertion("key_state", if_seen=integer(minimum=0), aid=string(),
                            expected=KEY_STATE),
    "emitted_body": _assertion("emitted_body", expected=HEX_STRING),
    "signatures_verify": _assertion("signatures_verify"),
    "attachments_equivalent": _assertion("attachments_equivalent",
                                         expected=array(anything_object)),
    "verdict": _assertion("verdict", expected=enum(*EXPECTED_VERDICTS)),
    "registry_reported": _assertion("registry_reported", expected=enum(True, False)),
    "registry_state": _assertion("registry_state", expected=REGISTRY_STATE),
    "edge_reported": _assertion("edge_reported", near=SAID, path=string(EDGE_PATH)),
    "edge_valid": _assertion("edge_valid", near=SAID, path=string(EDGE_PATH),
                             expected=enum(True, False)),
    "exn_verdict": _assertion("exn_verdict", message=integer(minimum=0),
                              expected=enum(*EXN_READINGS)),
}

# The checks that can apply to each operation's result.
OPERATION_CHECKS = {
    "cesr.parse": ("decoded", "rejected"),
    "cesr.encode": ("encoded",),
    "keri.process": ("disposition", "trunk", "key_state"),
    "keri.emit": ("emitted_body", "signatures_verify", "attachments_equivalent"),
    "acdc.verify": ("verdict", "registry_reported", "registry_state", "edge_reported",
                    "edge_valid"),
    "exn.verify": ("exn_verdict",),
}

PERSPECTIVE = obj({"role": enum("validator")})
SOURCED = obj({"stream": HEX_STRING, "source": string()})
STREAM = obj({"stream": HEX_STRING})

INPUTS = {
    "cesr.parse": obj({"stream": HEX_STRING}),
    "cesr.encode": obj({"code": string(min_length=1), "raw": HEX_STRING,
                        "domain": enum("text", "binary")}),
    "keri.process": obj({"perspective": PERSPECTIVE, "messages": array(SOURCED, min_items=1)}),
    "keri.emit": obj({"event": anything_object, "seeds": mapping(HEX_STRING)}),
    # The bundle (docs/design.md, ACDC): every KEL, registry event, schema and far-node ACDC the
    # presented ACDC depends on. The presented ACDC is a node of its own DAG, so the far nodes
    # number at most one fewer than the DAG's bound.
    "acdc.verify": obj({"perspective": PERSPECTIVE, "kels": array(SOURCED),
                        "registry": array(STREAM), "schemas": array(HEX_STRING),
                        "acdcs": array(STREAM, max_items=MAX_DAG_ACDCS - 1),
                        "presented": STREAM},
                       {"expect_schema": SAID}),
    "exn.verify": obj({"perspective": PERSPECTIVE, "kels": array(SOURCED),
                       "messages": array(SOURCED, min_items=1)}),
}

# The shape of an ACDC case's provenance DAG, which the runner bounds (_dag_problem) but never
# sends: the adapter finds the DAG in the bundle's bytes. `as_of` records, informatively, the
# sequence number at which the generator cut each KEL and registry: the evaluation point.
DAG = obj({"root": SAID, "edges": array(obj({"near": SAID, "path": string(EDGE_PATH),
                                             "n": SAID}))})
AS_OF = mapping(integer(minimum=0))
ACDC_ONLY = ("dag", "as_of")

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
        "dag": DAG,
        "as_of": AS_OF,
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
    acdc = case["operation"] == "acdc.verify"
    for field in ACDC_ONLY:
        if acdc and field not in case:
            return f'an acdc.verify case needs "{field}"'
        if not acdc and field in case:
            return f'only an acdc.verify case carries "{field}"'
    checks = OPERATION_CHECKS[case["operation"]]
    for n, assertion in enumerate(case["assertions"]):
        if assertion["check"] not in checks:
            return (f'assertions[{n}] uses the check {assertion["check"]}, which a '
                    f'{case["operation"]} operation cannot satisfy; its checks are '
                    f'{", ".join(checks)}')
        needs, forbids = (("clause", "basis") if assertion["level"] in NORMATIVE
                          else ("basis", "clause"))
        if needs not in assertion or forbids in assertion:
            return (f'assertions[{n}] at level {assertion["level"]} needs "{needs}" and must '
                    f'not carry "{forbids}"')
        if "inferred_from" in assertion and assertion["level"] != "SHOULD":
            return (f'assertions[{n}] carries "inferred_from", so its level must be SHOULD, '
                    f'not {assertion["level"]}')
    return None


def _longest(node, children, depth, path) -> int | None:
    """The most edges on a path from `node`, or None if a cycle is reachable from it. The node
    count is bounded before this runs, so the recursion is at most MAX_DAG_ACDCS deep."""
    if node in path:
        return None
    if node not in depth:
        path.add(node)
        lengths = [_longest(far, children, depth, path) for far in children.get(node, ())]
        path.discard(node)
        depth[node] = None if None in lengths else max((n + 1 for n in lengths), default=0)
    return depth[node]


def _dag_problem(dag: dict) -> str | None:
    """The bounds of docs/design.md, ACDC: at most MAX_DAG_ACDCS ACDCs, the presented one
    included, and at most MAX_DAG_DEPTH edges on the longest path from it; no cycle; each edge
    listed once."""
    edges = dag["edges"]
    nodes = {dag["root"]} | {e["near"] for e in edges} | {e["n"] for e in edges}
    if len(nodes) > MAX_DAG_ACDCS:
        return (f"Its provenance DAG holds {len(nodes)} ACDCs, more than the {MAX_DAG_ACDCS} a "
                "case may hold.")
    children, listed = {}, set()
    for edge in edges:
        if (edge["near"], edge["path"]) in listed:
            return f'Its provenance DAG lists the edge {edge["path"]} of {edge["near"]} twice.'
        listed.add((edge["near"], edge["path"]))
        children.setdefault(edge["near"], []).append(edge["n"])
    reached, frontier = {dag["root"]}, [dag["root"]]
    while frontier:
        for far in children.get(frontier.pop(), []):
            if far not in reached:
                reached.add(far)
                frontier.append(far)
    for edge in edges:
        if edge["near"] not in reached:
            return (f'Its provenance DAG lists the edge {edge["path"]} of {edge["near"]}, which '
                    f'the presented ACDC {dag["root"]} cannot reach.')
    depth = {}
    for node in sorted(nodes):
        if _longest(node, children, depth, set()) is None:
            return "Its provenance DAG has a cycle, so it is not a DAG."
    if depth[dag["root"]] > MAX_DAG_DEPTH:
        return (f"The longest path in its provenance DAG has {depth[dag['root']]} edges, more "
                f"than the {MAX_DAG_DEPTH} a case may hold.")
    return None


def case_problem(case) -> str | None:
    """None if the case satisfies the case schema (and the runner's own rule that assertion ids
    are unique), else a sentence saying what is wrong."""
    if not isinstance(case, dict):
        return "It is not a JSON object."
    problem = CASE(case, "") or _cross_field_problem(case)
    if problem:
        return f"It does not satisfy the case schema: {problem}."
    if "dag" in case:
        problem = _dag_problem(case["dag"])
        if problem:
            return problem
    seen = set()
    for assertion in case["assertions"]:
        if assertion["id"] in seen:
            return f'Its assertion id "{assertion["id"]}" is used twice.'
        seen.add(assertion["id"])
        # Beyond the schema, which cannot relate an index to a list's length.
        index = assertion.get("if_seen", assertion.get("message"))
        if index is not None:
            delivered = len(case["input"]["messages"])
            if index >= delivered:
                return (f'Its assertion "{assertion["id"]}" names message {index}, but the '
                        f'case delivers only {delivered} '
                        f'message{"" if delivered == 1 else "s"}.')
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


def _discover(directory: Path, max_files: int, max_total_bytes: int) -> list[Path]:
    """The case files under `directory`, refusing during the walk, before any file is read, once
    there are more than `max_files` of them or they add up to more than `max_total_bytes`."""
    paths, total = [], 0
    for path in directory.rglob("*.json"):
        if len(paths) == max_files:
            raise RunnerError(E_CASES_COUNT, f"The cases directory {directory} holds more than "
                                             f"{max_files} case files, the most the runner will "
                                             "load in one run.")
        try:
            total += os.path.getsize(path)
        except OSError as exc:
            code = E_CASE_READ_TRANSIENT if exc.errno in TRANSIENT_ERRNOS else E_CASE_READ
            raise RunnerError(code, f"The case file {path} could not be sized: "
                                    f"{exc.strerror or exc}.") from exc
        if total > max_total_bytes:
            raise RunnerError(E_CASES_BYTES, f"The case files under {directory} add up to more "
                                             f"than {max_total_bytes} bytes, the most the runner "
                                             "will load in one run.")
        paths.append(path)
    return sorted(paths)


def load_cases(directory, max_bytes: int = MAX_CASE_BYTES, *, max_files: int = MAX_CASE_FILES,
               max_total_bytes: int = MAX_CASES_BYTES) -> list[dict]:
    """Every case under `directory`, recursively, sorted by id."""
    directory = Path(directory)
    if not directory.is_dir():
        raise RunnerError(E_CASES_MISSING, f"The cases directory {directory} does not exist; pass "
                                           "--cases, or --suite with the root of a suite checkout.")
    cases, origin = [], {}
    for path in _discover(directory, max_files, max_total_bytes):
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
