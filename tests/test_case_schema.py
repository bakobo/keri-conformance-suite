"""The case schema accepts well-formed cases and rejects each way a case can be malformed.

The schema is the contract between generators, which write cases, and the runner and adapter
authors, which read them, so most of these tests are negative: each removes or breaks one thing a
case must have and checks the schema refuses it.
"""

import copy
import json
import pathlib

import pytest
from jsonschema import Draft202012Validator

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCHEMA = json.loads((ROOT / "schema" / "case.schema.json").read_text(encoding="utf-8"))
VALIDATOR = Draft202012Validator(SCHEMA)

CLAUSE = {
    "spec": "keri",
    "section": "Indexed signatures",
    "url": "https://github.com/trustoverip/kswg-keri-specification/blob/4df80aa/spec/spec-body.md#indexed-signatures",
    "commit": "4df80aa",
}

KERI_CASE = {
    "schema_version": 1,
    "id": "KERI-0001",
    "title": "Out-of-order interaction is not accepted early",
    "description": "An ixn at sn 2 arrives before the ixn at sn 1.",
    "status": "active",
    "profile": "keri-1.0",
    "targets": {"wire": ["KERI10JSON"], "features": ["kel.basic", "crypto.ed25519"]},
    "operation": "keri.process",
    "input": {
        "perspective": {"role": "validator"},
        "messages": [
            {"stream": "7b22", "source": "controller"},
            {"stream": "7b23", "source": "controller"},
        ],
    },
    "assertions": [
        {
            "id": "a1",
            "check": "disposition",
            "message": 1,
            "phase": "initial",
            "expected": "not-accepted",
            "level": "MUST",
            "clause": CLAUSE,
        },
        {
            "id": "a2",
            "check": "key_state",
            "aid": "EAbc",
            "expected": {
                "sn": 2, "said": "EDef", "keys": ["DAbc"], "kt": "1",
                "ndigs": ["EGhi"], "nt": "1", "wits": [], "bt": "0", "delegator": None,
            },
            "level": "SHOULD",
            "clause": CLAUSE,
        },
    ],
    "provenance": {
        "scenario": "scenarios/keri/out-of-order.yaml#ixn-early",
        "generator": {"name": "kcs-gen-keripy", "version": "0.0.1"},
        "reference": {"implementation": "keripy", "commit": "9a8b7aa7"},
    },
}

CESR_CASE = {
    "schema_version": 1,
    "id": "CESR-0001",
    "title": "Truncated count code is rejected",
    "description": "A stream that ends inside a count code.",
    "status": "active",
    "profile": "cesr-1.0",
    "targets": {"wire": ["CESR-2.00"], "features": ["cesr.genus-2.00"]},
    "operation": "cesr.parse",
    "input": {"stream": "2d4b"},
    "assertions": [
        {
            "id": "a1",
            "check": "rejected",
            "level": "MUST",
            "clause": {**CLAUSE, "spec": "cesr", "section": "Count codes"},
        }
    ],
    "provenance": {
        "scenario": "scenarios/cesr/truncation.yaml#count-code",
        "generator": {"name": "kcs-gen-spec-tables", "version": "0.0.1"},
        "reference": None,
    },
}


def errors(case):
    return sorted(VALIDATOR.iter_errors(case), key=lambda e: list(e.path))


def test_schema_is_itself_valid():
    Draft202012Validator.check_schema(SCHEMA)


@pytest.mark.parametrize("case", [KERI_CASE, CESR_CASE], ids=["keri", "cesr"])
def test_well_formed_cases_validate(case):
    assert errors(case) == []


@pytest.mark.parametrize(
    "field",
    ["schema_version", "id", "title", "description", "status", "profile", "targets",
     "operation", "input", "assertions", "provenance"],
)
def test_every_top_level_field_is_required(field):
    case = copy.deepcopy(KERI_CASE)
    del case[field]
    assert errors(case)


@pytest.mark.parametrize("bad", ["KERI-1", "keri-0001", "KEL-0001", "KERI-00001", "KERI-0001x"])
def test_case_id_format_is_enforced(bad):
    case = copy.deepcopy(KERI_CASE)
    case["id"] = bad
    assert errors(case)


def test_unknown_top_level_field_is_rejected():
    case = copy.deepcopy(KERI_CASE)
    case["expected"] = {"verdict": "accepted"}  # the old single-verdict shape must not creep back
    assert errors(case)


def test_assertions_cannot_be_empty():
    case = copy.deepcopy(KERI_CASE)
    case["assertions"] = []
    assert errors(case)


@pytest.mark.parametrize("level", ["MUST", "SHOULD", "MAY"])
def test_normative_levels_require_a_clause(level):
    case = copy.deepcopy(KERI_CASE)
    case["assertions"][0]["level"] = level
    del case["assertions"][0]["clause"]
    assert errors(case)


def test_interop_level_requires_a_basis_instead_of_a_clause():
    case = copy.deepcopy(KERI_CASE)
    assertion = case["assertions"][0]
    assertion["level"] = "INTEROP"
    del assertion["clause"]
    assert errors(case), "an INTEROP assertion must say what behaviour it rests on"
    assertion["basis"] = "keripy 1.x accepts this stream"
    assert errors(case) == []


def test_interop_level_must_not_carry_a_clause():
    case = copy.deepcopy(KERI_CASE)
    case["assertions"][0]["level"] = "INTEROP"
    case["assertions"][0]["basis"] = "keripy 1.x behaviour"
    assert errors(case), "an assertion resting on a clause is normative, not INTEROP"


def test_clause_must_pin_a_commit():
    case = copy.deepcopy(KERI_CASE)
    del case["assertions"][0]["clause"]["commit"]
    assert errors(case)


@pytest.mark.parametrize(
    "expected", ["not-accepted", "accepted", "pending", "rejected", "duplicitous", "superseded"]
)
def test_disposition_values(expected):
    case = copy.deepcopy(KERI_CASE)
    case["assertions"][0]["expected"] = expected
    case["assertions"][0]["phase"] = "final"
    assert errors(case) == []


def test_unknown_disposition_is_rejected():
    case = copy.deepcopy(KERI_CASE)
    case["assertions"][0]["expected"] = "escrowed"
    assert errors(case)


def test_superseded_is_only_a_final_disposition():
    case = copy.deepcopy(KERI_CASE)
    case["assertions"][0]["expected"] = "superseded"
    case["assertions"][0]["phase"] = "initial"
    assert errors(case)


def test_disposition_assertion_needs_message_and_phase():
    for field in ("message", "phase"):
        case = copy.deepcopy(KERI_CASE)
        del case["assertions"][0][field]
        assert errors(case), field


def test_key_state_requires_every_field():
    for field in ("sn", "said", "keys", "kt", "ndigs", "nt", "wits", "bt", "delegator"):
        case = copy.deepcopy(KERI_CASE)
        del case["assertions"][1]["expected"][field]
        assert errors(case), field


def test_streams_are_lowercase_hex():
    for bad in ("7B22", "7b2", "zz", "{\"v\":1}"):
        case = copy.deepcopy(KERI_CASE)
        case["input"]["messages"][0]["stream"] = bad
        assert errors(case), bad


def test_keri_process_requires_perspective():
    case = copy.deepcopy(KERI_CASE)
    del case["input"]["perspective"]
    assert errors(case)


def test_operation_and_input_must_match():
    case = copy.deepcopy(KERI_CASE)
    case["operation"] = "cesr.parse"
    assert errors(case), "a keri.process input under cesr.parse must not validate"


def test_disputed_case_requires_dispute_record():
    case = copy.deepcopy(KERI_CASE)
    case["status"] = "disputed"
    assert errors(case)
    case["dispute"] = {
        "clauses": [CLAUSE],
        "summary": "keripy escrows where the clause says drop.",
        "raised_at": "https://github.com/trustoverip/kswg-keri-specification/issues/1",
    }
    assert errors(case) == []


def test_deprecated_case_requires_successor():
    case = copy.deepcopy(KERI_CASE)
    case["status"] = "deprecated"
    assert errors(case)
    case["superseded_by"] = "KERI-0002"
    assert errors(case) == []


def test_reference_may_be_null_only_when_spec_derived():
    case = copy.deepcopy(KERI_CASE)
    case["provenance"]["reference"] = None
    assert errors(case) == [], "a spec-derived case names no reference implementation"
    del case["provenance"]["reference"]
    assert errors(case), "reference must be stated, even if null"
