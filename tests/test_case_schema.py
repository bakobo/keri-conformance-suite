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
            "expected": "not-seen",
            "level": "MUST",
            "clause": CLAUSE,
        },
        {
            "id": "a2",
            "check": "key_state",
            "if_seen": 1,
            "aid": "EAbc",
            "expected": {
                "sn": 2, "said": "EDef", "keys": ["DAbc"], "kt": "1",
                "ndigs": ["EGhi"], "nt": "1", "wits": [], "bt": "0", "delegator": None,
            },
            "level": "SHOULD",
            "clause": CLAUSE,
        },
        {
            "id": "a3",
            "check": "trunk",
            "message": 1,
            "expected": True,
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


QUOTED_BASIS = {
    "text": "The ACDC specification's non-normative IPEX section states this practice.",
    "spec": "acdc",
    "section": "IPEX",
    "url": "https://github.com/trustoverip/kswg-acdc-specification/blob/4df80aa/spec/spec.md#ipex",
    "commit": "4df80aa",
    "quote": "A Discloser MAY respond with a grant.",
}


def test_an_interop_basis_may_quote_the_sentence_it_rests_on():
    case = copy.deepcopy(KERI_CASE)
    assertion = case["assertions"][0]
    assertion["level"] = "INTEROP"
    del assertion["clause"]
    assertion["basis"] = copy.deepcopy(QUOTED_BASIS)
    assert errors(case) == []


@pytest.mark.parametrize("field", ["text", "spec", "section", "url", "commit", "quote"])
def test_a_quoted_basis_needs_every_field(field):
    case = copy.deepcopy(KERI_CASE)
    assertion = case["assertions"][0]
    assertion["level"] = "INTEROP"
    del assertion["clause"]
    assertion["basis"] = {k: v for k, v in QUOTED_BASIS.items() if k != field}
    assert errors(case), f"a quoted basis without {field} cannot be traced to its sentence"


@pytest.mark.parametrize("change", [{"quote": ""}, {"text": ""}, {"spec": "vlei"},
                                    {"commit": "zz"}, {"url": "http://x"}, {"extra": 1}])
def test_a_quoted_basis_is_checked_like_a_clause(change):
    case = copy.deepcopy(KERI_CASE)
    assertion = case["assertions"][0]
    assertion["level"] = "INTEROP"
    del assertion["clause"]
    assertion["basis"] = {**QUOTED_BASIS, **change}
    assert errors(case)


def test_interop_level_must_not_carry_a_clause():
    case = copy.deepcopy(KERI_CASE)
    case["assertions"][0]["level"] = "INTEROP"
    case["assertions"][0]["basis"] = "keripy 1.x behaviour"
    assert errors(case), "an assertion resting on a clause is normative, not INTEROP"


def test_clause_must_pin_a_commit():
    case = copy.deepcopy(KERI_CASE)
    del case["assertions"][0]["clause"]["commit"]
    assert errors(case)


@pytest.mark.parametrize("phase", ["initial", "final"])
@pytest.mark.parametrize("expected", ["seen", "not-seen", "pending", "rejected", "duplicitous"])
def test_disposition_values(expected, phase):
    case = copy.deepcopy(KERI_CASE)
    case["assertions"][0]["expected"] = expected
    case["assertions"][0]["phase"] = phase
    assert errors(case) == []


@pytest.mark.parametrize("expected", ["escrowed", "accepted", "not-accepted", "superseded"])
def test_unknown_or_retired_disposition_is_rejected(expected):
    # Superseded is now a final seen reading with a false trunk reading, not a value of its own.
    case = copy.deepcopy(KERI_CASE)
    case["assertions"][0]["expected"] = expected
    assert errors(case)


def test_trunk_assertion_names_a_message_and_a_boolean():
    for field in ("message", "expected"):
        case = copy.deepcopy(KERI_CASE)
        del case["assertions"][2][field]
        assert errors(case), field
    for bad in ("true", 1, None):
        case = copy.deepcopy(KERI_CASE)
        case["assertions"][2]["expected"] = bad
        assert errors(case), bad


def test_trunk_is_read_once_so_it_has_no_phase():
    case = copy.deepcopy(KERI_CASE)
    case["assertions"][2]["phase"] = "final"
    assert errors(case)


def test_trunk_is_a_keri_process_check():
    case = copy.deepcopy(CESR_CASE)
    case["assertions"] = [{"id": "a1", "check": "trunk", "message": 0, "expected": False,
                           "level": "MUST", "clause": CLAUSE}]
    assert errors(case)


def test_key_state_is_conditional_on_a_message_being_seen():
    case = copy.deepcopy(KERI_CASE)
    del case["assertions"][1]["if_seen"]
    assert errors(case)
    for bad in (-1, "1", 1.5, None):
        case["assertions"][1]["if_seen"] = bad
        assert errors(case), bad


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
