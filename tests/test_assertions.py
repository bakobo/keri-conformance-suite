"""Assertion evaluation: pure functions from an assertion and an adapter's result to an outcome."""

import pytest

from keri_conformance.assertions import (
    Evaluation,
    evaluate,
    normalize_threshold,
    strict_equal,
)

ITEMS = [
    {"kind": "counter", "start": 0, "end": 4, "code": "-K", "size": 1},
    {"kind": "indexed", "start": 4, "end": 92, "code": "A", "index": 0, "raw": "9c1f"},
]


def decoded(expected):
    return {"id": "a1", "check": "decoded", "level": "MUST", "expected": expected}


# --- strict equality -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("a", "b", "equal"),
    [
        (1, 1, True),
        (1, 1.0, False),
        (1, True, False),
        (True, True, True),
        (None, None, True),
        ("a", "a", True),
        ([1, 2], [1, 2], True),
        ([1, 2], [2, 1], False),
        ([1], [1, 1], False),
        ({"a": 1}, {"a": 1}, True),
        ({"a": 1}, {"a": 1, "b": 2}, False),
        ({"a": 1}, {"b": 1}, False),
        ({"a": [1]}, {"a": [1.0]}, False),
        ([1], (1,), False),
    ],
)
def test_strict_equal(a, b, equal):
    assert strict_equal(a, b) is equal
    assert strict_equal(b, a) is equal


# --- decoded ------------------------------------------------------------------------------------


def test_decoded_holds_on_exact_items():
    assert evaluate(decoded(ITEMS), {"items": [dict(i) for i in ITEMS]}).outcome == "pass"


@pytest.mark.parametrize(
    "actual",
    [
        list(reversed(ITEMS)),
        ITEMS[:1],
        [ITEMS[0], {**ITEMS[1], "ondex": 0}],
        [ITEMS[0], {**ITEMS[1], "end": 93}],
        [ITEMS[0], {**ITEMS[1], "index": 0.0}],
    ],
)
def test_decoded_fails_on_any_difference(actual):
    evaluation = evaluate(decoded(ITEMS), {"items": actual})
    assert evaluation.outcome == "fail"
    assert evaluation.actual == actual


def test_decoded_fails_on_a_rejection():
    evaluation = evaluate(decoded(ITEMS), {"reject": {"class": "truncated"}})
    assert evaluation.outcome == "fail"
    assert evaluation.actual == {"reject": {"class": "truncated"}}


# --- rejected -----------------------------------------------------------------------------------


def test_rejected_holds_whatever_the_class():
    evaluation = evaluate({"id": "a1", "check": "rejected", "level": "MUST"},
                          {"reject": {"class": "anything"}})
    assert evaluation == Evaluation("pass", {"reject": {"class": "anything"}})


def test_rejected_fails_on_decoded_items():
    evaluation = evaluate({"id": "a1", "check": "rejected", "level": "MUST"}, {"items": ITEMS})
    assert evaluation.outcome == "fail"


# --- encoded ------------------------------------------------------------------------------------


def test_encoded_compares_exactly():
    assertion = {"id": "a1", "check": "encoded", "level": "MUST", "expected": "0aff"}
    assert evaluate(assertion, {"encoded": "0aff"}) == Evaluation("pass", "0aff")
    assert evaluate(assertion, {"encoded": "0AFF"}).outcome == "fail"
    missing = evaluate(assertion, {"items": []})
    assert (missing.outcome, missing.actual) == ("fail", None)


# --- disposition --------------------------------------------------------------------------------


def disposition(message, phase, expected):
    return {"id": "a1", "check": "disposition", "level": "MUST", "message": message,
            "phase": phase, "expected": expected}


PROCESSED = {
    "dispositions": [
        {"initial": "accepted", "final": "accepted"},
        {"initial": "pending", "final": "accepted"},
        {"initial": "accepted", "final": "superseded"},
        {"initial": "duplicitous", "final": "duplicitous"},
    ],
    "key_states": {},
}


@pytest.mark.parametrize(
    ("message", "phase", "expected", "outcome"),
    [
        (0, "initial", "accepted", "pass"),
        (1, "initial", "not-accepted", "pass"),
        (1, "initial", "pending", "pass"),
        (1, "initial", "rejected", "fail"),
        (1, "final", "accepted", "pass"),
        (1, "final", "not-accepted", "fail"),
        (0, "initial", "not-accepted", "fail"),
        (2, "final", "not-accepted", "fail"),
        (2, "final", "superseded", "pass"),
        (2, "initial", "not-accepted", "fail"),
        (3, "initial", "not-accepted", "pass"),
        (3, "final", "not-accepted", "pass"),
        (3, "final", "duplicitous", "pass"),
        (4, "initial", "accepted", "fail"),
    ],
)
def test_disposition(message, phase, expected, outcome):
    evaluation = evaluate(disposition(message, phase, expected), PROCESSED)
    assert evaluation.outcome == outcome


def test_disposition_records_the_reported_value():
    assert evaluate(disposition(1, "initial", "accepted"), PROCESSED).actual == "pending"


def test_a_missing_message_index_fails_with_a_reason():
    evaluation = evaluate(disposition(9, "final", "accepted"), PROCESSED)
    assert evaluation.outcome == "fail"
    assert evaluation.actual is None
    assert "9" in evaluation.detail


def test_disposition_against_a_non_process_result_fails():
    assert evaluate(disposition(0, "final", "accepted"), {"encoded": "00"}).outcome == "fail"


# --- thresholds ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("a", "b"),
    [
        ("1", "0x1"),
        ("a", "0xA"),
        ("10", "0x10"),
        ("01", "1"),
        (["1/2", "1/2"], [["1/2", "1/2"]]),
        (["2/4", "1"], ["1/2", "1/1"]),
        ([["1/2"], ["1/3", "2/3"]], [["1/2"], ["2/6", "4/6"]]),
    ],
)
def test_equal_thresholds_normalize_equal(a, b):
    assert normalize_threshold(a) is not None
    assert normalize_threshold(a) == normalize_threshold(b)


@pytest.mark.parametrize(
    ("a", "b"),
    [
        ("1", "2"),
        ("10", "10/1"),
        ("1", ["1"]),
        ("0", ["0"]),
        (["1/2", "1/2"], ["1/2"]),
        (["1/2", "1/3"], ["1/3", "1/2"]),
        ([["1/2"], ["1/2"]], ["1/2", "1/2"]),
    ],
)
def test_different_thresholds_normalize_differently(a, b):
    assert normalize_threshold(a) != normalize_threshold(b)


def test_fraction_components_are_bounded_to_64_digits():
    assert normalize_threshold(["9" * 64 + "/" + "9" * 64]) == ("weighted", (("1",),))
    assert normalize_threshold(["9" * 65]) is None
    assert normalize_threshold(["1/" + "9" * 65]) is None


def test_a_fraction_that_fails_to_convert_is_malformed_not_an_exception(monkeypatch):
    from keri_conformance import assertions

    def broken(_text):
        raise ValueError("cannot convert")

    monkeypatch.setattr(assertions, "Fraction", broken)
    assert normalize_threshold(["1/2"]) is None


def test_normalized_forms_are_canonical():
    assert normalize_threshold("0x1f") == ("numeric", 31)
    assert normalize_threshold(["2/4", "3/3"]) == ("weighted", (("1/2", "1"),))


@pytest.mark.parametrize(
    "bad",
    [None, 1, True, "", "0x", "0X1", "-1", "1.5", "g", " 1", [], [[]], ["1/0"], ["1/2", ["1/2"]],
     [1], [["1/2", 3]], ["x/2"], ["1 / 2"], ["-1/2"], ["0.5"], [{"1/2": ["1/2"]}], {"a": 1}],
)
def test_malformed_thresholds_normalize_to_none(bad):
    assert normalize_threshold(bad) is None


# --- key_state ----------------------------------------------------------------------------------

STATE = {"sn": 2, "said": "EDef", "keys": ["DAbc"], "kt": "1", "ndigs": ["EGhi"], "nt": "1",
         "wits": ["BWit"], "bt": "1", "delegator": None}


def key_state(expected, aid="EAbc"):
    return {"id": "a2", "check": "key_state", "level": "SHOULD", "aid": aid, "expected": expected}


def processed(states):
    return {"dispositions": [], "key_states": states}


def test_key_state_holds_on_equal_state_with_normalized_thresholds():
    actual = {**STATE, "kt": "0x1", "nt": ["1"], "bt": "0x1"}
    expected = {**STATE, "nt": [["1/1"]]}
    evaluation = evaluate(key_state(expected), processed({"EAbc": actual}))
    assert evaluation.outcome == "pass"
    assert evaluation.actual == actual


def test_key_state_ignores_fields_beyond_the_nine():
    actual = {**STATE, "extra": 1}
    assert evaluate(key_state(STATE), processed({"EAbc": actual})).outcome == "pass"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("sn", 3),
        ("sn", 2.0),
        ("said", "EOther"),
        ("keys", ["DOther"]),
        ("kt", "2"),
        ("kt", ["1"]),
        ("ndigs", []),
        ("nt", "0"),
        ("wits", []),
        ("bt", "0"),
        ("delegator", "EDel"),
    ],
)
def test_key_state_fails_on_any_field(field, value):
    evaluation = evaluate(key_state(STATE), processed({"EAbc": {**STATE, field: value}}))
    assert evaluation.outcome == "fail"
    assert field in evaluation.detail


def test_key_state_fails_on_a_missing_field():
    actual = {k: v for k, v in STATE.items() if k != "delegator"}
    evaluation = evaluate(key_state(STATE), processed({"EAbc": actual}))
    assert evaluation.outcome == "fail"
    assert "delegator" in evaluation.detail


@pytest.mark.parametrize("bad", [{"kt": "zz"}, {"nt": [[]]}, {"bt": ["1/2"]}])
def test_malformed_thresholds_fail_on_either_side(bad):
    assert evaluate(key_state(STATE), processed({"EAbc": {**STATE, **bad}})).outcome == "fail"
    assert evaluate(key_state({**STATE, **bad}), processed({"EAbc": STATE})).outcome == "fail"


def test_key_state_for_an_identifier_not_reported_fails():
    evaluation = evaluate(key_state(STATE, aid="EZzz"), processed({"EAbc": STATE}))
    assert evaluation.outcome == "fail"
    assert evaluation.actual is None
    assert "EZzz" in evaluation.detail


def test_key_state_against_a_non_process_result_fails():
    assert evaluate(key_state(STATE), {"items": []}).outcome == "fail"


# --- checks this runner version cannot evaluate --------------------------------------------------


@pytest.mark.parametrize("check", ["emitted_body", "signatures_verify", "attachments_equivalent",
                                   "no_such_check"])
def test_crypto_checks_are_not_implemented_not_passed(check):
    evaluation = evaluate({"id": "a1", "check": check, "level": "MUST", "expected": "00"},
                          {"stream": "00"})
    assert evaluation.outcome == "not-implemented"
    assert check in evaluation.detail
    assert evaluation.detail.startswith("e.feature.unsupported.check.f: ")
