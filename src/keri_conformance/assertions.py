"""Assertion evaluation: pure functions from (assertion, adapter result) to an outcome.

The adapter's result has already been checked for plausible shape by the session; the checks here
still never assume a field is present or well-typed, because a wrong answer must be a failure and
never an exception. Equality is type-strict throughout, so `1`, `1.0` and `true` are all different.
"""

import re
from dataclasses import dataclass
from fractions import Fraction

from keri_conformance.errors import E_CHECK_NOT_IMPLEMENTED

# The schemas' threshold patterns, matched with re.search as Python's jsonschema matches them.
NUMERIC = re.compile(r"^(0x)?[0-9a-fA-F]+$")
FRACTION = re.compile(r"^[0-9]+(/[0-9]*[1-9][0-9]*)?$")
KEY_STATE_FIELDS = ("sn", "said", "keys", "kt", "ndigs", "nt", "wits", "bt", "delegator")
CRYPTO_CHECKS = ("emitted_body", "signatures_verify", "attachments_equivalent")


@dataclass(frozen=True)
class Evaluation:
    """`outcome` is pass, fail or not-implemented; `actual` is what the adapter reported."""

    outcome: str
    actual: object
    detail: str | None = None


def strict_equal(a, b) -> bool:
    """Equality that also requires equal JSON types at every level."""
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return a.keys() == b.keys() and all(strict_equal(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(strict_equal(x, y) for x, y in zip(a, b, strict=True))
    return a == b


def _numeric(value):
    if isinstance(value, str) and NUMERIC.search(value):
        return ("numeric", int(value.removeprefix("0x"), 16))
    return None


def _fraction(value):
    if not (isinstance(value, str) and FRACTION.search(value)):
        return None
    return str(Fraction(value))  # FRACTION admits no zero denominator


def normalize_threshold(value):
    """A canonical, comparable form of a threshold, or None if it is malformed.

    A numeric threshold is a hex integer string with an optional 0x prefix. A weighted threshold
    is a list of fraction strings (one clause) or a list of such lists (several clauses); each
    fraction becomes `n/d` in lowest terms, or `n` when the denominator is 1. The two kinds never
    compare equal.
    """
    if isinstance(value, str):
        return _numeric(value)
    if not isinstance(value, list) or not value:
        return None
    if all(isinstance(v, str) for v in value):
        clauses = [value]
    elif all(isinstance(v, list) for v in value):
        clauses = value
    else:
        return None
    normalized = []
    for clause in clauses:
        fractions = tuple(_fraction(v) for v in clause)
        if not clause or None in fractions:
            return None
        normalized.append(fractions)
    return ("weighted", tuple(normalized))


def _fail(actual, detail):
    return Evaluation("fail", actual, detail)


def _decoded(assertion, result):
    if "items" not in result:
        return _fail(result, "The adapter did not report decoded items.")
    items = result["items"]
    if strict_equal(items, assertion["expected"]):
        return Evaluation("pass", items)
    return _fail(items, "The decoded items differ from the expected items.")


def _rejected(assertion, result):
    if "reject" in result:
        return Evaluation("pass", result)
    return _fail(result, "The adapter did not reject the stream.")


def _encoded(assertion, result):
    encoded = result.get("encoded")
    if strict_equal(encoded, assertion["expected"]):
        return Evaluation("pass", encoded)
    return _fail(encoded, "The encoding differs from the expected encoding.")


def _disposition(assertion, result):
    dispositions = result.get("dispositions")
    message, phase, expected = assertion["message"], assertion["phase"], assertion["expected"]
    if not isinstance(dispositions, list) or message >= len(dispositions):
        return _fail(None, f"The adapter reported no disposition for message {message}.")
    actual = dispositions[message].get(phase)
    if expected == "not-accepted":
        excluded = ("accepted", "superseded") if phase == "final" else ("accepted",)
        holds = actual not in excluded
    else:
        holds = actual == expected
    if holds:
        return Evaluation("pass", actual)
    return _fail(actual, f"Message {message}'s {phase} disposition is {actual}, not {expected}.")


def _key_state(assertion, result):
    aid, expected = assertion["aid"], assertion["expected"]
    states = result.get("key_states")
    if not isinstance(states, dict) or aid not in states:
        return _fail(None, f"The adapter reported no key state for {aid}.")
    actual = states[aid]
    wrong = []
    for field in KEY_STATE_FIELDS:
        if field not in actual:
            wrong.append(field)
        elif field in ("kt", "nt"):
            ours = normalize_threshold(expected[field])
            if ours is None or ours != normalize_threshold(actual[field]):
                wrong.append(field)
        elif field == "bt":
            ours = _numeric(expected[field])
            if ours is None or ours != _numeric(actual[field]):
                wrong.append(field)
        elif not strict_equal(actual[field], expected[field]):
            wrong.append(field)
    if wrong:
        return _fail(actual, f"The key state of {aid} differs in {', '.join(wrong)}.")
    return Evaluation("pass", actual)


CHECKS = {
    "decoded": _decoded,
    "rejected": _rejected,
    "encoded": _encoded,
    "disposition": _disposition,
    "key_state": _key_state,
}


def evaluate(assertion: dict, result: dict) -> Evaluation:
    """Evaluate one assertion against the adapter's result for its case."""
    check = CHECKS.get(assertion["check"])
    if check is None:
        return Evaluation("not-implemented", None,
                          f"{E_CHECK_NOT_IMPLEMENTED}: This runner version cannot evaluate a "
                          f"{assertion['check']} assertion, so it is neither passed nor failed.")
    return check(assertion, result)
