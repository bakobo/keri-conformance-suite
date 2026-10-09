"""Small structural checks, stdlib only, for mirroring the suite's JSON schemas by hand.

The runner has no runtime dependencies, so it cannot run `schema/*.json`. Instead each schema is
mirrored here with a handful of combinators, and tests/test_schema_agreement.py runs the mirror
and the real schema over a mutation corpus and fails on any disagreement.

A check is a function `(value, path) -> str | None`: None if the value conforms, else a sentence
fragment naming the path and what was expected. Pattern matching uses `re.search`, as Python's
jsonschema does, so the two agree on every string. Integers are stricter than Python's jsonschema,
which counts 1.0 as an integer; the runner indexes and compares with these values, so it requires
a JSON integer.
"""

import re
from collections.abc import Callable

Check = Callable[[object, str], str | None]

HEX = r"^([0-9a-f]{2})*$"


def _matches(compiled, value: str) -> bool:
    """Match as JSON Schema (ECMA-262) does: search, but a pattern ending in "$" must reach the
    true end of the string. Python's "$" also matches before a final newline, which would let
    "0xabc\\n" pass a hex pattern."""
    found = compiled.search(value)
    if found is None:
        return False
    return not compiled.pattern.endswith("$") or found.end() == len(value)


def _name(path: str) -> str:
    return path or "the document"


def _join(path: str, key) -> str:
    return f"{path}[{key}]" if isinstance(key, int) else (f"{path}.{key}" if path else key)


def _json_equal(a, b) -> bool:
    return type(a) is type(b) and a == b


def _describe(values) -> str:
    return ", ".join(f'"{v}"' if isinstance(v, str) else str(v) for v in values)


def string(pattern: str | None = None, min_length: int = 0) -> Check:
    compiled = re.compile(pattern) if pattern else None

    def check(value, path):
        if not isinstance(value, str):
            return f"{_name(path)} must be a string"
        if len(value) < min_length:
            return f"{_name(path)} must not be empty"
        if compiled and not _matches(compiled, value):
            return f"{_name(path)} must match {pattern}"
        return None

    return check


def integer(minimum: int | None = None) -> Check:
    def check(value, path):
        if type(value) is not int:
            return f"{_name(path)} must be an integer"
        if minimum is not None and value < minimum:
            return f"{_name(path)} must be at least {minimum}"
        return None

    return check


def enum(*values) -> Check:
    def check(value, path):
        if any(_json_equal(value, v) for v in values):
            return None
        return f"{_name(path)} must be {'one of ' if len(values) > 1 else ''}{_describe(values)}"

    return check


def anything_object(value, path):
    return None if isinstance(value, dict) else f"{_name(path)} must be an object"


def array(items: Check, min_items: int = 0, max_items: int | None = None) -> Check:
    def check(value, path):
        if not isinstance(value, list):
            return f"{_name(path)} must be a list"
        if len(value) < min_items:
            return f"{_name(path)} must have at least {min_items} item{'s' if min_items > 1 else ''}"
        if max_items is not None and len(value) > max_items:
            return f"{_name(path)} must have at most {max_items} items"
        for n, item in enumerate(value):
            problem = items(item, _join(path, n))
            if problem:
                return problem
        return None

    return check


def mapping(values: Check) -> Check:
    """An object whose every value satisfies `values` (additionalProperties: <schema>)."""

    def check(value, path):
        if not isinstance(value, dict):
            return f"{_name(path)} must be an object"
        for key, item in value.items():
            problem = values(item, _join(path, key))
            if problem:
                return problem
        return None

    return check


def obj(required: dict[str, Check], optional: dict[str, Check] | None = None) -> Check:
    """A closed object (additionalProperties: false)."""
    optional = optional or {}

    def check(value, path):
        if not isinstance(value, dict):
            return f"{_name(path)} must be an object"
        for key in required:
            if key not in value:
                return f"{_name(path)} lacks the required field \"{key}\""
        for key, item in value.items():
            field = required.get(key) or optional.get(key)
            if field is None:
                return f"{_name(path)} has the unexpected field \"{key}\""
            problem = field(item, _join(path, key))
            if problem:
                return problem
        return None

    return check


def nullable(form: Check) -> Check:
    """null, or `form` (the schema's oneOf of null and one other type)."""

    def check(value, path):
        return None if value is None else form(value, path)

    return check


def keyed(forms: dict[str, Check]) -> Check:
    """One of several closed objects told apart by which required key is present, as a oneOf whose
    branches each require a different key. Dispatching on the key keeps the complaint specific."""

    def check(value, path):
        if not isinstance(value, dict):
            return f"{_name(path)} must be an object"
        for key, form in forms.items():
            if key in value:
                return form(value, path)
        return f"{_name(path)} must have one of {_describe(forms)}"

    return check


def tagged(tag: str, forms: dict[str, Check]) -> Check:
    """Dispatch on a discriminating field, as a oneOf whose branches each fix that field."""

    def check(value, path):
        if not isinstance(value, dict):
            return f"{_name(path)} must be an object"
        form = value.get(tag)
        if not isinstance(form, str) or form not in forms:
            return f"{_join(path, tag)} must be one of {_describe(forms)}"
        return forms[form](value, path)

    return check


def all_of(*checks: Check) -> Check:
    """Every check in turn, reporting the first problem (allOf, or a schema's if/then beside the
    form it constrains)."""

    def check(value, path):
        for each in checks:
            problem = each(value, path)
            if problem:
                return problem
        return None

    return check


def predicate(test: Callable[[object], bool], expected: str) -> Check:
    def check(value, path):
        return None if test(value) else f"{_name(path)} must be {expected}"

    return check
