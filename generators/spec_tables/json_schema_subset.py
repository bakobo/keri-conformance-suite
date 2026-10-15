"""The JSON Schema subset the generators evaluate, which lives with the runner
(src/keri_conformance/json_schema_subset.py) so the runner can check an issued credential against
its schema too. A refusal is re-raised here as a generator error, so a generator catches it as it
catches every other."""

from keri_conformance import json_schema_subset as _js
from keri_conformance.json_schema_subset import (
    DIALECT,
    E_DEPTH,
    E_FORM,
    E_KEYWORD,
    E_REFERENCE,
    dialect,
    nonlocal_references,
)

from .errors import GeneratorError

# The names the generators use, re-exported from the runner's module.
__all__ = ["DIALECT", "E_DEPTH", "E_FORM", "E_KEYWORD", "E_REFERENCE", "SchemaError", "check",
           "dialect", "nonlocal_references", "validate"]


class SchemaError(GeneratorError):
    pass


def check(schema, allow_nonlocal: bool = False) -> None:
    try:
        _js.check(schema, allow_nonlocal)
    except _js.SchemaError as exc:
        raise SchemaError(exc.message, exc.code) from None


def validate(schema, instance) -> bool:
    try:
        return _js.validate(schema, instance)
    except _js.SchemaError as exc:
        raise SchemaError(exc.message, exc.code) from None
