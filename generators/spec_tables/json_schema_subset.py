"""A JSON Schema 2020-12 evaluator for the subset the ACDC generator declares.

Expected schema verdicts must not come from an implementation under test, and the generators use
only the standard library, so the ACDC generator evaluates schemas itself (docs/design.md, ACDC,
"Schemas"). It implements these keywords with their 2020-12 meaning, and no others:

- ``type`` (a name or a list of names; an integer is any number with no fractional part, and a
  boolean is never a number);
- ``properties`` and ``required``, which apply only to objects;
- ``oneOf`` (exactly one subschema holds) and ``anyOf`` (at least one holds);
- ``const``, compared as JSON values: numbers by value, booleans apart from numbers, objects
  without regard to key order;
- ``$ref`` to a JSON pointer inside the same schema (``#`` or ``#/...``), applied together with
  its sibling keywords, as 2020-12 requires.

Some keywords have no effect on a verdict and are allowed: ``$id`` and ``$schema`` at the root,
``$defs`` as a home for reference targets, the annotations ``title`` and ``description``, and
``version``, which the ACDC specification requires of every schema and says is not used in
validation (line 230). Every other keyword, including words JSON Schema itself would ignore, is
refused with a coded error rather than skipped, because a skipped keyword would yield a verdict
the full dialect could contradict.

A reference that leaves the schema (a URI, a ``sad:`` or ``did:`` reference, a plain-name
fragment, ``$dynamicRef``, or an ``$id`` below the root) is refused by ``check`` and ``validate``.
``nonlocal_references`` names such references, so that a scenario built to be refused for using
one (ACDC lines 194, 206 and 220) can be recognized and decided without evaluating the schema.
"""

import urllib.parse

from .errors import GeneratorError

DIALECT = "https://json-schema.org/draft/2020-12/schema"

# A keyword outside the subset.
E_KEYWORD = "e.input.format.kcs-schema-keyword.f"
# A reference outside the schema, or one that resolves to nothing usable.
E_REFERENCE = "e.input.format.kcs-schema-reference.f"
# A keyword whose value is not of the form 2020-12 gives it.
E_FORM = "e.input.format.kcs-schema-form.f"
# Evaluation followed more nested references than any scenario schema needs.
E_DEPTH = "e.input.range.kcs-schema-depth.f"

MAX_REF_DEPTH = 64
TYPES = ("object", "array", "string", "number", "integer", "boolean", "null")
ASSERTIONS = ("type", "properties", "required", "oneOf", "anyOf", "const", "$ref")
ALLOWED = ASSERTIONS + ("$id", "$schema", "$defs", "title", "description", "version")
ROOT_ONLY = ("$id", "$schema")
NONLOCAL_KEYWORDS = ("$dynamicRef", "$dynamicAnchor", "$recursiveRef", "$recursiveAnchor")


class SchemaError(GeneratorError):
    pass


def _where(path: str) -> str:
    return f"at {path or '/'}"


def _is_local(ref) -> bool:
    return isinstance(ref, str) and (ref == "#" or ref.startswith("#/"))


def nonlocal_references(schema) -> list[str]:
    """The locations of every reference that leaves the schema: a non-local ``$ref``, a dynamic
    or recursive reference keyword, or an ``$id`` below the root."""
    found: list[str] = []

    def walk(node, path, root):
        if isinstance(node, dict):
            for key, value in node.items():
                here = f"{path}/{key}"
                leaves = key == "$ref" and not _is_local(value)
                if leaves or key in NONLOCAL_KEYWORDS or (key == "$id" and not root):
                    found.append(here)
                walk(value, here, False)
        elif isinstance(node, list):
            for i, value in enumerate(node):
                walk(value, f"{path}/{i}", False)

    walk(schema, "", True)
    return found


def _check_node(node, path: str, root: bool, refs: list, allow_nonlocal: bool):
    if isinstance(node, bool):
        return
    if not isinstance(node, dict):
        raise SchemaError(f"A schema must be an object or a boolean, not {node!r}, "
                          f"{_where(path)}.", E_FORM)
    for key, value in node.items():
        here = f"{path}/{key}"
        if key in NONLOCAL_KEYWORDS or (key == "$id" and not root):
            if allow_nonlocal:
                continue
            raise SchemaError(f"The keyword {key!r} {_where(path)} refers outside the schema, "
                              f"which the subset cannot evaluate.", E_REFERENCE)
        if key not in ALLOWED:
            raise SchemaError(f"The keyword {key!r} {_where(path)} is outside the declared JSON "
                              f"Schema subset ({', '.join(ASSERTIONS)}).", E_KEYWORD)
        if key in ROOT_ONLY and not root:  # only $schema reaches here; $id is handled above
            raise SchemaError(f"The keyword {key!r} may appear only at the root, not "
                              f"{_where(path)}.", E_FORM)
        _check_value(key, value, here, refs, allow_nonlocal)


def _check_value(key, value, here, refs, allow_nonlocal):
    if key == "type":
        names = value if isinstance(value, list) else [value]
        if (not names or any(n not in TYPES for n in names) or len(set(names)) != len(names)
                or not all(isinstance(n, str) for n in names)):
            raise SchemaError(f"{here}: type must name one or more of {', '.join(TYPES)}, each "
                              f"once; got {value!r}.", E_FORM)
    elif key in ("properties", "$defs"):
        if not isinstance(value, dict):
            raise SchemaError(f"{here} must be an object of schemas.", E_FORM)
        for name, sub in value.items():
            _check_node(sub, f"{here}/{name}", False, refs, allow_nonlocal)
    elif key == "required":
        if (not isinstance(value, list) or not all(isinstance(v, str) for v in value)
                or len(set(value)) != len(value)):
            raise SchemaError(f"{here} must be a list of distinct property names.", E_FORM)
    elif key in ("oneOf", "anyOf"):
        if not isinstance(value, list) or not value:
            raise SchemaError(f"{here} must be a non-empty list of schemas.", E_FORM)
        for i, sub in enumerate(value):
            _check_node(sub, f"{here}/{i}", False, refs, allow_nonlocal)
    elif key == "$ref":
        if not isinstance(value, str):
            raise SchemaError(f"{here} must be a string.", E_FORM)
        if _is_local(value):
            refs.append((here, value))
        elif not allow_nonlocal:
            raise SchemaError(f"The reference {value!r} at {here} is not local to the schema, "
                              f"which the subset cannot evaluate.", E_REFERENCE)
    elif key != "const" and not isinstance(value, str):
        # $id, $schema, title, description and version all take strings.
        raise SchemaError(f"{here} must be a string.", E_FORM)


def _resolve(root, ref: str):
    """The subschema a local reference points to, by RFC 6901 after percent-decoding."""
    node = root
    pointer = urllib.parse.unquote(ref[1:])
    tokens = pointer.split("/")[1:] if pointer else []
    for token in tokens:
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict) and token in node:
            node = node[token]
        elif isinstance(node, list) and token.isdigit() and int(token) < len(node):
            node = node[int(token)]
        else:
            raise SchemaError(f"The reference {ref!r} resolves to nothing in the schema.",
                              E_REFERENCE)
    if not isinstance(node, (dict, bool)):
        raise SchemaError(f"The reference {ref!r} resolves to {node!r}, which is not a schema.",
                          E_REFERENCE)
    return node


def check(schema, allow_nonlocal: bool = False) -> None:
    """Refuse a schema that uses anything outside the subset, is malformed, or has a local
    reference that resolves to nothing. With ``allow_nonlocal``, references that leave the
    schema are let through (and ``validate`` will still refuse them)."""
    refs: list = []
    _check_node(schema, "", True, refs, allow_nonlocal)
    for _, ref in refs:
        _resolve(schema, ref)


def dialect(schema) -> str | None:
    """The schema's declared ``$schema``, if any."""
    return schema.get("$schema") if isinstance(schema, dict) else None


def _is_number(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _has_type(name: str, v) -> bool:
    if name == "integer":
        return _is_number(v) and float(v).is_integer()
    if name == "number":
        return _is_number(v)
    return isinstance(v, {"object": dict, "array": list, "string": str, "boolean": bool,
                          "null": type(None)}[name])


def _equal(a, b) -> bool:
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if _is_number(a) and _is_number(b):
        return a == b
    if type(a) is not type(b):
        return False
    if isinstance(a, list):
        return len(a) == len(b) and all(_equal(x, y) for x, y in zip(a, b))
    if isinstance(a, dict):
        return a.keys() == b.keys() and all(_equal(a[k], b[k]) for k in a)
    return a == b


def _valid(root, node, instance, depth: int) -> bool:
    if isinstance(node, bool):
        return node
    if "$ref" in node:
        if depth >= MAX_REF_DEPTH:
            raise SchemaError(f"Evaluation followed more than {MAX_REF_DEPTH} nested references; "
                              f"the schema loops without consuming the instance.", E_DEPTH)
        if not _valid(root, _resolve(root, node["$ref"]), instance, depth + 1):
            return False
    if "type" in node:
        names = node["type"] if isinstance(node["type"], list) else [node["type"]]
        if not any(_has_type(n, instance) for n in names):
            return False
    if "const" in node and not _equal(node["const"], instance):
        return False
    if isinstance(instance, dict):
        if any(name not in instance for name in node.get("required", [])):
            return False
        for name, sub in node.get("properties", {}).items():
            # A property's value is a new instance, so references below it start afresh.
            if name in instance and not _valid(root, sub, instance[name], 0):
                return False
    if "anyOf" in node and not any(_valid(root, s, instance, depth) for s in node["anyOf"]):
        return False
    return "oneOf" not in node or sum(_valid(root, s, instance, depth) for s in node["oneOf"]) == 1


def validate(schema, instance) -> bool:
    """Whether ``instance`` is valid against ``schema``, after ``check(schema)``."""
    check(schema)
    return _valid(schema, schema, instance, 0)
