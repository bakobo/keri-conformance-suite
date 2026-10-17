"""sedi-1's issuer: whether an issuance request must be issued or refused (choice issuer-issues;
docs/adapter-protocol.md, acdc.issue; this.i 2u2ps8mt).

An issuer issues exactly what a request asks for, so the runner grades what comes back by
verifying it. What a scenario decides here is only which way the case goes: a request must be
refused when a credential's attributes cannot satisfy its schema's attribute section once the
issuer has added the block's ``d``, ``u`` and ``i``, or when an edge asked for cannot hold between
the credentials as the request's roles issue them (an I2I edge needs the far credential issued to
the near one's issuer; NI2I always holds; an OR group needs one member, AND every one). Every
other request must be issued. A request outside what this decides (an operator other than
I2I or NI2I, or a schema that constrains the d, u or i the issuer chooses) is a scenario error,
never a guessed direction.
"""

from keri_conformance import json_schema_subset as runner_js

from . import acdc_saids as sa
from . import json_schema_subset as js
from .errors import ScenarioError

# Two sets of placeholders of the right shape for what the issuer adds to an attribute block. The
# issuer chooses these values, so a schema whose verdict differs between the two constrains them,
# and the decision cannot say which way the case goes.
PLACEHOLDERS = ({"d": "E" + "A" * 43, "u": "0A" + "A" * 22, "i": "E" + "B" * 43},
                {"d": "E" + "C" * 43, "u": "0A" + "D" * 22, "i": "E" + "F" * 43})
OPERATORS = ("I2I", "NI2I")


def schema_doc(t, schema: dict) -> dict:
    """The schema with its ``$id`` set to its SAID, as a request carries it."""
    return {**schema, "$id": sa.schema_said(t, {**schema, "$id": ""})}


def _attributes(asked: dict, placeholders: dict) -> dict:
    block = {"d": placeholders["d"], "u": placeholders["u"]}
    if asked.get("issuee"):
        block["i"] = placeholders["i"]
    return {**block, **asked["attributes"]}


def _holds(edges: dict, near: dict, by_name: dict) -> bool:
    """Whether an edge section (or group) asked for can hold."""
    results = []
    for label, member in edges.items():
        if label == "o":
            continue
        if "credential" not in member:
            results.append(_holds(member, near, by_name))
            continue
        far = by_name[member["credential"]]
        ops = member.get("o", [])
        ops = [ops] if isinstance(ops, str) else list(ops)
        beyond = [op for op in ops if op not in OPERATORS]
        if beyond:
            raise ScenarioError(f"The edge {label!r} asks for the operators {beyond}; the issuer "
                                "decision models only I2I and NI2I.")
        relation = next((op for op in reversed(ops) if op in OPERATORS), None)
        if relation is None:
            relation = "I2I" if far.get("issuee") else "NI2I"
        results.append(relation == "NI2I" or far.get("issuee") == near["issuer"])
    return any(results) if edges.get("o") == "OR" else all(results)


def refusal(schemas: dict, request: dict) -> str | None:
    """Why the request must be refused, or None when it must be issued. ``schemas`` maps each
    schema's SAID to the schema."""
    by_name = {c["name"]: c for c in request["credentials"]}
    for asked in request["credentials"]:
        schema = schemas[asked["schema"]]
        js.check(schema)  # a schema outside the subset is a scenario error, coded
        section = schema.get("properties", {}).get("a")
        if section is not None:
            fits = {runner_js._valid(schema, section, _attributes(asked, p), 0)
                    for p in PLACEHOLDERS}
            if len(fits) > 1:
                raise ScenarioError(f"The schema of {asked['name']} constrains the d, u or i an "
                                    "issuer chooses, so whether it must refuse is not decided by "
                                    "the request.")
            if fits == {False}:
                return f"the attributes of {asked['name']} do not satisfy its schema"
        if "edges" in asked and not _holds(asked["edges"], asked, by_name):
            return f"the edges of {asked['name']} cannot hold as the request issues them"
    return None
