"""sedi-1's issuer: whether an issuance request must be issued or refused (choice issuer-issues;
docs/adapter-protocol.md, acdc.issue; this.i 2u2ps8mt).

An issuer issues exactly what a request asks for, so the runner grades what comes back by
verifying it. What a scenario decides here is only which way the case goes: a request must be
refused when a credential's attributes cannot satisfy its schema's attribute section once the
issuer has added the block's ``d``, ``u`` and ``i``, or when an edge asked for cannot hold between
the credentials as the request's roles issue them (an I2I edge needs the far credential issued to
the near one's issuer; NI2I always holds; an OR group needs one member, AND every one), or when
the registry kind asked for does not fit the schema (direct-issuance, this.i 92zkyy59): none
under a schema that admits rd leaves the credential uncommitted, and bup under one that forbids
rd leaves the ACDC unable to name its registry. Every other request must be issued. A request outside what this decides (an operator other than
I2I or NI2I, or a schema that constrains the d, u or i the issuer chooses) is a scenario error,
never a guessed direction.
"""

from keri_conformance import json_schema_subset as runner_js

from . import acdc_saids as sa
from . import json_schema_subset as js
from . import sedi_model as sm
from .errors import ScenarioError

# Placeholders of the right shape for what the issuer adds to an attribute block. The issuer
# chooses these values, so the decision first requires the schema to leave them free (_free), and
# then which placeholder stands in for them cannot change the verdict.
PLACEHOLDERS = {"d": "E" + "A" * 43, "u": "0A" + "A" * 22, "i": "E" + "B" * 43}
OPERATORS = ("I2I", "NI2I")
# What a schema may say of a value the issuer chooses and still leave it free.
FREE_KEYWORDS = {"type", "title", "description"}


def schema_doc(t, schema: dict) -> dict:
    """The schema with its ``$id`` set to its SAID, as a request carries it."""
    return {**schema, "$id": sa.schema_said(t, {**schema, "$id": ""})}


def _attributes(asked: dict, placeholders: dict) -> dict:
    block = {"d": placeholders["d"], "u": placeholders["u"]}
    if asked.get("issuee"):
        block["i"] = placeholders["i"]
    return {**block, **asked["attributes"]}


def _free(node, names) -> bool:
    """Whether a schema node leaves every one of ``names`` unconstrained but for being a string,
    on every branch an attribute block can be validated under. Anything it cannot prove free is
    not: a const, a reference, an additionalProperties schema that would apply to an unnamed one."""
    if isinstance(node, bool):
        return True
    if "const" in node or "$ref" in node:
        return False
    if not all(_free(sub, names) for key in ("oneOf", "anyOf") for sub in node.get(key, [])):
        return False
    props = node.get("properties", {})
    for name in names:
        sub = props.get(name, node.get("additionalProperties", True))
        if isinstance(sub, bool):
            continue  # a value either always allowed or always refused, whatever it is
        if set(sub) - FREE_KEYWORDS or sub.get("type", "string") != "string":
            return False
    return True


def _top_level_problem(schema: dict, asked: dict) -> str | None:
    """Why no ACDC an issuer could write satisfies the schema's top level, whatever the issuer
    does, or None. Asked only of a request whose registry kind fits its schema. The issuer
    writes v, t, d, i and s as strings it chooses, and rd when it is given a registry; a schema
    that refuses one of them, constrains it, or requires a field the issuance never carries
    decides nothing about the request."""
    kind = asked.get("registry", "bup")
    written = ["v", "t", "d", "i", "s"] + (["rd"] if kind != "none" else [])
    properties = schema.get("properties", {})
    for name in written:
        sub = properties.get(name, schema.get("additionalProperties", True))
        if sub is False:
            return f"refuses the {name} an issuer must write"
        if isinstance(sub, dict) and not _free({"properties": {name: sub}}, [name]):
            return f"constrains the {name} an issuer chooses"
    carried = {*written, "u", "a", *(["e"] if "edges" in asked else [])}
    beyond = sorted(set(schema.get("required", [])) - carried)
    if beyond:
        return f"requires {beyond[0]}, which the issuance does not carry"
    return None


def _operators(label: str, o) -> list[str]:
    if o is None:
        return []
    ops = [o] if isinstance(o, str) else o
    if not isinstance(ops, list) or any(op not in OPERATORS for op in ops):
        raise ScenarioError(f"The edge {label!r} asks for the operators {o!r}; the issuer "
                            "decision models only I2I and NI2I, as a string or a list.")
    return ops


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
        if "o" in member and member["o"] is None:
            raise ScenarioError(f"The edge {label!r} has an o of null.")
        ops = _operators(label, member.get("o"))
        relation = ops[-1] if ops else ("I2I" if far.get("issuee") else "NI2I")
        results.append(relation == "NI2I" or far.get("issuee") == near["issuer"])
    group = edges.get("o", "AND")
    if group not in ("AND", "OR"):
        raise ScenarioError(f"An edge group asks for the operator {group!r}; the issuer decision "
                            "models only AND and OR groups.")
    return any(results) if group == "OR" else all(results)


def refusal(schemas: dict, request: dict) -> str | None:
    """Why the request must be refused, or None when it must be issued. ``schemas`` maps each
    schema's SAID to the schema."""
    by_name = {c["name"]: c for c in request["credentials"]}
    reasons = []
    # Every credential is checked before any reason is returned, so a refusal found early never
    # hides a request the decision does not model.
    for asked in request["credentials"]:
        schema = schemas[asked["schema"]]
        js.check(schema)  # a schema outside the subset is a scenario error, coded
        direct = sm.forbids_rd(schema)
        if asked.get("registry") == "none" and not direct:
            reasons.append(f"the schema of {asked['name']} admits a registry, so it cannot be "
                           "issued without one")
        elif asked.get("registry") == "bup" and direct:
            reasons.append(f"the schema of {asked['name']} forbids rd, so it cannot name a "
                           "registry")
        else:
            problem = _top_level_problem(schema, asked)
            if problem:
                raise ScenarioError(f"The schema of {asked['name']} {problem}, so whether it "
                                    "must be refused is not decided by the request.")
        section = schema.get("properties", {}).get("a")
        if section is not None:
            chosen = ["d", "u", "i"] if asked.get("issuee") else ["d", "u"]
            if not _free(section, chosen):
                raise ScenarioError(f"The schema of {asked['name']} constrains the d, u or i an "
                                    "issuer chooses, so whether it must refuse is not decided by "
                                    "the request.")
            if not runner_js._valid(schema, section, _attributes(asked, PLACEHOLDERS), 0):
                reasons.append(f"the attributes of {asked['name']} do not satisfy its schema")
        if "edges" in asked and not _holds(asked["edges"], asked, by_name):
            reasons.append(f"the edges of {asked['name']} cannot hold as the request issues them")
    return reasons[0] if reasons else None
