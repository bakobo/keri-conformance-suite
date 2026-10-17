"""The sedi-1x-interop companion's cases (test-plan item 11; this.i 9sgwng6m): acdc.verify cases
over keripy 1.x issuances the suite builds (keripy1x_issue), each graded at INTEROP on what keripy
1.2.14 concludes. The scenario states each expected verdict; generators/keripy1x_check/
check_acdc.py confirms keripy 1.2.14 reaches it, so a disagreement is found, never absorbed.

A scenario's fixtures are issuance specs (keripy1x_issue.Issuance). A schema in one is given
inline, or as ``{"from": NAME}`` for an entry of the scenario's own ``schemas`` table, which holds
each shared schema with ``copy_of``, the committed file it copies (a test holds the two equal), so
a scenario never reads outside itself. A ``from`` may add ``"shape": "2.x"``: the KERI 2.0 shape that interop/two-wallets/INCOMPATIBILITIES.md entry 7 says
SEDI publishes, derived from the 1.x profile by that entry's own mapping run backwards (top-level
``ri`` back to ``rd``, ``t`` restored, and ``e`` and ``r`` required again). ``"allow_dt": true``
names ``dt`` in the attribute section, which the SEDI profile closes without it, and
``"edge_section_u": false`` stops requiring the edge section's own ``u``, which keripy 1.x reads
as an edge.
"""

import copy

from . import keripy1x
from .errors import ScenarioError
from .keripy1x_issue import Issuance

PROFILE = "sedi-1x-interop"
GENERATOR = {"name": "kcs-gen-sedi1x", "version": "0.1.0"}
FEATURES = sorted(["acdc.keripy-1x", "acdc.ptel-1x", "cesr.genus-1.00", "cesr.serialization.json",
                   "crypto.ed25519", "kel.basic", "keri.version-1.x"])
WIRE = ["CESR-1.00", "KERI10JSON", "ACDC10JSON"]
VERDICTS = ("valid", "invalid", "incomplete")
CASE_FIELDS = {"id", "key", "title", "description", "fixture", "presented", "expected", "basis",
               "triage", "pair"}
REQUIRED = CASE_FIELDS - {"pair"}


def two_x(schema: dict) -> dict:
    """The KERI 2.0 shape of a 1.x profile schema (INCOMPATIBILITIES.md entry 7, backwards)."""
    out = copy.deepcopy(schema)
    props = out["properties"]
    rd = props.pop("ri")
    out["properties"] = {"v": props.pop("v"), "t": {"description": "Message type",
                                                     "type": "string"},
                         **{k: props[k] for k in ("d", "u", "i")}, "rd": rd,
                         **{k: v for k, v in props.items() if k not in ("d", "u", "i")}}
    out["required"] = ["v", "d", "i", "rd", "s", "a", "e", "r"]
    return out


def _schemas(library: dict, schemas: dict) -> dict:
    out = {}
    for name, schema in schemas.items():
        if isinstance(schema, dict) and "from" in schema:
            if schema["from"] not in library:
                raise ScenarioError(f"The schema {name!r} is from {schema['from']!r}, which the "
                                    "scenario's schemas table does not hold.")
            loaded = copy.deepcopy(library[schema["from"]]["schema"])
            loaded.pop("$id", None)
            if schema.get("allow_dt"):
                detail = loaded["properties"]["a"]["oneOf"][1]
                detail["properties"]["dt"] = {"description": "Issuance date-time",
                                              "type": "string"}
            if schema.get("edge_section_u") is False:
                detail = loaded["properties"]["e"]["oneOf"][1]
                detail["required"] = [r for r in detail["required"] if r != "u"]
            schema = two_x(loaded) if schema.get("shape") == "2.x" else loaded
        out[name] = schema
    return out


def build_case(t, rel: str, fixtures: dict, case: dict, pairs: dict,
               library: dict | None = None) -> dict:
    """One case, from its scenario entry and the fixture it names."""
    missing = REQUIRED - set(case)
    if missing:
        raise ScenarioError(f"{case.get('id')}: needs {sorted(missing)}.")
    if set(case) - CASE_FIELDS:
        raise ScenarioError(f"{case['id']}: unknown fields {sorted(set(case) - CASE_FIELDS)}.")
    if case["expected"] not in VERDICTS:
        raise ScenarioError(f"{case['id']}: {case['expected']!r} is not a verdict.")
    if case["fixture"] not in fixtures:
        raise ScenarioError(f"{case['id']}: the fixture {case['fixture']!r} is not defined.")
    spec = dict(fixtures[case["fixture"]])
    spec["schemas"] = _schemas(library or {}, spec["schemas"])
    issuance = Issuance(t, spec)
    request = issuance.request(case["presented"])
    description = case["description"]
    if "pair" in case:
        if case["pair"] not in pairs:
            raise ScenarioError(f"{case['id']}: its pair {case['pair']!r} is not a case here.")
        description += (f" Its positive pair is {case['pair']} ({pairs[case['pair']]}), which "
                        "differs from it only in the defect.")
    basis = (f"keripy {keripy1x.KERIPY_1X_VERSION} (commit {keripy1x.KERIPY_1X_COMMIT}): "
             f"{case['basis']}")
    return {
        "schema_version": 1,
        "id": case["id"],
        "title": case["title"],
        "description": description,
        "status": "draft",
        "profile": PROFILE,
        "targets": {"wire": WIRE, "features": FEATURES},
        "operation": "acdc.verify",
        "input": request,
        "dag": issuance.dag(case["presented"]),
        "as_of": issuance.as_of,
        "assertions": [{"id": "a1", "check": "verdict", "expected": case["expected"],
                        "level": "INTEROP", "basis": basis}],
        "provenance": {"scenario": f"{rel}#{case['key']}", "generator": GENERATOR,
                       "reference": keripy1x.REFERENCE},
    }
