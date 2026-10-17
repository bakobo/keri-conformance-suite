"""sedi-1's issuer decision (choice issuer-issues): which way an acdc.issue case goes, issued or
refused, from the request and its schemas alone."""

import pytest

from generators.spec_tables import sedi_issue
from generators.spec_tables.errors import GeneratorError

ATTRS = {"type": "object", "required": ["d", "u", "name"], "additionalProperties": False,
         "properties": {"d": {"type": "string"}, "u": {"type": "string"},
                        "i": {"type": "string"}, "name": {"type": "string"}}}
SCHEMA = {"$id": "ES", "type": "object", "properties": {"a": ATTRS}}
OPEN = {"$id": "EO", "type": "object"}
SCHEMAS = {"ES": SCHEMA, "EO": OPEN}


def cred(name, issuer, issuee=None, schema="ES", **over):
    c = {"name": name, "issuer": issuer, "schema": schema, "attributes": {"name": name}}
    if issuee:
        c["issuee"] = issuee
    return {**c, **over}


def request(*credentials):
    return {"roles": ["issuer", "holder", "other"], "credentials": list(credentials)}


def test_a_request_within_its_schema_is_issued():
    assert sedi_issue.refusal(SCHEMAS, request(cred("core", "issuer", "holder"))) is None
    assert sedi_issue.refusal(SCHEMAS, request(cred("x", "issuer", schema="EO"))) is None


def test_an_attribute_the_schema_forbids_is_refused():
    asked = cred("core", "issuer", "holder", attributes={"name": "core", "extra": 1})
    assert "do not satisfy its schema" in sedi_issue.refusal(SCHEMAS, request(asked))


@pytest.mark.parametrize("edges,far_issuee,refused", [
    ({"core": {"credential": "core", "o": "I2I"}}, "holder", False),
    ({"core": {"credential": "core", "o": "I2I"}}, "other", True),
    ({"core": {"credential": "core", "o": ["I2I", "NI2I"]}}, "other", False),  # latest wins
    ({"core": {"credential": "core"}}, "other", True),  # default I2I for a targeted far node
    ({"core": {"credential": "core"}}, None, False),  # default NI2I for an untargeted one
    ({"o": "OR", "a": {"credential": "core", "o": "I2I"},
      "b": {"credential": "core", "o": "NI2I"}}, "other", False),
    ({"g": {"o": "AND", "a": {"credential": "core", "o": "I2I"}}}, "other", True),
])
def test_an_edge_that_cannot_hold_is_refused(edges, far_issuee, refused):
    req = request(cred("core", "issuer", far_issuee),
                  cred("guardian", "holder", edges=edges))
    assert (sedi_issue.refusal(SCHEMAS, req) is not None) is refused


def test_a_schema_outside_the_subset_is_a_generator_error():
    with pytest.raises(GeneratorError):
        sedi_issue.refusal({"EX": {"$id": "EX", "not": {}}},
                           request(cred("x", "issuer", schema="EX")))
