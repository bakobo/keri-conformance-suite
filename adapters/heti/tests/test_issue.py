"""acdc.issue through heti: what heti issues comes back in the protocol's shape, and heti's own
verifier, through this adapter's acdc.verify, accepts it."""

import json
import pathlib

import pytest

from kcs_adapter_heti import issue, verify

SCHEMA = json.loads((pathlib.Path(__file__).parent / "fixtures" / "schema.json").read_text())


def request(*credentials, roles=("issuer", "holder")):
    return {"id": 1, "op": "acdc.issue", "roles": list(roles), "schemas": [SCHEMA["schema"]],
            "credentials": list(credentials)}


def credential(name, issuer="issuer", issuee="holder", **over):
    out = {"name": name, "issuer": issuer, "schema": SCHEMA["said"],
           "attributes": {"name": name}, "registry": "bup", **over}
    if issuee:
        out["issuee"] = issuee
    return out


def bundle(result, name, far=()):
    """An acdc.verify request for one issued credential, built from the issue result."""
    def registry(entry):
        chain = bytes.fromhex(entry["registry"])
        events = verify.split(chain)
        out, rest = [], chain[len(verify.GENUS):]
        while rest:
            _, raw, after = verify.split(rest)
            out.append(verify.GENUS + raw)
            rest = after
        disclosure = "-aA" + verify.B64[len(entry["disclosure"]) // 4] + entry["disclosure"]
        out[-1] += ("-CA" + verify.B64[len(disclosure) // 4] + disclosure).encode()
        assert events is not None
        return [{"stream": s.hex()} for s in out]

    entries = [result["credentials"][n] for n in (name, *far)]
    return {"perspective": {"role": "validator"},
            "kels": [{"stream": k} for k in result["kels"].values()],
            "registry": [r for e in entries for r in registry(e)],
            "schemas": [SCHEMA["schema"]],
            "acdcs": [{"stream": result["credentials"][n]["acdc"]} for n in far],
            "presented": {"stream": result["credentials"][name]["acdc"]}}


def test_heti_issues_a_credential_its_verifier_accepts():
    result = issue.issue(request(credential("core")))
    assert set(result["kels"]) == {"issuer", "holder"} and set(result["credentials"]) == {"core"}
    assert verify.verify(bundle(result, "core"))["verdict"] == "valid"


def test_heti_issues_a_chain_far_node_first():
    near = credential("guardian", issuer="holder", issuee=None,
                      edges={"core": {"credential": "core", "o": "I2I"}})
    result = issue.issue(request(near, credential("core")))
    acdc = verify.split(bytes.fromhex(result["credentials"]["guardian"]["acdc"]))[0]
    core = verify.split(bytes.fromhex(result["credentials"]["core"]["acdc"]))[0]
    assert acdc["e"]["core"]["n"] == core["d"] and acdc["e"]["core"]["o"] == "I2I"
    verdict = verify.verify(bundle(result, "guardian", far=("core",)))
    assert verdict["verdict"] == "valid"
    assert verdict["edges"] == [{"near": acdc["d"], "path": "e.core", "n": core["d"],
                                 "valid": True}]


def test_an_edge_group_keeps_its_operator():
    near = credential("guardian", issuer="holder", issuee=None,
                      edges={"g": {"o": "OR", "core": {"credential": "core"}}})
    result = issue.issue(request(near, credential("core")))
    acdc = verify.split(bytes.fromhex(result["credentials"]["guardian"]["acdc"]))[0]
    assert acdc["e"]["g"]["o"] == "OR"


def test_heti_refuses_an_issuance_it_cannot_make():
    result = issue.issue(request(credential("core", schema="E" + "A" * 43)))
    assert "refused" in result and "e." in result["refused"]["reason"]


@pytest.mark.parametrize("edges", [{"le": {"credential": "nope"}},
                                   {"g": {"le": {"credential": "nope"}}},
                                   {"le": {"credential": "n"}}])
def test_an_edge_to_a_credential_the_request_does_not_issue_is_malformed(edges):
    with pytest.raises(verify.Malformed, match="names no other credential"):
        issue.issue(request(credential("n", edges=edges)))


def test_a_credential_name_given_twice_is_malformed():
    with pytest.raises(verify.Malformed, match="twice"):
        issue.issue(request(credential("n"), credential("n")))


def test_edges_for_heti_pass_through_what_they_cannot_resolve():
    assert issue.edges({"le": {"credential": "nope"}}, {}, {}) == {"le": {"n": "nope", "s": ""}}
    assert issue.edges({"x": 7}, {}, {}) == {"x": 7}
    assert issue._named({"o": "OR", "x": 7, "le": {"credential": "a"}}) == ["a"]


def test_far_first_tolerates_cycles_and_unknown_names():
    order = issue.far_first([{"name": "a", "edges": {"le": {"credential": "a"}}},
                             {"name": "b", "edges": {"g": {"le": {"credential": "a"}}}},
                             {"name": "c", "edges": {"le": {"credential": "z"}}}])
    assert [c["name"] for c in order] == ["a", "b", "c"]


def test_an_uncoded_failure_inside_heti_is_an_adapter_error(monkeypatch):
    async def explode(self, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(issue.Lockbox, "mint", explode)
    with pytest.raises(RuntimeError, match="boom"):
        issue.issue(request(credential("core")))


@pytest.mark.parametrize("change", [
    lambda r: r.update(roles=[]),
    lambda r: r.update(roles=[7]),
    lambda r: r.update(credentials=[]),
    lambda r: r["credentials"][0].update(issuer="nobody"),
    lambda r: r["credentials"][0].update(issuee="nobody"),
    lambda r: r["credentials"][0].update(registry="upd"),
    lambda r: r["credentials"][0].update(attributes="x"),
    lambda r: r["credentials"][0].update(edges=[]),
    lambda r: r.update(schemas=[1]),
])
def test_a_malformed_issue_request_is_refused(change):
    r = request(credential("core"))
    change(r)
    with pytest.raises(verify.Malformed):
        issue.issue(r)
