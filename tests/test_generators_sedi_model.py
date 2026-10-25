"""The sedi-1 model validator: acdc_model's decision procedure under sedi-1's choices, graded
valid, invalid or incomplete (this.i 8fh68wt6).

Each test builds a bundle with the generator's builder from a small world of credentials, each
committed through its own blindable registry, and checks the verdict and every finding."""

import copy
import os
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sedi_world import AIDS, S1, cred, edge, presented_by, single, world

from generators.spec_tables import acdc_build as ab
from generators.spec_tables import acdc_model as am
from generators.spec_tables import sedi_model as sm
from generators.spec_tables import spec_source, tables
from generators.spec_tables.errors import ScenarioError

try:
    CESR_TEXT = spec_source.load_spec()
except spec_source.SpecUnavailable as e:
    if os.environ.get("KCS_REQUIRE_SPEC") == "1":
        raise
    pytest.skip(f"a pinned specification text is unavailable: {e}", allow_module_level=True)

T = tables.load(CESR_TEXT)
def run(frag):
    b = ab.build_bundle(T, frag)
    return sm.evaluate(T, b.request), b


def reasons(result):
    return sorted(f"{f.grade}/{f.reason}" for f in result.findings)


def test_a_credential_issued_through_its_registry_is_valid():
    result, b = run(world({"A": cred("I")}, "A"))
    assert result.verdict == sm.VALID and result.findings == []
    assert result.head.facts() == {"rd": b.saids["rip-A"], "n": 1, "d": b.saids["bup-A-1"],
                                   "td": b.saids["A"], "ts": "issued"}
    assert result.tags() == []


def test_both_accepted_seal_shapes_anchor():
    assert run(world({"A": cred("I")}, "A", shape="sd"))[0].verdict == sm.VALID


@pytest.mark.parametrize("seal,grade", [
    ({"shape": "d"}, "invalid"),
    ({"shape": "isd", "i": {"aid": "Q"}}, "invalid"),
    ({"shape": "isd", "i": {"aid": "I"}}, "invalid"),  # the issuer's prefix is not the registry
    ({"shape": "sd", "extra": {"x": "1"}}, "invalid"),
])
def test_a_seal_naming_the_event_in_another_shape_fails(seal, grade):
    frag = world({"A": cred("I")}, "A")
    frag["events"][-1]["a"] = [{"registry": "bup-A-1", **seal}]
    result, _ = run(frag)
    assert result.verdict == grade and reasons(result) == [f"{grade}/bup-anchor"]


def test_an_unanchored_or_absent_event_is_incomplete():
    frag = world({"A": cred("I")}, "A")
    frag["events"][-1]["a"] = []
    result, _ = run(frag)
    assert reasons(result) == ["incomplete/bup-anchor"] and result.head.n == 0
    frag = world({"A": cred("I")}, "A")
    frag["events"][-2]["a"] = []
    assert reasons(run(frag)[0]) == ["incomplete/rip-anchor"]


def test_the_issuer_kel_and_the_commitment():
    frag = world({"A": cred("I")}, "A")
    frag["kels"] = [k for k in frag["kels"] if not k["event"].startswith(("Iicp", "ixn"))]
    assert reasons(run(frag)[0]) == ["incomplete/issuer-kel"]
    frag = world({"A": cred("I")}, "A")
    del frag["acdcs"][0]["registry"]
    frag["acdcs"][0]["source_seal"] = None
    assert reasons(run(frag)[0]) == ["invalid/no-registry"]



# -- direct issuance (direct-issuance, this.i 947dh20t) --------------------------------------------

CLOSED = {"additionalProperties": False,
          "properties": {**{f: {"type": "string"} for f in ("v", "t", "d", "u", "i", "s")},
                         "a": S1["properties"]["a"]}}


def direct(seal=None, schema=CLOSED):
    """A's credential issued with no registry, under ``schema`` laid over S1, anchored by
    ``seal`` (an {"acdc": "A"} seal spec) in an interaction event of I's KEL, or by nothing."""
    frag = world({"A": cred("I")}, "A")
    del frag["acdcs"][0]["registry"]
    frag["registries"] = []
    frag["events"] = [e for e in frag["events"] if e["t"] == "icp"]
    frag["kels"] = [k for k in frag["kels"] if k["event"].endswith("icp")]
    frag["schemas"][0]["schema"].update(copy.deepcopy(schema))
    if seal is not None:
        frag["events"].append({"name": "ixn-A", "aid": "I", "t": "ixn", "a": [seal]})
        frag["kels"].append({"event": "ixn-A", "sigs": ["I0"]})
    return frag


def test_a_credential_whose_schema_forbids_rd_is_committed_by_its_digest_seal():
    result, _ = run(direct({"acdc": "A"}))
    assert result.verdict == sm.VALID and result.findings == [] and result.head is None
    assert reasons(run(direct())[0]) == ["incomplete/direct-anchor"]
    assert reasons(run(direct({"acdc": "A", "extra": {"s": "0"}}))[0]) == ["invalid/direct-seal"]


def test_a_seal_of_another_shape_beside_the_digest_seal_does_not_spoil_it():
    frag = direct({"acdc": "A", "extra": {"s": "0"}})
    frag["events"][-1]["a"].append({"acdc": "A"})
    assert run(frag)[0].verdict == sm.VALID


def test_no_rd_under_a_schema_that_admits_one_is_uncommitted():
    # S1 lists no rd but leaves its top level open, so it admits one.
    assert reasons(run(direct({"acdc": "A"}, schema={}))[0]) == ["invalid/no-registry"]
    listed = {"properties": {**CLOSED["properties"], "rd": {"type": "string"}},
              "additionalProperties": False}
    assert reasons(run(direct({"acdc": "A"}, schema=listed))[0]) == ["invalid/no-registry"]


def test_without_its_schema_a_credential_without_rd_is_left_to_the_schema_finding():
    frag = direct({"acdc": "A"})
    frag["omit"] = ["S1"]
    assert reasons(run(frag)[0]) == ["incomplete/schema-absent"]


@pytest.mark.parametrize("schema,forbids", [
    ({}, False),
    ({"additionalProperties": True}, False),
    ({"additionalProperties": False}, True),
    ({"additionalProperties": False, "properties": {"rd": {"type": "string"}}}, False),
    # A closing subschema may admit some registry SAID, whichever SAIDs it refuses.
    ({"additionalProperties": {"type": "integer"}}, False),
    ({"additionalProperties": {"const": "EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}, False),
    ({"additionalProperties": "no"}, False),
])
def test_which_schemas_forbid_rd(schema, forbids):
    assert sm.forbids_rd(schema) is forbids


def test_the_registry_inception():
    frag = world({"A": cred("I")}, "A", )
    frag["registries"][0]["alter"] = [{"path": "dt", "value": "2026-07-04T17:50:00.000000+00:00"}]
    assert "invalid/rip-said" in reasons(run(frag)[0])
    frag = world({"A": cred("I")}, "A")
    frag["registries"][0]["issuer"] = "Q"
    frag["events"][len(AIDS)]["aid"] = "Q"
    frag["kels"][len(AIDS)]["sigs"] = ["Q0"]
    assert reasons(run(frag)[0]) == ["invalid/rip-issuer"]
    frag = world({"A": cred("I")}, "A")
    frag["omit"] = ["rip-A"]
    assert reasons(run(frag)[0]) == ["incomplete/registry-absent"]
    frag = world({"A": cred("I")}, "A")
    frag["registries"][0]["alter"] = [{"path": "t", "value": "vcp"}]
    assert reasons(run(frag)[0]) == ["incomplete/registry-kind"]


def test_revocation_and_the_head():
    result, _ = run(world({"A": cred("I", states=("issued", "revoked"))}, "A"))
    assert reasons(result) == ["invalid/revoked"] and result.head.n == 2
    result, _ = run(world({"A": cred("I", states=("issued", "revoked", "issued"))}, "A"))
    assert result.verdict == sm.VALID and result.head.n == 3
    result, _ = run(world({"A": cred("I", states=("pending",))}, "A"))
    assert reasons(result) == ["incomplete/registry-state"]


def test_withheld_and_undisclosed_updates_are_never_valid():
    frag = world({"A": cred("I", states=("issued", "issued", "revoked"))}, "A")
    frag["omit"] = ["bup-A-2"]
    frag["registries"][3]["prior"] = "bup-A-1"
    frag["registries"][3]["n"] = 3
    result, _ = run(frag)
    # n=3 names n=1 as its prior, so it skipped n=2 whether or not n=2 exists: a failed check.
    # n=2's seal is still in the KEL, so its absence is also anchored evidence unseen.
    assert reasons(result) == ["incomplete/registry-unseen", "invalid/bup-sequence"]
    assert result.verdict == sm.INVALID and result.head.n == 1
    # n=3 chaining to the withheld n=2 is only a gap.
    frag = world({"A": cred("I", states=("issued", "issued", "revoked"))}, "A")
    frag["omit"] = ["bup-A-2"]
    result, _ = run(frag)
    assert reasons(result) == ["incomplete/registry-gap", "incomplete/registry-unseen"]
    # An unanchored event at the skipped n does not hide the skip.
    frag = world({"A": cred("I", states=("issued", "issued"))}, "A")
    frag["registries"][2]["n"] = 3
    frag["registries"].append({"name": "bup-A-x", "t": "bup", "registry": "rip-A", "n": 2,
                               "prior": "bup-A-1", "disclose": True,
                               "state": {"u": "x", "td": {"acdc": "A"}, "ts": "revoked"}})
    assert reasons(run(frag)[0]) == ["invalid/bup-sequence"]
    # The first update claims n=2 with the inception as its prior.
    frag = world({"A": cred("I")}, "A")
    frag["registries"][1]["n"] = 2
    assert reasons(run(frag)[0]) == ["invalid/bup-sequence"]
    # n=2 withheld and nothing after it in the bundle, but a third event anchored in the KEL.
    frag = world({"A": cred("I", states=("issued", "issued", "revoked"))}, "A")
    frag["omit"] = ["bup-A-2", "bup-A-3"]
    result, _ = run(frag)
    assert reasons(result) == ["incomplete/registry-unseen"]
    frag = world({"A": cred("I", states=("issued", "revoked"))}, "A")
    frag["registries"][2]["disclose"] = False
    result, _ = run(frag)
    assert reasons(result) == ["incomplete/registry-state"] and result.head.n == 2


def test_registry_checks_that_fail():
    frag = world({"A": cred("I", states=("issued", "revoked"))}, "A")
    frag["registries"][2].update(prior="rip-A", n=2)
    assert reasons(run(frag)[0]) == ["invalid/bup-prior"]
    frag = world({"A": cred("I", states=("issued", "revoked"))}, "A")
    frag["registries"][2]["alter"] = [{"path": "dt", "value": "2026-07-04T17:50:00.000000+00:00"}]
    # An event whose SAID does not verify also accounts for none of the seals naming it.
    assert reasons(run(frag)[0]) == ["incomplete/registry-unseen", "invalid/bup-said"]
    frag = world({"A": cred("I", states=("issued", "revoked"))}, "A")
    frag["registries"][2]["alter"] = [{"path": "t", "value": "upd"}]
    assert reasons(run(frag)[0]) == ["incomplete/registry-unseen", "invalid/registry-kind-mixed"]
    frag = world({"A": cred("I", states=("issued", "revoked"))}, "A")
    frag["registries"][2]["n"] = 0
    assert reasons(run(frag)[0]) == ["invalid/bup-sn"]
    frag = world({"A": cred("I")}, "A")
    frag["registries"][1]["disclose"] = {"ts": "revoked", "blid": "own"}
    assert reasons(run(frag)[0]) == ["invalid/blid-other"]


def test_two_events_anchored_at_one_n_are_refused():
    frag = world({"A": cred("I", states=("issued",))}, "A")
    frag["registries"].append({"name": "bup-A-x", "t": "bup", "registry": "rip-A", "n": 1,
                               "prior": "rip-A", "disclose": True,
                               "state": {"u": "x", "td": {"acdc": "A"}, "ts": "revoked"}})
    frag["events"].append({"name": "ixn-x", "aid": "I", "t": "ixn",
                           "a": [{"registry": "bup-A-x", "shape": "isd"}]})
    frag["kels"].append({"event": "ixn-x", "sigs": ["I0"]})
    assert reasons(run(frag)[0]) == ["invalid/registry-duplicity"]
    # The same second event unanchored is ignored: the head is the anchored one.
    frag["events"][-1]["a"] = []
    assert run(frag)[0].verdict == sm.VALID


def test_a_registry_head_for_another_credential():
    frag = world({"A": cred("I")}, "A")
    frag["registries"][1]["state"]["td"] = {"nothing": "B"}
    assert reasons(run(frag)[0]) == ["invalid/registry-state"]


# -- edges ----------------------------------------------------------------------------------------

def test_a_valid_one_hop_chain():
    result, _ = run(world(single(), "N"))
    assert result.verdict == sm.VALID, result.tags()


@pytest.mark.parametrize("o,verdict,found", [
    ("I2I", "valid", []),
    (["I2I"], "valid", []),
    (None, "valid", []),
    ([], "valid", []),
    ("NI2I", "valid", []),
    ("DI2I", "valid", []),
    (["NI2I", "I2I"], "valid", []),
    ("XYZ", "incomplete", ["incomplete/operator-unknown"]),
    (["I2I", "XYZ"], "incomplete", ["incomplete/operator-unknown"]),
    ("NOT", "incomplete", ["incomplete/operator-unknown"]),
    ([1], "incomplete", ["incomplete/operator-shape"]),
    ({"x": "I2I"}, "incomplete", ["incomplete/operator-shape"]),
    ([["I2I"]], "invalid", ["invalid/operator-shape"]),
])
def test_unary_operator_shapes(o, verdict, found):
    result, _ = run(world(single(o=o), "N"))
    assert result.verdict == verdict and reasons(result) == found


def test_the_issuer_relation():
    # F issued by Q to R, so N's issuer I is not F's issuee.
    creds = single()
    creds["F"] = cred("Q", "R")
    assert reasons(run(world(creds, "N"))[0]) == ["invalid/i2i-issuee"]
    creds["N"]["e"]["le"]["o"] = ["I2I", "NI2I"]
    assert run(world(creds, "N"))[0].verdict == sm.VALID
    creds["N"]["e"]["le"]["o"] = ["NI2I", "I2I"]
    assert reasons(run(world(creds, "N"))[0]) == ["invalid/i2i-issuee"]
    creds["N"]["e"]["le"]["o"] = "DI2I"
    assert reasons(run(world(creds, "N"))[0]) == ["invalid/di2i-issuee"]
    # Untargeted F: the default is NI2I, and an explicit I2I fails.
    creds = single(o=None)
    creds["F"] = cred("Q", None)
    assert run(world(creds, "N"))[0].verdict == sm.VALID
    creds["N"]["e"]["le"]["o"] = "I2I"
    assert reasons(run(world(creds, "N"))[0]) == ["invalid/i2i-untargeted"]


def test_di2i_admits_a_delegate_of_the_far_issuee():
    """D, delegated by R, issues N; F is issued to R."""
    def delegation():
        return [{"name": "Rixn", "aid": "R", "t": "ixn", "a": [{"event": "Dicp"}],
                 "sigs": ["R0"]},
                {"name": "Dicp", "aid": "D", "t": "dip", "keys": ["D0"], "next": ["D1"],
                 "delegator": "R", "sigs": ["D0"]}]
    creds = {"F": cred("Q", "R"), "N": cred("D", "H", e={"d": "", "le": edge("F", "DI2I")})}
    result, _ = run(world(creds, "N", extra_aids=delegation()))
    assert result.verdict == sm.VALID, result.tags()
    creds["N"]["e"]["le"]["o"] = "I2I"
    assert reasons(run(world(creds, "N", extra_aids=delegation()))[0]) == ["invalid/i2i-issuee"]


def test_e1e_binds_the_two_issuees():
    creds = {"F": cred("Q", "H"), "N": cred("I", "H", e={"d": "", "le": edge("F", "E1E")})}
    assert run(world(creds, "N"))[0].verdict == sm.VALID
    creds["F"] = cred("Q", "R")
    assert reasons(run(world(creds, "N"))[0]) == ["invalid/e1e-issuee"]
    creds["F"] = cred("Q", None)
    assert reasons(run(world(creds, "N"))[0]) == ["invalid/e1e-issuee"]


def test_hidden_issuees_cannot_be_evaluated():
    hidden = {"name": "F", "A": [{"d": "", "u": {"nonce": "f1"}, "i": {"aid": "I"}},
                                 {"d": "", "u": {"nonce": "f2"}, "x": 1}],
              "form": {"disclose": [1]}}
    frag = world(single(), "N")
    far = next(a for a in frag["acdcs"] if a["name"] == "F")
    del far["a"]
    far.update(hidden)
    frag["schemas"][0]["schema"]["required"] = ["v", "d", "i", "s"]
    result, _ = run(frag)
    assert reasons(result) == ["incomplete/i2i-hidden"]
    near = next(a for a in frag["acdcs"] if a["name"] == "N")
    near["e"]["le"]["o"] = "E1E"
    assert reasons(run(frag)[0]) == ["incomplete/e1e-hidden"]
    far["form"] = {"disclose": [0]}
    near["e"]["le"]["o"] = "I2I"
    assert run(frag)[0].verdict == sm.VALID


@pytest.mark.parametrize("o", ["I2I", None])
@pytest.mark.parametrize("far_issuee", ["I", "R"])
def test_a_far_attribute_block_presented_compact_hides_the_issuee(o, far_issuee):
    """A compact a may or may not hold an issuee, so neither I2I nor the default operator can be
    decided, whoever the far node was issued to; read as untargeted, the default would append
    NI2I and pass an edge to a credential issued to someone else."""
    creds = single(o=o)
    creds["F"] = cred("Q", far_issuee)
    frag = world(creds, "N")
    next(a for a in frag["acdcs"] if a["name"] == "F")["form"] = {"compact": ["a"]}
    assert reasons(run(frag)[0]) == ["incomplete/i2i-hidden"]
    creds["N"]["e"]["le"]["o"] = "E1E"
    frag = world(creds, "N")
    next(a for a in frag["acdcs"] if a["name"] == "F")["form"] = {"compact": ["a"]}
    assert reasons(run(frag)[0]) == ["incomplete/e1e-hidden"]


def test_edge_blocks_carry_their_own_said():
    frag = world(single(d=None), "N")
    assert reasons(run(frag)[0]) == ["invalid/edge-said"]


def test_a_far_node_that_is_absent_fails_or_is_revoked():
    frag = world(single(), "N")
    frag["omit"] = ["F"]
    assert reasons(run(frag)[0]) == ["incomplete/far-absent"]
    creds = single()
    creds["F"] = cred("Q", "I", states=("issued", "revoked"))
    assert reasons(run(world(creds, "N"))[0]) == ["invalid/revoked"]
    creds = single(s={"schema": "S1"})
    assert run(world(creds, "N"))[0].verdict == sm.VALID
    frag = world(single(), "N")
    frag["schemas"].append({"name": "S2", "schema": {**S1, "required": ["v", "d", "i", "s", "zz"],
                                                     "title": "other"}})
    next(a for a in frag["acdcs"] if a["name"] == "N")["e"]["le"]["s"] = {"schema": "S2"}
    assert reasons(run(frag)[0]) == ["invalid/edge-schema"]


def test_a_revoked_middle_node_breaks_the_head():
    creds = {"T": cred("R", "Q"), "F": cred("Q", "I", e={"d": "", "le": edge("T")},
                                           states=("issued", "revoked")),
             "N": cred("I", "H", e={"d": "", "le": edge("F")})}
    assert reasons(run(world(creds, "N"))[0]) == ["invalid/revoked"]
    creds["F"]["states"] = ("issued",)
    assert run(world(creds, "N"))[0].verdict == sm.VALID


def test_groups_and_or():
    creds = {"F": cred("Q", "I"), "G": cred("R", "I", states=("issued", "revoked")),
             "N": cred("I", "H", e={"d": "", "o": "OR", "f": edge("F"), "g": edge("G")})}
    assert run(world(creds, "N"))[0].verdict == sm.VALID
    creds["N"]["e"]["o"] = "AND"
    assert reasons(run(world(creds, "N"))[0]) == ["invalid/revoked"]
    del creds["N"]["e"]["o"]
    assert reasons(run(world(creds, "N"))[0]) == ["invalid/revoked"]
    # OR: an unresolved alternative and a valid one is valid; a failed and an unresolved one is
    # invalid (failure-precedence).
    creds["N"]["e"] = {"d": "", "o": "OR", "f": edge("F", "XYZ"), "g": edge("G")}
    assert reasons(run(world(creds, "N"))[0]) == ["incomplete/operator-unknown",
                                                  "invalid/revoked"]
    assert run(world(creds, "N"))[0].verdict == sm.INVALID
    creds["G"]["states"] = ("issued",)
    assert run(world(creds, "N"))[0].verdict == sm.VALID
    del creds["G"]
    creds["N"]["e"] = {"d": "", "o": "OR", "f": edge("F", "XYZ")}
    assert run(world(creds, "N"))[0].verdict == sm.INCOMPLETE


@pytest.mark.parametrize("e,found", [
    ({"d": "", "o": "OR"}, ["invalid/group-empty"]),
    ({"d": ""}, ["invalid/group-empty"]),
    ({"d": "", "o": "NAND", "f": edge("F")}, ["incomplete/group-operator"]),
    ({"d": "", "grp": {"d": "", "o": "AND"}}, ["invalid/group-empty"]),
    ({"d": "", "grp": {"d": "", "o": "OR", "f": edge("F")}}, []),
])
def test_group_shapes(e, found):
    creds = {"N": cred("I", "H", e=e)}
    if "n" in str(e):
        creds["F"] = cred("Q", "I")
    assert reasons(run(world(creds, "N"))[0]) == found


def test_compact_edges_cannot_be_evaluated():
    frag = world(single(), "N")
    near = next(a for a in frag["acdcs"] if a["name"] == "N")
    near["form"] = {"compact": ["e.le"]}
    assert reasons(run(frag)[0]) == ["incomplete/edge-compact"]
    near["form"] = {"compact": ["e"]}
    assert reasons(run(frag)[0]) == ["incomplete/edge-compact"]


def test_a_cycle_and_a_diamond():
    creds = {"T": cred("R", "Q"), "F": cred("Q", "I", e={"d": "", "le": edge("T")}),
             "G": cred("Q", "I", e={"d": "", "le": edge("T")}),
             "N": cred("I", "H", e={"d": "", "f": edge("F"), "g": edge("G")})}
    assert run(world(creds, "N"))[0].verdict == sm.VALID
    _, b = run(world(creds, "N"))
    req = b.request
    model = sm._SediModel(T, req)
    node = model.far[b.saids["F"]][0]
    state = {node.said: None}
    # A node reached while its own verdict is open is a cycle.
    assert model.edge(node.body, {"d": "x", "n": b.saids["T"], "o": "NI2I"}, "p",
                      lambda n: state.get(n.said) or (sm.INVALID, [sm.Finding(
                          sm.INVALID, n.said, "cycle")]))[0] == sm.INVALID


def test_presented_bytes_that_do_not_frame():
    _, b = run(world({"A": cred("I")}, "A"))
    req = copy.deepcopy(b.request)
    req["presented"]["stream"] = req["presented"]["stream"][:-20]
    result = sm.evaluate(T, req)
    assert result.verdict == sm.INVALID and reasons(result) == ["invalid/unframeable"]


def test_helpers():
    assert sm.combine([]) == sm.VALID
    assert sm.combine([sm.INCOMPLETE, sm.VALID], "OR") == sm.VALID
    assert sm.combine([sm.INCOMPLETE, sm.INVALID], "OR") == sm.INVALID
    assert sm.combine([sm.INCOMPLETE], "OR") == sm.INCOMPLETE
    assert sm.issuee(None) is None and sm.issuee({"a": "Ecompact"}) is ...
    assert sm.issuee({"A": ["agid"]}) is None and sm.issuee({"A": ["agid", "Eblock"]}) is ...
    assert [sm._sn(x) for x in ("1", "a", "0", "01", "", "A", "zz", 5)] == [
        1, 10, 0, None, None, None, None, None]
    assert sm.Finding(sm.INVALID, "x", "y").tag == "invalid/x/y"


def test_the_builder_refuses_an_unknown_seal_shape():
    frag = world({"A": cred("I")}, "A")
    frag["events"][-1]["a"] = [{"registry": "bup-A-1", "shape": "sdx"}]
    with pytest.raises(ScenarioError, match="shape"):
        ab.build_bundle(T, frag)


def sealed_unseen(frag, registry, n, **seal):
    """``frag`` with an update of ``registry`` at ``n`` that the bundle omits, sealed in an
    interaction event of I's KEL as ``seal`` describes."""
    name = f"phantom-{registry}-{n}"
    frag["registries"].append({"name": name, "t": "bup", "registry": registry, "n": n,
                               "prior": registry, "disclose": True,
                               "state": {"u": name, "td": {"acdc": "A"}, "ts": "revoked"}})
    frag["omit"] = frag.get("omit", []) + [name]
    frag["events"].append({"name": f"ixn-{name}", "aid": "I", "t": "ixn",
                           "a": [{"registry": name, **seal}]})
    frag["kels"].append({"event": f"ixn-{name}", "sigs": ["I0"]})
    return frag


@pytest.mark.parametrize("n,seal", [
    (1, {"shape": "sd"}),  # a second couple at the head's own n
    (2, {"shape": "sd", "extra": {"s": "02"}}),  # an n that is not canonical
    (2, {"shape": "sd", "extra": {"s": ""}}),
    (1, {"shape": "isd", "extra": {"s": "0"}}),  # this registry, at any n
])
def test_a_seal_whose_event_the_bundle_lacks_is_never_valid(n, seal):
    frag = sealed_unseen(world({"A": cred("I")}, "A"), "rip-A", n, **seal)
    assert reasons(run(frag)[0]) == ["incomplete/registry-unseen"]


def test_an_event_seal_naming_another_registry_is_not_this_registrys():
    frag = world({"A": cred("I", states=("issued", "issued"))}, "A")
    frag["registries"].append({"name": "rip-B", "t": "rip", "issuer": "I"})
    frag["omit"] = ["rip-B"]
    frag = sealed_unseen(frag, "rip-B", 5, shape="isd")
    assert run(frag)[0].verdict == sm.VALID


def test_a_withheld_couple_below_the_head_may_be_a_second_update_there():
    frag = sealed_unseen(world({"A": cred("I", states=("issued", "issued"))}, "A"), "rip-A", 1,
                         shape="sd")
    assert reasons(run(frag)[0]) == ["incomplete/registry-unseen"]


def test_a_known_event_sealed_at_another_s_names_an_absent_event():
    frag = world({"A": cred("I")}, "A")
    frag["events"].append({"name": "ixn-x", "aid": "I", "t": "ixn",
                           "a": [{"registry": "bup-A-1", "shape": "sd", "extra": {"s": "2"}}]})
    frag["kels"].append({"event": "ixn-x", "sigs": ["I0"]})
    assert reasons(run(frag)[0]) == ["incomplete/registry-unseen"]


def test_an_event_seal_is_accounted_for_only_by_an_event_of_its_registry():
    frag = world({"A": cred("I")}, "A")
    frag["registries"] += [
        {"name": "rip-B", "t": "rip", "issuer": "I"},
        {"name": "bup-B-1", "t": "bup", "registry": "rip-B", "disclose": True,
         "state": {"u": "s-B-0", "td": {"acdc": "A"}, "ts": "issued"}}]
    # I's KEL seals B's update as if it were A's: an event seal naming A's registry at s=1, whose
    # d is the SAID of an event the bundle carries, but of B's registry.
    frag["events"].append({"name": "ixn-x", "aid": "I", "t": "ixn",
                           "a": [{"registry": "bup-B-1", "shape": "isd",
                                  "i": {"registry": "rip-A"}}]})
    frag["kels"].append({"event": "ixn-x", "sigs": ["I0"]})
    assert reasons(run(frag)[0]) == ["incomplete/registry-unseen"]


def test_a_carried_event_that_does_not_verify_accounts_for_nothing():
    _, b = run(world({"A": cred("I")}, "A"))
    model = sm._SediModel(T, b.request)
    rd = b.saids["rip-A"]
    issuer = model.node(bytes.fromhex(b.request["presented"]["stream"]))[0].body["i"]
    model.registry_streams.append(({"d": "Ex", "n": ["1"], "t": "bup"}, b"", []))
    model.registry_streams.append(({"d": "Ey", "n": "1", "rd": rd, "t": "bup"}, b"", []))
    model.registry_streams.append(({"d": "Ez", "n": "1", "x": "\ud800", "t": "bup"}, b"", []))
    head, problems = model.head(rd, issuer)
    assert head.n == 1 and "registry-unseen" not in [r for _, r in problems]


def test_a_seal_whose_d_is_not_a_string_names_nothing_the_bundle_holds():
    frag = sealed_unseen(world({"A": cred("I")}, "A"), "rip-A", 1, shape="sd",
                         extra={"d": ["x"]})
    assert reasons(run(frag)[0]) == ["incomplete/registry-unseen"]


def test_an_empty_group_is_invalid_whatever_its_operator():
    creds = {"N": cred("I", "H", e={"d": "", "g": {"d": "", "o": "XOR"}})}
    assert reasons(run(world(creds, "N"))[0]) == ["invalid/group-empty"]


def test_an_unknown_group_operator_does_not_hide_a_failure_inside_it():
    creds = {"F": cred("Q", "I", states=("issued", "revoked")),
             "N": cred("I", "H", e={"d": "", "g": {"d": "", "o": "XOR", "le": edge("F")}})}
    result, _ = run(world(creds, "N"))
    assert result.verdict == sm.INVALID
    assert reasons(result) == ["incomplete/group-operator", "invalid/revoked"]


def test_a_node_reached_by_two_paths_reports_once():
    diamond = {"G": cred("R", "Q", states=("issued", "revoked")),
               "F1": cred("Q", "I", e={"d": "", "le": edge("G")}),
               "F2": cred("Q", "I", e={"d": "", "le": edge("G")}),
               "N": cred("I", "H", e={"d": "", "le1": edge("F1"), "le2": edge("F2")})}
    assert reasons(run(world(diamond, "N"))[0]) == ["invalid/revoked"]


def test_a_registry_is_walked_once_per_model():
    _, b = run(world({"A": cred("I")}, "A"))
    model = sm._SediModel(T, b.request)
    issuer = b.expanded["A"]["i"]
    first = model.head(b.saids["rip-A"], issuer)
    assert model.head(b.saids["rip-A"], issuer) is first and first[0].n == 1


def test_the_model_rests_on_the_acdc_model():
    assert issubclass(sm._SediModel, am._Model)


def test_an_unevaluable_operator_never_hides_a_failure_beside_it():
    creds = single(o="XYZ")
    creds["F"] = cred("Q", "I", states=("issued", "revoked"))
    result, _ = run(world(creds, "N"))
    assert result.verdict == sm.INVALID
    assert reasons(result) == ["incomplete/operator-unknown", "invalid/revoked"]
    creds = single(o=["XYZ", "I2I"])
    creds["F"] = cred("Q", "R")
    assert reasons(run(world(creds, "N"))[0]) == ["incomplete/operator-unknown",
                                                  "invalid/i2i-issuee"]
    creds = single(o=[1])
    creds["F"] = cred("Q", "R")
    assert reasons(run(world(creds, "N"))[0]) == ["incomplete/operator-shape",
                                                  "invalid/i2i-issuee"]


def test_an_edge_schema_absent_from_the_bundle_cannot_be_evaluated():
    frag = world(single(), "N")
    frag["schemas"].append({"name": "S2", "schema": {**S1, "title": "other"}})
    next(a for a in frag["acdcs"] if a["name"] == "N")["e"]["le"]["s"] = {"schema": "S2"}
    frag["omit"] = ["S2"]
    result, _ = run(frag)
    assert result.verdict == sm.INCOMPLETE and reasons(result) == ["incomplete/edge-schema-absent"]


# -- the presentation context (this.i 09snlyre, 7krs5hfz) ------------------------------------------


def grant(frag):
    return frag["presentation"]["exchanges"][0]


@pytest.mark.parametrize("sender,found", [("H", []), ("R", ["invalid/presenter"]),
                                          ("I", ["invalid/presenter"])])
def test_the_presenter_is_bound_to_the_issuee(sender, found):
    result, _ = run(presented_by(world({"A": cred("I")}, "A"), sender))
    assert reasons(result) == found
    assert result.verdict == (sm.VALID if not found else sm.INVALID)


def test_an_untargeted_credential_is_a_bearer_credential():
    result, _ = run(presented_by(world({"A": cred("I", None)}, "A"), "R"))
    assert result.verdict == sm.VALID


def test_an_issuee_the_presentation_hides_cannot_be_bound():
    frag = presented_by(world({"A": cred("I")}, "A"), "H")
    frag["acdcs"][0]["form"] = {"compact": ["a"]}
    result, _ = run(frag)
    assert result.verdict == sm.INCOMPLETE and reasons(result) == ["incomplete/presenter-undisclosed"]


def test_a_grant_to_another_verifier_is_a_replay():
    result, _ = run(presented_by(world({"A": cred("I")}, "A"), "H", receiver="W"))
    assert reasons(result) == ["invalid/presentation-verifier"]


@pytest.mark.parametrize("a", [{"o": []}, {"o": [{"nothing": "other"}]}, "flat",
                               {"o": [{"acdc": "A"}, {"acdc": "A"}]}])
def test_the_grant_must_name_exactly_the_presented_acdc(a):
    frag = presented_by(world({"A": cred("I")}, "A"), "H")
    grant(frag)["a"] = a
    assert reasons(run(frag)[0]) == ["invalid/presentation-names"]


@pytest.mark.parametrize("change", [
    {"r": "/kcs/exchange"},
    {"t": "xip", "nonce": "n", "x": None, "p": None},
])
def test_only_a_grant_presents(change):
    frag = presented_by(world({"A": cred("I")}, "A"), "H")
    spec = grant(frag)
    spec.update(change)
    for field in [k for k, v in change.items() if v is None]:
        del spec[field]
    result, _ = run(frag)
    assert result.verdict == sm.INVALID and reasons(result) == ["invalid/presentation-not-grant"]


def test_a_grant_the_exchange_model_refuses_proves_no_presenter():
    frag = presented_by(world({"A": cred("I")}, "A"), "H")
    frag["presentation"]["messages"][0]["sigs"] = []
    result, _ = run(frag)
    assert result.verdict == sm.INVALID and reasons(result) == ["invalid/grant-unsigned"]


def test_without_a_context_the_presenter_is_not_judged():
    frag = presented_by(world({"A": cred("I")}, "A"), "R")
    del frag["presentation"]
    assert run(frag)[0].verdict == sm.VALID


@pytest.mark.parametrize("change,words", [
    (lambda p: p.update(extra=1), "unknown fields"),
    (lambda p: p.update(messages=[]), "at least one message"),
])
def test_the_builder_refuses_a_malformed_presentation(change, words):
    frag = presented_by(world({"A": cred("I")}, "A"), "H")
    change(frag["presentation"])
    with pytest.raises(ScenarioError, match=words):
        ab.build_bundle(T, frag)


# -- group codes (seal-couple-code, blind-state-code) ---------------------------------------------


def with_update(**over):
    frag = world({"A": cred("I")}, "A")
    next(r for r in frag["registries"] if r["name"] == "bup-A-1").update(over)
    return frag


@pytest.mark.parametrize("over,found", [
    ({"source_seal": {"event": "ixn-bup-A-1"}}, []),
    ({"source_seal": {"event": "ixn-bup-A-1", "code": "-T"}}, ["invalid/bup-attachments"]),
    ({"block_code": "--a"}, []),
    ({"block_code": "--a9"}, ["invalid/bup-attachments"]),
])
def test_sedi_reads_a_couple_at_s_and_a_big_state_at_eight_characters(over, found):
    assert reasons(run(with_update(**over))[0]) == found


def test_an_inception_whose_attachments_sedi_cannot_read_fails():
    frag = world({"A": cred("I")}, "A")
    frag["registries"][0]["source_seal"] = {"event": "ixn-rip-A", "code": "-T"}
    assert reasons(run(frag)[0]) == ["invalid/rip-attachments"]


def test_an_acdc_whose_attachments_sedi_cannot_read_fails():
    frag = world({"A": cred("I")}, "A")
    frag["acdcs"][0]["source_seal"] = {"event": "ixn-bup-A-1", "code": "-T"}
    assert reasons(run(frag)[0]) == ["invalid/attachments"]
    frag["acdcs"][0]["source_seal"] = "ixn-bup-A-1"
    assert run(frag)[0].verdict == sm.VALID


@pytest.mark.parametrize("text,words", [
    ("-dAA", "unknown count code"),
    ("-!", "not text-domain"),
    ("-AAA", "not one attachments group"),
    ("-CAC", "not one attachments group"),
    ("-CAB-TAA", "does not read the group -T"),
])
def test_the_attachments_reader_refuses_what_sedi_does_not_read(text, words):
    assert sm.attachments(T, "") == []
    with pytest.raises(ValueError, match=words):
        sm.attachments(T, text)


@pytest.mark.parametrize("over,words", [
    ({"source_seal": {"event": "ixn-bup-A-1", "code": "-Z"}}, "a couple's code is -S or -T"),
    ({"block_code": "-z"}, "is not -a, --a or --a9"),
])
def test_the_builder_refuses_an_unknown_code(over, words):
    with pytest.raises(ScenarioError, match=words):
        ab.build_bundle(T, with_update(**over))


SN, DIG = "0A" + "A" * 22, "E" + "A" * 43


def couple_group(item: str) -> str:
    """An attachments group holding one -S group of ``item``, which is 68 characters."""
    return "-CAS-SAR" + item


def test_a_seal_source_couple_is_a_sequence_number_then_a_digest():
    assert sm.attachments(T, couple_group(SN + DIG)) == []
    for item, words in ((DIG + SN, "sequence number and a digest"),
                        ("4AAG" + "A" * 20 + DIG, "variable size"),
                        (SN + "E!" + "A" * 42, "not text-domain"),
                        ("0A_" + "A" * 21 + DIG, "canonically encoded"),
                        (SN + "E_" + "A" * 42, "canonically encoded")):
        with pytest.raises(ValueError, match=words):
            sm.attachments(T, couple_group(item))


def test_a_couple_pointing_at_another_event_is_only_a_pointer():
    """A source couple names where to look; the seal is still found on the issuer's trunk
    (docs/design.md, ACDC step 4), so one naming another event changes nothing."""
    frag = with_update(source_seal={"event": "ixn-rip-A"})
    assert run(frag)[0].verdict == sm.VALID


# -- keripy 1.x shapes (no-1x) -----------------------------------------------------------------


def test_a_1x_version_string_or_field_set_is_never_valid():
    frag = world({"A": cred("I")}, "A")
    frag["acdcs"][0]["version"] = "1.x"
    result, b = run(frag)
    assert reasons(result) == ["invalid/unframeable"]
    assert bytes.fromhex(b.request["presented"]["stream"])[8:24] == b'{"v":"ACDC10JSON'
    frag = world({"A": cred("I")}, "A")
    frag["acdcs"][0]["fields"] = "1.x"
    result, b = run(frag)
    # Its SAID is recomputed over the 1.x field set, so only the field set fails.
    assert reasons(result) == ["invalid/field-order", "invalid/no-registry"]
    assert set(b.forms["A"]) >= {"ri"} and not {"rd", "t"} & set(b.forms["A"])
    assert b.dag["root"] == b.forms["A"]["d"] == b.saids["A"]
    # The field set precedes the SAID, so the registry's td, which names the ACDC's SAID,
    # names the body presented, and so does an edge to it.
    assert b.expanded["A"]["d"] == b.saids["A"]
    chain = world(single(), "N")
    chain["acdcs"] = [{**a, "fields": "1.x"} if a["name"] == "F" else a for a in chain["acdcs"]]
    _, b = run(chain)
    assert b.dag["edges"][0]["n"] == b.forms["F"]["d"]


@pytest.mark.parametrize("tamper", [{"protocol": "KERI"}, {"declared_size": "compact"}])
def test_a_1x_shape_does_not_combine_with_another_version_tamper(tamper):
    frag = world({"A": cred("I")}, "A")
    frag["acdcs"][0].update(fields="1.x", **tamper)
    with pytest.raises(ScenarioError, match="combines a 1.x shape"):
        ab.build_bundle(T, frag)


@pytest.mark.parametrize("key", ["version", "fields"])
def test_the_builder_knows_only_the_1x_shape(key):
    frag = world({"A": cred("I")}, "A")
    frag["acdcs"][0][key] = "3.x"
    with pytest.raises(ScenarioError, match="the only one is 1.x"):
        ab.build_bundle(T, frag)


# -- bounds (choice bounds, this.i 7qx6tl5p) ------------------------------------------------------


def test_the_models_maxima_are_the_profiles():
    source = (ROOT / "scenarios" / "sedi" / "profile.json").read_text(encoding="utf-8")
    import json
    assert json.loads(source)["maxima"] == sm.MAXIMA


@pytest.mark.parametrize("body,reason", [
    ({"a": {"d": "E", "name": "x" * 4096}}, None),
    ({"a": {"d": "E", "name": "x" * 4097}}, "bound-attribute-bytes"),
    ({"a": {"d": "E", "list": ["\u00e9" * 2049]}}, "bound-attribute-bytes"),  # bytes, not chars
    ({"A": ["agid"] + ["E"] * 32}, None),
    ({"A": ["agid"] + ["E"] * 33}, "bound-aggregate-blocks"),
    ({"A": ["agid", {"d": "E", "v": "y" * 4097}]}, "bound-attribute-bytes"),
    ({"a": {"d": "E", "many": ["x" * 3000, "y" * 3000]}}, "bound-attribute-bytes"),  # one value
    ({"a": {"d": "E", "sub": {"d": "E", "v": "z" * 4097}}}, "bound-attribute-bytes"),
    # a nested block is one value, measured whole though no field of it is past the maximum
    ({"a": {"d": "E", "profile": {"d": "E", "x": "p" * 3000, "y": "q" * 3000}}},
     "bound-attribute-bytes"),
    ({"a": {"d": "E", "u": {"hidden": "h" * 5000}}}, "bound-salt-chars"),  # not a string
    ({"a": {"d": "E", "u": "0A" + "A" * 22}}, None),
    ({"a": {"d": "E", "u": "0B" + "A" * 46}}, "bound-salt-chars"),
    ({"u": "x" * 45}, "bound-salt-chars"),
    ({"e": {"d": "E", "o": "OR", "fine": {"d": "E", "n": "EF"},
            "long": {"d": "E", "n": "EF", "o": ["I2I"] * 9}}}, "bound-operator-list"),
    ({"e": {"d": "E", "a.b.c.d.e.f.g.h": {"d": "E", "n": "EF"}}}, None),  # a label, not depth
    ({}, None),
])
def test_a_credential_past_a_maximum_is_named(body, reason):
    assert sm._past_bounds(body) == reason



def test_groups_nested_past_the_maximum_depth_are_refused_whatever_their_operator():
    group = {"d": "E", "le": {"d": "E", "n": "EF"}}
    for _ in range(sm.MAXIMA["edge_group_depth"] - 1):
        group = {"d": "E", "o": "OR", "g": group}
    assert sm._past_bounds({"e": group}) is None
    assert sm._past_bounds({"e": {"d": "E", "o": "OR", "g": group}}) == "bound-edge-group-depth"


def test_a_registry_salt_or_blind_past_the_maximum_is_refused():
    frag = world({"A": cred("I")}, "A")
    frag["registries"][0]["u"] = {"literal": "0B" + "A" * 46}
    assert reasons(run(frag)[0]) == ["invalid/bound-salt-chars"]



def test_a_literal_registry_salt_must_be_a_string():
    frag = world({"A": cred("I")}, "A")
    frag["registries"][0]["u"] = {}
    with pytest.raises(ScenarioError, match="a literal salt"):
        ab.build_bundle(T, frag)



def test_a_far_credential_past_a_maximum_behind_an_unused_or_is_not_hidden():
    big = cred("Q", "I")
    creds = {"F": cred("Q", "I"), "G": big,
             "N": cred("I", "H", e={"d": "", "g": {"d": "", "o": "OR", "le1": edge("F"),
                                                    "le2": edge("G")}})}
    frag = world(creds, "N")
    next(a for a in frag["acdcs"] if a["name"] == "G")["a"]["name"] = "x" * 4097
    result, _ = run(frag)
    assert result.verdict == sm.INVALID and reasons(result) == ["invalid/bound-attribute-bytes"]



def test_a_far_registry_past_the_maximum_behind_an_unused_or_is_not_hidden():
    creds = {"F": cred("Q", "I"), "G": cred("Q", "I", states=("issued",) * 64),
             "N": cred("I", "H", e={"d": "", "g": {"d": "", "o": "OR", "le1": edge("F"),
                                                    "le2": edge("G")}})}
    result, _ = run(world(creds, "N"))
    assert result.verdict == sm.INVALID and "invalid/bound-registry-events" in reasons(result)


def test_a_second_entry_claiming_a_far_nodes_said_is_still_bounded():
    _, b = run(world(single(), "N"))
    said = b.saids["F"]
    oversized = world(single(), "N")
    far = next(a for a in oversized["acdcs"] if a["name"] == "F")
    far["a"]["name"] = "x" * 4097
    far["alter"] = [{"path": "d", "value": said}]  # claims the first far node's SAID
    _, big = run(oversized)
    request = {**b.request, "acdcs": b.request["acdcs"] + big.request["acdcs"]}
    result = sm.evaluate(T, request)
    assert result.verdict == sm.INVALID and "invalid/bound-attribute-bytes" in reasons(result)



def test_the_bundle_check_passes_over_a_registry_stream_it_cannot_read():
    _, b = run(world({"A": cred("I")}, "A"))
    request = {**b.request, "registry": b.request["registry"] + [{"stream": "00"}]}
    assert sm.evaluate(T, request).verdict == sm.VALID
