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
    # n=2's seal is still in the KEL, so its absence is also anchored evidence unseen.
    assert reasons(result) == ["incomplete/registry-gap", "incomplete/registry-unseen"]
    assert result.head.n == 1
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
    assert reasons(run(frag)[0]) == ["invalid/bup-said"]
    frag = world({"A": cred("I", states=("issued", "revoked"))}, "A")
    frag["registries"][2]["alter"] = [{"path": "t", "value": "upd"}]
    assert reasons(run(frag)[0]) == ["invalid/registry-kind-mixed"]
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
    assert sm.issuee(None) is None and sm.issuee({"a": "Ecompact"}) is None
    assert sm.issuee({"A": ["agid"]}) is None and sm.issuee({"A": ["agid", "Eblock"]}) is ...
    assert [sm._sn(x) for x in ("1", "a", "0", "01", "", "A", "zz", 5)] == [
        1, 10, 0, None, None, None, None, None]
    assert sm.Finding(sm.INVALID, "x", "y").tag == "invalid/x/y"


def test_the_builder_refuses_an_unknown_seal_shape():
    frag = world({"A": cred("I")}, "A")
    frag["events"][-1]["a"] = [{"registry": "bup-A-1", "shape": "sdx"}]
    with pytest.raises(ScenarioError, match="shape"):
        ab.build_bundle(T, frag)


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
