"""The ACDC generator's builders: registry events (rip, bup) with their seals in the issuer's KEL,
ACDCs in each disclosure form, and the acdc.verify request bundle (docs/adapter-protocol.md).

No case is built here. These tests pin what a bundle contains and the bounds and refusals that
keep a scenario from describing a bundle the protocol forbids."""

import json
import os
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from generators.spec_tables import acdc_build as ab
from generators.spec_tables import acdc_saids as sa
from generators.spec_tables import json_schema_subset as js
from generators.spec_tables import keri_events, spec_source, tables
from generators.spec_tables.errors import GeneratorError, ScenarioError

try:
    CESR_TEXT = spec_source.load_spec()
except spec_source.SpecUnavailable as e:
    if os.environ.get("KCS_REQUIRE_SPEC") == "1":
        raise
    pytest.skip(f"a pinned specification text is unavailable: {e}", allow_module_level=True)

T = tables.load(CESR_TEXT)
GENUS = "-_AAACAA"

S1 = {"$id": "", "$schema": js.DIALECT, "title": "S1", "version": "1.0.0", "type": "object",
      "required": ["v", "d", "i", "s", "a"],
      "properties": {"a": {"oneOf": [{"type": "string"},
                                     {"type": "object", "required": ["d", "i", "name"],
                                      "properties": {"name": {"type": "string"}}}]}}}


def icp(aid, key):
    return {"name": f"{aid}icp", "aid": aid, "t": "icp", "keys": [key], "next": [key + "n"]}


def ixn(name, aid, seals):
    return {"name": name, "aid": aid, "t": "ixn", "a": seals}


def deliver(*names, key="i0"):
    return [{"event": n, "sigs": [key]} for n in names]


def direct(**over):
    """I issues A1 to H directly: a digest seal of A1's most compact SAID in I's ixn1."""
    frag = {
        "events": [icp("I", "i0"), icp("H", "h0"), ixn("ixn1", "I", [{"acdc": "A1"}])],
        "kels": deliver("Iicp", "ixn1") + deliver("Hicp", key="h0"),
        "schemas": [{"name": "S1", "schema": S1}],
        "acdcs": [{"name": "A1", "issuer": "I", "schema": "S1",
                   "a": {"d": "", "i": {"aid": "H"}, "name": "Zoe"}, "source_seal": "ixn1"}],
        "presented": "A1",
    }
    frag.update(over)
    return frag


def stream(entry) -> bytes:
    return bytes.fromhex(entry["stream"])


def body(entry) -> tuple[dict, str]:
    """A stream's body as a map, and the attachment text after it."""
    data = stream(entry)
    assert data.startswith(GENUS.encode())
    text = data[len(GENUS):].decode()
    obj, end = json.JSONDecoder().raw_decode(text)
    return obj, text[end:]


# -- registry events ------------------------------------------------------------------------------

def test_rip_reproduces_the_spec_example_at_line_2239():
    rip = ab.rip(T, "ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf", "0ABhY2Rjc3BlY3dvcmtyYXcx",
                 dt="2025-07-04T17:51:00.000000+00:00")
    assert list(rip) == list(ab.RIP_FIELDS)
    assert rip["d"] == "ECOWJI9kAjpCFYJ7RenpJx2w66-GsGlhyKLO-Or3qOIQ"
    assert rip["n"] == "0"


def test_bup_reproduces_the_spec_example_at_line_2295():
    bup = ab.bup(T, rd="ECOWJI9kAjpCFYJ7RenpJx2w66-GsGlhyKLO-Or3qOIQ", n=2,
                 prior="EPNwyvHp2XJsz9pSpXtHtcCmzw6bKSFc-nhGKTbso0Yg",
                 b="EOtWw6X_aoOJlkzNaLj23IC6MXHl7ZSYSWVulFW_Hr_t",
                 dt="2020-08-02T12:00:20.000000+00:00")
    assert list(bup) == list(ab.BUP_FIELDS)
    assert bup["d"] == "EBdytzDC4dnatn-6mrCWLSGuM62LM0BgS31YnAg5NTeW"
    assert ab.bup(T, rd="x", n=26, prior="y", b="z")["n"] == "1a"  # hex, no leading zeros


def test_nonces_are_deterministic_qualified_salts():
    assert ab.nonce(T, "a") == ab.nonce(T, "a") != ab.nonce(T, "b")
    assert ab.nonce(T, "a").startswith("0A") and len(ab.nonce(T, "a")) == 24
    assert ab.blind(T, "a").startswith("a") and len(ab.blind(T, "a")) == 44


# -- a directly issued ACDC -----------------------------------------------------------------------

def test_a_directly_sealed_acdc_bundle():
    b = ab.build_bundle(T, direct())
    req = b.request
    assert set(req) == {"kels", "registry", "schemas", "acdcs", "presented"}
    assert req["registry"] == [] and req["acdcs"] == []
    # Every stream leads with the genus/version code; schemas are raw compact JSON.
    for entry in req["kels"] + [req["presented"]]:
        assert stream(entry).startswith(GENUS.encode())
    assert [k["source"] for k in req["kels"]] == ["I", "I", "H"]
    schema = json.loads(bytes.fromhex(req["schemas"][0]))
    assert bytes.fromhex(req["schemas"][0]) == sa.serialize(schema)
    assert schema["$id"] == sa.schema_said(T, schema) == b.saids["S1"]
    js.check(schema)
    # The presented ACDC is compact by default, sized to itself, sealed by its SAID in ixn1.
    acdc, attachments = body(req["presented"])
    assert list(acdc) == ["v", "t", "d", "i", "s", "a"]
    assert acdc["t"] == "acm" and acdc["s"] == b.saids["S1"]
    assert acdc["d"] == b.saids["A1"] == sa.acdc_said(T, b.forms["A1"])
    assert acdc["v"] == sa.version_string(len(sa.serialize(acdc)))
    assert isinstance(acdc["a"], str)
    ixn1, _ = body(req["kels"][1])
    assert ixn1["a"] == [{"d": b.saids["A1"]}]
    # The attachment points at ixn1: -C group, -S seal source couple (sequence number, SAID).
    sn = "0A" + "A" * 21 + "B"
    assert attachments == "-CAS" + "-SAR" + sn + ixn1["d"]
    # The issuee resolves to H's prefix.
    assert b.expanded["A1"]["a"]["i"] == body(req["kels"][2])[0]["i"]


def test_the_case_input_and_evaluation_point():
    frag = direct()
    frag["registries"] = [{"name": "rip1", "t": "rip", "issuer": "I"}]
    b = ab.build_bundle(T, frag)
    assert b.case_input() == {"perspective": {"role": "validator"}, **b.request}
    assert b.dag == {"root": b.saids["A1"], "edges": []}
    i, h = b.expanded["A1"]["i"], b.expanded["A1"]["a"]["i"]
    assert b.as_of == {i: 1, h: 0, b.saids["rip1"]: 0}


def test_an_acdc_without_a_source_seal_has_no_attachments():
    frag = direct()
    del frag["acdcs"][0]["source_seal"]
    _, attachments = body(ab.build_bundle(T, frag).request["presented"])
    assert attachments == ""


@pytest.mark.parametrize("form,shape", [
    ("expanded", dict),
    ("compact", str),
    ({"compact": ["a"]}, str),
    ({"compact": []}, dict),
])
def test_every_form_has_the_same_said_and_its_own_size(form, shape):
    frag = direct()
    frag["acdcs"][0]["form"] = form
    b = ab.build_bundle(T, frag)
    acdc, _ = body(b.request["presented"])
    assert isinstance(acdc["a"], shape)
    assert acdc["v"] == sa.version_string(len(sa.serialize(acdc)))
    assert sa.acdc_said(T, acdc) == acdc["d"] == ab.build_bundle(T, direct()).saids["A1"]


def test_a_nested_block_can_be_compacted_by_path():
    frag = direct()
    frag["acdcs"][0]["a"]["inner"] = {"d": "", "u": {"nonce": "x"}, "lei": "L"}
    frag["acdcs"][0]["form"] = {"compact": ["a.inner"]}
    b = ab.build_bundle(T, frag)
    acdc, _ = body(b.request["presented"])
    assert acdc["a"]["inner"] == sa.block_said(T, b.expanded["A1"]["a"]["inner"])
    assert acdc["a"]["d"] == sa.block_said(T, b.expanded["A1"]["a"])
    assert sa.acdc_said(T, acdc) == b.saids["A1"]


def test_a_private_acdc_carries_a_top_level_nonce_and_no_t_when_asked():
    frag = direct()
    frag["acdcs"][0].update({"u": "top", "t": None})
    acdc, _ = body(ab.build_bundle(T, frag).request["presented"])
    assert list(acdc) == ["v", "d", "u", "i", "s", "a"]
    assert acdc["u"] == ab.nonce(T, "top")


def test_a_selectively_disclosable_acdc():
    frag = direct()
    blocks = [{"d": "", "u": {"nonce": f"b{i}"}, "x": i} for i in range(3)]
    acdc_spec = frag["acdcs"][0]
    del acdc_spec["a"]
    acdc_spec.update({"A": blocks, "form": {"disclose": [1]}})
    b = ab.build_bundle(T, frag)
    acdc, _ = body(b.request["presented"])
    full = b.expanded["A1"]["A"]
    assert full[0] == sa.aggregate(T, full[1:])[0]
    assert acdc["A"][0] == full[0]
    assert acdc["A"][2] == full[2] and isinstance(acdc["A"][1], str) and isinstance(acdc["A"][3], str)
    assert sa.acdc_said(T, acdc) == b.saids["A1"]
    frag["acdcs"][0]["form"] = "compact"
    assert body(ab.build_bundle(T, frag).request["presented"])[0]["A"] == full[0]


# -- registries -----------------------------------------------------------------------------------

def registry(**over):
    frag = direct(
        events=[icp("I", "i0"), icp("H", "h0"), ixn("ixn1", "I", [{"registry": "rip1"}]),
                ixn("ixn2", "I", [{"registry": "bup1"}])],
        kels=deliver("Iicp", "ixn1", "ixn2") + deliver("Hicp", key="h0"),
        registries=[
            {"name": "rip1", "t": "rip", "issuer": "I", "u": "r", "source_seal": "ixn1"},
            {"name": "bup1", "t": "bup", "registry": "rip1", "source_seal": "ixn2",
             "state": {"u": "s1", "td": {"acdc": "A1"}, "ts": "issued"}, "disclose": True},
        ],
    )
    frag["acdcs"][0].update({"registry": "rip1"})
    del frag["acdcs"][0]["source_seal"]
    frag.update(over)
    return frag


def test_a_blindable_registry_bundle():
    b = ab.build_bundle(T, registry())
    req = b.request
    rip, rip_att = body(req["registry"][0])
    bup, bup_att = body(req["registry"][1])
    acdc, _ = body(req["presented"])
    assert list(acdc) == ["v", "t", "d", "i", "rd", "s", "a"]
    assert rip["i"] == b.expanded["A1"]["i"] and rip["n"] == "0"
    assert acdc["rd"] == rip["d"] == bup["rd"] == bup["p"] == b.saids["rip1"]
    assert bup["n"] == "1" and bup["d"] == b.saids["bup1"]
    block = sa.blinded_block(T, ab.blind(T, "s1"), b.saids["A1"], "issued")
    assert bup["b"] == block[:44]
    # Seals in I's KEL: a transaction event seal {s, d} per event.
    ixn1, _ = body(req["kels"][1])
    ixn2, _ = body(req["kels"][2])
    assert ixn1["a"] == [{"s": "0", "d": rip["d"]}]
    assert ixn2["a"] == [{"s": "1", "d": bup["d"]}]
    # Attachments: the seal source couple, then the disclosed blinded state quadruple.
    sn1 = "0A" + "A" * 21 + "C"
    assert bup_att == "-CA2" + "-SAR" + sn1 + ixn2["d"] + "-aAj" + block
    assert rip_att.startswith("-CAS-SAR")


def test_registry_overrides_and_an_undisclosed_block():
    frag = registry()
    frag["registries"].append({"name": "bup2", "t": "bup", "registry": "rip1", "prior": "rip1",
                               "n": 3, "dt": "2026-01-01T00:00:00.000000+00:00",
                               "state": {"u": "s2", "td": "", "ts": ""}})
    b = ab.build_bundle(T, frag)
    bup2, att = body(b.request["registry"][2])
    assert (bup2["n"], bup2["p"], att) == ("3", b.saids["rip1"], "")
    assert bup2["b"] == sa.blid(T, ab.blind(T, "s2"), "", "")


def test_an_omitted_registry_event_leaves_the_bundle_and_the_evaluation_point():
    b = ab.build_bundle(T, registry(omit=["bup1"]))
    assert [body(e)[0]["t"] for e in b.request["registry"]] == ["rip"]
    assert b.as_of[b.saids["rip1"]] == 0
    assert ab.build_bundle(T, registry()).as_of[b.saids["rip1"]] == 1


def test_the_ts_reading_reaches_the_bup():
    other = sa.Readings(ts_code="bytes")
    a = ab.build_bundle(T, registry()).saids["bup1"]
    assert ab.build_bundle(T, registry(), other).saids["bup1"] != a


# -- the provenance DAG ---------------------------------------------------------------------------

def chain(names, **over):
    """names[0] is presented; each node has an edge to the next. All issued by I to I."""
    acdcs = []
    for i, name in enumerate(names):
        spec = {"name": name, "issuer": "I", "schema": "S1",
                "a": {"d": "", "i": {"aid": "I"}, "name": name}}
        if i + 1 < len(names):
            spec["e"] = {"d": "", "up": {"d": "", "n": {"acdc": names[i + 1]},
                                         "s": {"schema": "S1"}}}
        acdcs.append(spec)
    frag = direct(acdcs=acdcs, presented=names[0],
                  events=[icp("I", "i0"), icp("H", "h0"),
                          ixn("ixn1", "I", [{"acdc": n} for n in names])])
    frag.update(over)
    return frag


def test_far_nodes_go_into_acdcs_leaves_first_and_edges_point_at_their_saids():
    b = ab.build_bundle(T, chain(["N", "F", "G"]))
    far = [body(e)[0] for e in b.request["acdcs"]]
    assert [f["d"] for f in far] == [b.saids["G"], b.saids["F"]]
    n = b.expanded["N"]
    assert n["e"]["up"]["n"] == b.saids["F"] and n["e"]["up"]["s"] == b.saids["S1"]
    assert b.graph == {"N": ["F"], "F": ["G"], "G": []}
    # The case's dag field: SAIDs, each edge keyed by its near node and label path.
    assert b.dag == {"root": b.saids["N"], "edges": [
        {"near": b.saids["N"], "path": "e.up", "n": b.saids["F"]},
        {"near": b.saids["F"], "path": "e.up", "n": b.saids["G"]},
    ]}


def test_a_diamond_puts_each_far_node_in_once():
    frag = chain(["N", "F1", "G"])
    frag["acdcs"].insert(2, {"name": "F2", "issuer": "I", "schema": "S1",
                             "a": {"d": "", "i": {"aid": "I"}, "name": "F2"},
                             "e": {"d": "", "g": {"d": "", "n": {"acdc": "G"}}}})
    frag["acdcs"][0]["e"]["b"] = {"d": "", "n": {"acdc": "F2"}}
    b = ab.build_bundle(T, frag)
    assert [body(e)[0]["d"] for e in b.request["acdcs"]] == [b.saids[n] for n in ("G", "F1", "F2")]


def test_an_acdc_outside_the_presented_acdcs_dag_is_refused_by_name():
    """``acdcs`` holds the presented ACDC's provenance DAG and nothing else
    (docs/adapter-protocol.md), so a fragment naming an ACDC no edge reaches is refused."""
    frag = chain(["N", "F"])
    frag["acdcs"].append({"name": "X", "issuer": "I", "schema": "S1", "a": {"d": "", "name": "x"}})
    with pytest.raises(ScenarioError) as e:
        ab.build_bundle(T, frag)
    assert e.value.code == ab.E_DAG_UNREACHABLE
    assert "'X'" in e.value.message and "'N'" in e.value.message


def test_an_acdc_reference_that_is_not_an_edge_does_not_reach_a_node():
    """Only an edge's ``n`` field links a far node. An ``{"acdc": X}`` elsewhere in ``e`` puts X's
    SAID in the body but writes no edge into the dag, so X would ship in ``acdcs`` with no edge
    to it."""
    frag = chain(["N", "F"])
    frag["acdcs"].append({"name": "X", "issuer": "I", "schema": "S1", "a": {"d": "", "name": "x"}})
    frag["acdcs"][0]["e"]["metadata"] = {"acdc": "X"}
    with pytest.raises(ScenarioError) as e:
        ab.build_bundle(T, frag)
    assert e.value.code == ab.E_DAG_UNREACHABLE
    assert "'X'" in e.value.message


def test_an_edge_naming_its_far_node_by_literal_said_reaches_it():
    frag = chain(["N", "F"])
    said = ab.build_bundle(T, frag).saids["F"]
    frag["acdcs"][0]["e"]["up"]["n"] = said
    b = ab.build_bundle(T, frag)
    assert [body(e)[0]["d"] for e in b.request["acdcs"]] == [said]
    assert b.graph["N"] == ["F"]
    assert b.dag["edges"] == [{"near": b.saids["N"], "path": "e.up", "n": said}]


def test_an_edge_whose_literal_said_names_no_acdc_in_the_fragment_is_refused():
    frag = chain(["N", "F"])
    frag["acdcs"][0]["e"]["far"] = {"d": "", "n": "E" + "A" * 43}
    err = _refused(frag, "'N'", "e.far", "E" + "A" * 43)
    assert err.code == ab.E_DAG_UNREACHABLE


def test_acdcs_and_the_dag_hold_the_same_nodes_on_a_diamond():
    frag = chain(["N", "F1", "G"])
    frag["acdcs"].insert(2, {"name": "F2", "issuer": "I", "schema": "S1",
                             "a": {"d": "", "i": {"aid": "I"}, "name": "F2"},
                             "e": {"d": "", "g": {"d": "", "n": {"acdc": "G"}}}})
    frag["acdcs"][0]["e"]["b"] = {"d": "", "n": {"acdc": "F2"}}
    b = ab.build_bundle(T, frag)
    shipped = {body(e)[0]["d"] for e in b.request["acdcs"]} | {b.dag["root"]}
    in_dag = {b.dag["root"]} | {e["near"] for e in b.dag["edges"]} | {e["n"] for e in b.dag["edges"]}
    assert shipped == in_dag == {b.saids[n] for n in ("N", "F1", "F2", "G")}


def test_omit_drops_entries_but_keeps_their_saids_and_incoming_edges():
    frag = chain(["N", "F"])
    frag["omit"] = ["F", "S1"]
    b = ab.build_bundle(T, frag)
    assert b.request["acdcs"] == []
    assert b.request["schemas"] == []
    assert "F" in b.saids  # an omitted node still has a SAID that edges name
    # The omitted far node's incoming edge stays in the dag: its near node is in the bundle.
    assert b.dag["edges"] == [{"near": b.saids["N"], "path": "e.up", "n": b.saids["F"]}]
    frag["omit"] = ["N"]
    with pytest.raises(ScenarioError):
        ab.build_bundle(T, frag)


def test_omitting_a_mid_dag_node_drops_what_only_it_reaches():
    """Tick 7q56: a validator cannot see an omitted node's edges, so the nodes only it reaches
    leave the bundle with it, and acdcs keeps holding exactly the DAG's nodes other than the
    omitted ones."""
    frag = chain(["N", "F", "G"])
    frag["omit"] = ["F"]
    b = ab.build_bundle(T, frag)
    assert b.request["acdcs"] == []
    assert b.dag["edges"] == [{"near": b.saids["N"], "path": "e.up", "n": b.saids["F"]}]
    shipped = {body(e)[0]["d"] for e in b.request["acdcs"]} | {b.dag["root"]}
    in_dag = {b.dag["root"]} | {e["near"] for e in b.dag["edges"]} | {e["n"] for e in b.dag["edges"]}
    assert shipped == in_dag - {b.saids["F"]}


def test_a_node_reachable_another_way_survives_omitting_one_parent():
    frag = chain(["N", "F1", "G"])
    frag["acdcs"].insert(2, {"name": "F2", "issuer": "I", "schema": "S1",
                             "a": {"d": "", "i": {"aid": "I"}, "name": "F2"},
                             "e": {"d": "", "g": {"d": "", "n": {"acdc": "G"}}}})
    frag["acdcs"][0]["e"]["b"] = {"d": "", "n": {"acdc": "F2"}}
    frag["omit"] = ["F1"]
    b = ab.build_bundle(T, frag)
    assert [body(e)[0]["d"] for e in b.request["acdcs"]] == [b.saids["G"], b.saids["F2"]]
    assert {(e["near"], e["path"]) for e in b.dag["edges"]} == {
        (b.saids["N"], "e.up"), (b.saids["N"], "e.b"), (b.saids["F2"], "e.g")}


@pytest.mark.parametrize("n", [["x"], 7, None, {"k": "v"}])
def test_an_edge_n_that_is_not_a_string_is_refused_with_a_code(n):
    """Tick 7q56: a map with an ``n`` key is an edge, and an edge's ``n`` names its far node by
    SAID, so anything but a string is a coded refusal, not a TypeError."""
    frag = chain(["N", "F"])
    frag["acdcs"][0]["e"]["bad"] = {"d": "", "n": n}
    with pytest.raises(ScenarioError) as e:
        ab.build_bundle(T, frag)
    assert e.value.code == ab.E_EDGE
    assert "e.bad" in e.value.message


def test_the_dag_may_be_eight_edges_deep_but_not_nine():
    ab.build_bundle(T, chain([f"N{i}" for i in range(9)]))
    with pytest.raises(GeneratorError) as e:
        ab.build_bundle(T, chain([f"N{i}" for i in range(10)]))
    assert e.value.code == ab.E_DAG


def test_the_bundle_may_hold_sixteen_acdcs_but_not_seventeen():
    def wide(n):
        frag = chain(["N", "F"])
        for i in range(n - 2):
            frag["acdcs"].append({"name": f"X{i}", "issuer": "I", "schema": "S1",
                                  "a": {"d": "", "name": f"x{i}"}})  # distinct, one SAID each
            frag["acdcs"][0]["e"][f"x{i}"] = {"d": "", "n": {"acdc": f"X{i}"}}
        return frag
    ab.build_bundle(T, wide(16))
    with pytest.raises(GeneratorError) as e:
        ab.build_bundle(T, wide(17))
    assert e.value.code == ab.E_DAG


def test_two_acdcs_with_one_said_are_refused():
    # Written alike, they are one ACDC: an edge to it would ship the same far node twice.
    frag = chain(["N", "F"])
    frag["acdcs"].append({**frag["acdcs"][1], "name": "G"})
    e = _refused(frag, "'F'", "'G'", "SAID")
    assert e.code == ScenarioError("x").code

    # A twin is found even when the first ACDC's name is empty (cross-model review of the fix).
    frag = chain(["N", ""])
    frag["acdcs"].append({**frag["acdcs"][1], "name": "G"})
    _refused(frag, "''", "'G'", "SAID")


def test_edges_are_found_inside_lists_and_plain_maps_and_must_name_an_acdc():
    frag = chain(["N", "F"])
    frag["acdcs"][0]["e"] = {"d": "", "grp": {"o": "AND", "m": [{"d": "", "n": {"acdc": "F"}}]}}
    b = ab.build_bundle(T, frag)
    grp = b.expanded["N"]["e"]["grp"]
    assert "d" not in grp and grp["m"][0]["n"] == b.saids["F"]
    assert b.graph["N"] == ["F"]
    assert b.dag["edges"] == [{"near": b.saids["N"], "path": "e.grp.m.0", "n": b.saids["F"]}]
    # Two edges to one far node are two dag edges, and the far node is listed once.
    frag["acdcs"][0]["e"]["grp"]["m"].append({"d": "", "n": {"acdc": "F"}})
    b = ab.build_bundle(T, frag)
    assert b.graph["N"] == ["F"] and len(b.dag["edges"]) == 2
    frag["acdcs"][0]["e"]["grp"]["m"].append({"d": "", "n": {"acdc": "Z"}})
    _refused(frag, "Z", "ACDC")


def test_a_cycle_is_refused():
    frag = chain(["N", "F"])
    frag["acdcs"][1]["e"] = {"d": "", "back": {"d": "", "n": {"acdc": "N"}}}
    with pytest.raises(GeneratorError) as e:
        ab.build_bundle(T, frag)
    assert e.value.code == ab.E_DAG


# -- refusals -------------------------------------------------------------------------------------

def _refused(frag, *words):
    with pytest.raises(ScenarioError) as e:
        ab.build_bundle(T, frag)
    for w in words:
        assert w in str(e.value)
    return e.value


def test_scenario_refusals():
    f = direct()
    f["acdcs"].append(dict(f["acdcs"][0]))
    _refused(f, "A1", "twice")
    _refused(direct(presented="Z"), "Z")
    f = direct()
    f["acdcs"][0]["a"]["i"] = {"aid": "Q"}
    _refused(f, "Q")
    f = direct()
    f["acdcs"][0]["a"]["x"] = {"acdc": "Z"}
    _refused(f, "Z")
    f = direct()
    f["acdcs"][0]["schema"] = "S9"
    _refused(f, "S9")
    f = direct()
    f["acdcs"][0]["form"] = "folded"
    _refused(f, "folded")
    f = direct()
    f["acdcs"][0]["form"] = {"compact": ["a.nope"]}
    _refused(f, "a.nope")
    f = direct()
    f["acdcs"][0]["form"] = {"disclose": [0]}
    _refused(f, "A")
    f = direct()
    f["acdcs"][0]["form"] = {"squash": []}
    _refused(f, "squash")
    f = direct()
    f["events"][2]["a"] = [{"acdc": "Z"}]
    _refused(f, "Z")
    f = direct()
    f["events"][2]["a"] = [{"thing": 1}]
    _refused(f, "thing")
    f = registry()
    f["registries"][1]["registry"] = "nope"
    _refused(f, "nope")
    f = registry()
    f["registries"][0]["t"] = "upd"
    _refused(f, "upd")
    f = registry()
    f["registries"][1]["t"] = "rip"
    f["registries"][1]["issuer"] = "I"
    f["registries"][1]["name"] = "rip1"
    _refused(f, "rip1", "twice")
    f = registry()
    f["acdcs"][0]["registry"] = "bup1"
    _refused(f, "bup1", "inception")
    f = registry()
    f["registries"][1]["prior"] = "zzz"
    _refused(f, "zzz")
    f = direct()
    f["schemas"].append({"name": "S1", "schema": S1})
    _refused(f, "S1", "twice")
    f = direct(omit=["nothing"])
    _refused(f, "nothing")
    f = registry()
    f["registries"].reverse()
    _refused(f, "bup1", "earlier")
    f = direct()
    f["acdcs"][0]["form"] = {"compact": ["a.name.x"]}
    _refused(f, "a.name.x")


@pytest.mark.parametrize("kind,name", [("schemas", "rip1"), ("acdcs", "rip1"), ("acdcs", "S1")])
def test_a_name_used_for_two_kinds_of_thing_is_refused(kind, name):
    # One map holds every SAID, so a shared name would let an ACDC's s silently name a registry.
    f = registry()
    extra = {"name": name, "schema": S1} if kind == "schemas" else \
        {"name": name, "issuer": "I", "schema": "S1"}
    f[kind].append(extra)
    _refused(f, repr(name), "names both")


@pytest.mark.parametrize("prior", ["self", "mutual", "state", "seal"])
def test_a_registry_event_that_depends_on_itself_is_refused(prior):
    f = registry()
    bup = f["registries"][1]
    if prior == "self":
        bup["prior"] = "bup1"
    elif prior == "mutual":
        f["registries"].append({**bup, "name": "bup2", "prior": "bup1", "disclose": False})
        del f["registries"][2]["source_seal"]
        bup["prior"] = "bup2"
    elif prior == "state":
        bup["state"]["td"] = {"registry": "bup1"}
    else:
        f["events"][0]["a"] = [{"registry": "rip1"}]
    e = _refused(f, "depends on itself")
    assert e.code == "e.input.format.kcs-scenario.f"


def test_an_acdc_sealed_in_its_own_issuers_inception_is_refused():
    f = direct()
    f["events"][0]["a"] = [{"acdc": "A1"}]
    with pytest.raises(GeneratorError) as e:
        ab.build_bundle(T, f)
    assert e.value.code == ab.E_DAG


def test_a_schema_outside_the_subset_is_refused_unless_its_reference_leaves_the_schema():
    bad = {**S1, "additionalProperties": False}
    with pytest.raises(GeneratorError) as e:
        ab.build_bundle(T, direct(schemas=[{"name": "S1", "schema": bad}]))
    assert e.value.code == js.E_KEYWORD
    remote = {**S1, "properties": {"a": {"$ref": "https://example.com/a.json"}}}
    b = ab.build_bundle(T, direct(schemas=[{"name": "S1", "schema": remote}]))
    assert json.loads(bytes.fromhex(b.request["schemas"][0]))["properties"]["a"]["$ref"]


def test_a_seal_that_names_nothing_the_builder_knows_is_refused():
    eb = keri_events.EventBuilder(T, [icp("I", "i0"), ixn("x", "I", [{"acdc": "A1"}])])
    with pytest.raises(ScenarioError) as e:
        eb.event("x")
    assert "seal" in str(e.value)
    resolved = keri_events.EventBuilder(T, [icp("I", "i0"), ixn("x", "I", [{"acdc": "A1"}])],
                                        seal_resolver=lambda seal: {"d": "E" + "A" * 43})
    assert resolved.event("x").body["a"] == [{"d": "E" + "A" * 43}]


def test_a_schema_marked_unsaided_is_delivered_as_written():
    """A schema that stands at a non-local reference's URI is not a SAD, so its $id is the URI and
    nothing is computed (the decoy for a schema that refers outside itself)."""
    lei = {"$id": "https://example.com/lei.json", "type": "string"}
    frag = direct(schemas=[{"name": "S1", "schema": S1},
                           {"name": "LEI", "schema": lei, "said": False}])
    b = ab.build_bundle(T, frag)
    assert json.loads(bytes.fromhex(b.request["schemas"][1])) == lei
    assert b.saids["LEI"] == lei["$id"]


def test_an_unsaided_schema_needs_an_id():
    frag = direct(schemas=[{"name": "S1", "schema": S1},
                           {"name": "LEI", "schema": {"type": "string"}, "said": False}])
    with pytest.raises(ScenarioError, match="LEI"):
        ab.build_bundle(T, frag)
