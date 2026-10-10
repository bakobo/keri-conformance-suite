"""The ACDC model validator: docs/design.md's decision procedure over a bundle's bytes.

Each test builds a bundle with the generator's builder and checks what the model finds. The
model reports every failing check, with its step, because the grading needs every independent
derivation (docs/design.md, "How levels are derived")."""

import copy
import json
import os
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from generators.spec_tables import acdc_build as ab
from generators.spec_tables import acdc_model as am
from generators.spec_tables import acdc_saids as sa
from generators.spec_tables import json_schema_subset as js
from generators.spec_tables import spec_source, tables
from generators.spec_tables.errors import ScenarioError

try:
    CESR_TEXT = spec_source.load_spec()
except spec_source.SpecUnavailable as e:
    if os.environ.get("KCS_REQUIRE_SPEC") == "1":
        raise
    pytest.skip(f"a pinned specification text is unavailable: {e}", allow_module_level=True)

T = tables.load(CESR_TEXT)
ATTRS = {"type": "object", "required": ["d", "i", "name"],
         "properties": {"d": {"type": "string"}, "i": {"type": "string"},
                        "name": {"type": "string"}}}
S1 = {"$id": "", "$schema": js.DIALECT, "version": "1.0.0", "type": "object",
      "required": ["v", "d", "i", "s"],
      "properties": {"a": {"oneOf": [{"type": "string"}, ATTRS]},
                     "A": {"oneOf": [{"type": "string"}, {"type": "array"}]},
                     "e": {"oneOf": [{"type": "string"}, {"type": "object"}]}}}


def icp(aid):
    return {"name": f"{aid}icp", "aid": aid, "t": "icp", "keys": [f"{aid}0"],
            "next": [f"{aid}1"]}


def base(**over):
    """I issues A1 to H, sealed in ixn1; A1 presented expanded."""
    frag = {
        "events": [icp("I"), icp("H"), icp("Q"),
                   {"name": "ixn1", "aid": "I", "t": "ixn", "a": [{"acdc": "A1"}]}],
        "kels": [{"event": "Iicp", "sigs": ["I0"]}, {"event": "ixn1", "sigs": ["I0"]}],
        "schemas": [{"name": "S1", "schema": copy.deepcopy(S1)}],
        "acdcs": [{"name": "A1", "issuer": "I", "schema": "S1", "form": "expanded",
                   "a": {"d": "", "i": {"aid": "H"}, "name": "Zoe"}, "source_seal": "ixn1"}],
        "presented": "A1",
    }
    frag.update(over)
    return frag


def run(frag, readings=sa.DEFAULT):
    b = ab.build_bundle(T, frag)
    return am.evaluate(T, b.request, readings), b


def tags(node):
    return [f.tag for f in node.failures]


def test_a_sealed_acdc_passes_every_check():
    result, b = run(base())
    assert result.presented.failures == [] and not result.failing()
    assert result.presented.said == b.saids["A1"]
    assert result.edges == [] and result.registry is None


@pytest.mark.parametrize("over,expected", [
    ({"said": "expanded"}, ["1/said"]),
    ({"alter": [{"path": "a.name", "value": "Zed"}]}, ["1/said"]),
    ({"order": ["v", "t", "d", "i", "a", "s"]}, ["1/field-order"]),
    ({"schema": None}, ["1/required-field", "2/schema-absent"]),
    ({"protocol": "KERI"}, ["1/protocol"]),
    ({"declared_size": "compact"}, ["1/unframeable"]),
    ({"A": [{"d": "", "u": {"nonce": "b0"}, "x": 0}]}, ["1/a-and-A"]),
])
def test_intrinsic_failures(over, expected):
    frag = base()
    frag["acdcs"][0].update(over)
    result, _ = run(frag)
    assert tags(result.presented) == expected
    assert result.failing()


def test_an_unknown_top_level_field_is_out_of_order():
    frag = base()
    frag["acdcs"][0]["alter"] = [{"path": "t", "value": "xyz"}]
    result, b = run(frag)
    body = result.presented.body
    raw = bytes.fromhex(b.request["presented"]["stream"]).replace(b'"t":"xyz"', b'"q":"xyz"')
    node, _ = am._Model(T, b.request, sa.DEFAULT).node(raw)
    assert "1/field-order" in tags(node) and body["t"] == "xyz"


def test_a_stream_that_frames_no_single_acdc_body_is_unframeable():
    frag = base()
    b = ab.build_bundle(T, frag)
    model = am._Model(T, b.request, sa.DEFAULT)
    good = bytes.fromhex(b.request["presented"]["stream"])
    for bad in (good[:-10], good[:8] + b"[]" , am.GENUS + good[8:] + good[8:]):
        node, _ = model.node(bad)
        assert tags(node) == ["1/unframeable"] and node.said is None


def test_a_selectively_disclosed_acdc_and_a_wrong_aggregate():
    frag = base()
    spec = frag["acdcs"][0]
    del spec["a"]
    spec.update({"A": [{"d": "", "u": {"nonce": f"b{i}"}, "x": i} for i in range(3)],
                 "form": {"disclose": [1]}})
    result, _ = run(frag)
    assert result.presented.failures == []
    assert tags(run(frag, sa.Readings(aggregate="concat"))[0].presented) == ["1/said"]


def test_a_wrong_aggregate_entry_and_a_tampered_disclosed_block_fail_the_said_check():
    frag = base()
    spec = frag["acdcs"][0]
    del spec["a"]
    spec.update({"A": [{"d": "", "u": {"nonce": f"b{i}"}, "x": i} for i in range(2)],
                 "form": {"disclose": [0]}})
    _, b = run(frag)
    agid = b.forms["A1"]["A"][0]
    other = agid[:-1] + ("A" if agid[-1] != "A" else "B")
    spec["alter"] = [{"path": "A", "value": [other] + b.forms["A1"]["A"][1:]}]
    assert tags(run(frag)[0].presented) == ["1/said"]
    block = dict(b.forms["A1"]["A"][1])
    block["x"] = 7
    spec["alter"] = [{"path": "A", "value": [agid, block] + b.forms["A1"]["A"][2:]}]
    assert tags(run(frag)[0].presented) == ["1/said"]


def test_a_said_that_is_not_a_string_fails_the_said_check():
    frag = base()
    result, b = run(frag)
    model = am._Model(T, b.request, sa.DEFAULT)
    body = dict(result.presented.body)
    assert not model._saids_verify({**body, "d": 7})
    assert not model._saids_verify({**body, "A": [7, {"d": 3}]})
    # Values no SAID can be computed over: a block that is not a map, an empty aggregate, and
    # a body with no version string under the presented-size reading.
    assert not model._saids_verify({**body, "A": ["x", 7]})
    assert not model._saids_verify({**body, "A": []})
    presented = am._Model(T, b.request, sa.Readings(compact_v="presented"))
    assert not presented._saids_verify({k: v for k, v in body.items() if k != "v"})


def test_streams_that_do_not_frame():
    _, b = run(base())
    model = am._Model(T, b.request, sa.DEFAULT)
    good = bytes.fromhex(b.request["presented"]["stream"])
    for bad in (good[8:],  # no genus/version code
                good.replace(b"ACDCCAA", b"ACDCBAA", 1),  # version 1.00 in 2.00 form
                good.replace(b"JSON", b"CBOR", 1),
                good + b"-CAA",  # an attachments group after nothing
                good.replace(b'{"v"', b'["v"', 1)):
        assert tags(model.node(bad)[0]) == ["1/unframeable"], bad


def test_attachments_that_do_not_read_make_the_stream_unframeable():
    _, b = run(reg())
    stream = bytes.fromhex(b.request["registry"][1]["stream"])
    body_end = stream.index(b"}-C") + 1
    head = stream[:body_end]
    for bad in (b"-C", b"-SAA", b"-CAC-aAB!!!!", b"-CAC-aABEAAA"):
        assert am._parse(T, head + bad) is None, bad
    assert am._parse(T, head + b"-CAB-SAA")[2] == []
    assert am._parse(T, head + b"-CAB-aAA")[2] == []  # an empty group holds no block
    assert am._parse(T, head[:-1]) is None  # the body cut short of its declared size


@pytest.mark.parametrize("schema_over,expected", [
    ({"alter": [{"path": "required", "value": ["v", "d", "i", "s", "zz"]}]}, ["2/schema-said"]),
    ({"schema": {**S1, "required": ["v", "d", "i", "s", "zz"]}}, ["2/schema-invalid"]),
    ({"schema": {**S1, "properties": {"a": {"$ref": "https://example.com/a.json"}}}},
     ["2/schema-nonlocal"]),
    ({"schema": {**S1, "$schema": "http://json-schema.org/draft-07/schema#"}},
     ["2/schema-dialect"]),
    ({"schema": {**S1, "version": "9.9.9"}}, []),
])
def test_schema_failures(schema_over, expected):
    frag = base()
    frag["schemas"][0].update(schema_over)
    assert tags(run(frag)[0].presented) == expected


def test_a_schema_absent_or_substituted_is_absent():
    assert tags(run(base(omit=["S1"]))[0].presented) == ["2/schema-absent"]
    frag = base(omit=["S1"])
    frag["schemas"].append({"name": "S2", "schema": {**S1, "title": "lenient"}})
    assert tags(run(frag)[0].presented) == ["2/schema-absent"]


def test_schema_bytes_that_are_not_json_or_hold_a_bad_id_are_no_schema():
    _, b = run(base())
    req = copy.deepcopy(b.request)
    good = req["schemas"][0]
    for raw in (b"NaN", b'{"$id":', json.dumps({"$id": 7}).encode()):
        req["schemas"] = [raw.hex()]
        assert tags(am.evaluate(T, req).presented) == ["2/schema-absent"]
    # A schema printed with whitespace verifies under the compact reading only (A-B2), and bytes
    # the received reading cannot read verify under neither.
    pretty = json.dumps(json.loads(bytes.fromhex(good)), indent=2).encode()
    req["schemas"] = [pretty.hex()]
    assert am.evaluate(T, req).presented.failures == []
    assert tags(am.evaluate(T, req, sa.Readings(schema="received")).presented) == \
        ["2/schema-said"]
    twice = pretty.replace(b'"$id"', b'"$id": "x", "$id"', 1)
    req["schemas"] = [twice.hex()]
    assert tags(am.evaluate(T, req, sa.Readings(schema="received")).presented) == \
        ["2/schema-said"]


def test_issuer_key_state_and_commitment():
    assert tags(run(base(kels=[]))[0].presented) == ["3/issuer-kel"]
    frag = base()
    frag["events"][3]["a"] = []
    assert tags(run(frag)[0].presented) == ["4/no-commitment"]
    frag = base()
    frag["kels"][1]["sigs"] = [{"key": "I0", "forged": True}]
    assert tags(run(frag)[0].presented) == ["4/no-commitment"]
    frag = base()
    frag["events"][3] = {"name": "ixn1", "aid": "Q", "t": "ixn", "a": [{"acdc": "A1"}]}
    frag["kels"] = [{"event": "Iicp", "sigs": ["I0"]}, {"event": "Qicp", "sigs": ["Q0"]},
                    {"event": "ixn1", "sigs": ["Q0"]}]
    frag["acdcs"][0]["source_seal"] = None
    assert tags(run(frag)[0].presented) == ["4/no-commitment"]


def test_a_seal_in_a_superseded_event_commits_nothing():
    """A recovery rotation displaces the interaction that seals the ACDC: the seal is seen but off
    the trunk, so it is no commitment; sealed again on the new trunk, it is."""
    frag = base()
    frag["events"].append({"name": "rot1", "aid": "I", "t": "rot", "prior": "Iicp",
                           "keys": ["I1"], "next": ["I2"], "a": [{"event": "Hicp"}]})
    frag["kels"].append({"event": "rot1", "sigs": ["I1"]})
    assert tags(run(frag)[0].presented) == ["4/no-commitment"]
    frag["events"][-1]["a"] = [{"acdc": "A1"}]
    assert tags(run(frag)[0].presented) == []


def test_kels_that_end_differently_under_different_keep_policies_are_refused():
    frag = base()
    frag["events"].insert(1, {"name": "Iicp", "aid": "I", "t": "icp", "keys": ["I0", "I9"],
                              "kt": "2", "next": ["I1"]})
    del frag["events"][0]
    frag["kels"] = [{"event": "Iicp", "sigs": ["I0"]}, {"event": "Iicp", "sigs": ["I9"]},
                    {"event": "ixn1", "sigs": ["I0", "I9"]}]
    with pytest.raises(ScenarioError, match="keep"):
        run(frag)


# -- registries -----------------------------------------------------------------------------------

def reg(**over):
    frag = base()
    frag["events"][3]["a"] = [{"registry": "rip1"}]
    frag["events"] += [{"name": "ixn2", "aid": "I", "t": "ixn", "a": [{"registry": "bup1"}]},
                       {"name": "ixn3", "aid": "I", "t": "ixn", "a": [{"registry": "bup2"}]}]
    frag["kels"] += [{"event": "ixn2", "sigs": ["I0"]}, {"event": "ixn3", "sigs": ["I0"]}]
    frag["acdcs"][0].update({"registry": "rip1", "source_seal": None})
    frag["registries"] = [
        {"name": "rip1", "t": "rip", "issuer": "I"},
        {"name": "bup1", "t": "bup", "registry": "rip1", "disclose": True,
         "state": {"u": "s1", "td": {"acdc": "A1"}, "ts": "issued"}},
        {"name": "bup2", "t": "bup", "registry": "rip1", "disclose": True,
         "state": {"u": "s2", "td": {"acdc": "A1"}, "ts": "revoked"}}]
    frag.update(over)
    return frag


def one_update():
    frag = reg()
    del frag["registries"][2]
    frag["events"][-1]["a"] = []
    return frag


def test_a_registry_issues_and_revokes():
    result, b = run(reg())
    assert result.presented.failures == [] and not result.failing()
    assert result.registry.facts() == {"rd": b.saids["rip1"], "n": 2, "d": b.saids["bup2"],
                                       "td": b.saids["A1"], "ts": "revoked"}
    assert result.registry.updates == 2 and result.registry.stop is None


@pytest.mark.parametrize("change,stop,n", [
    (lambda f: f["kels"].pop(), "bup-unsealed", 1),
    (lambda f: f["registries"][2].update(prior="rip1", n=2), "bup-prior", 1),
    (lambda f: f["registries"][2].update(n=3), "bup-sn", 1),
    (lambda f: f["registries"][2].update(
        alter=[{"path": "dt", "value": "2026-07-04T17:50:00.000000+00:00"}]), "bup-said", 1),
    (lambda f: f["registries"][2].update(alter=[{"path": "t", "value": "upd"}]), "bup-type", 1),
])
def test_a_registry_chain_stops_at_its_first_failure(change, stop, n):
    frag = reg()
    change(frag)
    result, _ = run(frag)
    assert result.registry.stop == stop and result.registry.n == n
    assert result.registry.facts()["ts"] == "issued" and result.failing()


def test_registry_inception_failures_report_no_registry():
    frag = reg()
    frag["kels"] = frag["kels"][:1]
    result, _ = run(frag)
    assert result.registry is None and result.registry_failure == "rip-unsealed"
    assert tags(result.presented) == ["5/no-registry-commitment"]
    frag = reg()
    frag["registries"][0]["issuer"] = "Q"
    assert run(frag)[0].registry_failure == "rip-issuer"
    frag = reg()
    frag["registries"][0]["alter"] = [{"path": "dt", "value": "2026-07-04T17:50:00.000000+00:00"}]
    assert run(frag)[0].registry_failure == "rip-said"
    frag = reg(omit=["rip1"])
    assert run(frag)[0].registry_failure == "rip-absent"


@pytest.mark.parametrize("disclose,block", [
    ({"td": {"nothing": "A2"}, "blid": "kept"}, "blid-self"),
    ({"td": {"nothing": "A2"}, "blid": "own"}, "blid-other"),
    (False, None),
])
def test_a_block_that_does_not_verify_or_is_absent_leaves_the_state_unknown(disclose, block):
    frag = one_update()
    frag["registries"][1]["disclose"] = disclose
    result, _ = run(frag)
    assert result.registry.n == 1 and (result.registry.td, result.registry.ts) == (None, None)
    assert result.registry.block == block
    assert tags(result.presented) == ["5/no-registry-commitment"]


def test_an_empty_state_and_a_state_that_is_not_a_tag():
    frag = one_update()
    frag["registries"][1]["state"] = {"u": "s1", "td": "", "ts": ""}
    result, _ = run(frag)
    assert (result.registry.td, result.registry.ts) == ("", "")
    assert am._state("Xabc") == "abc" and am._state("0Kab") == "ab"
    with pytest.raises(ScenarioError, match="Tag"):
        am._state("6AABAAA-")


# -- edges ----------------------------------------------------------------------------------------

def chain(**edge):
    frag = base()
    frag["events"].append({"name": "qixn", "aid": "Q", "t": "ixn", "a": [{"acdc": "F"}]})
    frag["kels"] += [{"event": "Qicp", "sigs": ["Q0"]}, {"event": "qixn", "sigs": ["Q0"]}]
    frag["events"][3]["a"] = [{"acdc": "N"}]
    block = {"d": "", "n": {"acdc": "F"}, "s": {"schema": "S1"}, "o": "I2I", **edge}
    frag["acdcs"] = [
        {"name": "N", "issuer": "I", "schema": "S1", "a": {"d": "", "i": {"aid": "H"},
                                                           "name": "N"},
         "e": {"d": "", "le": {k: v for k, v in block.items() if v is not None}},
         "source_seal": "ixn1", "form": "expanded"},
        {"name": "F", "issuer": "Q", "schema": "S1", "form": "expanded",
         "a": {"d": "", "i": {"aid": "I"}, "name": "F"}, "source_seal": "qixn"}]
    frag["presented"] = "N"
    return frag


def test_a_valid_chain():
    result, b = run(chain())
    assert not result.failing()
    assert [(e.near, e.path, e.n, e.failure) for e in result.edges] == [
        (b.saids["N"], "e.le", b.saids["F"], None)]
    assert set(result.far) == {b.saids["F"]}


def _edge(frag):
    result, _ = run(frag)
    return [e.failure for e in result.edges]


def test_a_far_node_whose_said_fails_is_not_walked():
    """A forged far node whose own edge names the near node would make a cycle, but its SAID
    does not verify, so the walk stops there and only the edge that names it is checked
    (docs/design.md, ACDC, The bundle and the evaluation point)."""
    frag = chain()
    frag["events"] += [icp("R"), {"name": "rixn", "aid": "R", "t": "ixn", "a": [{"acdc": "G"}]}]
    frag["kels"] += [{"event": "Ricp", "sigs": ["R0"]}, {"event": "rixn", "sigs": ["R0"]}]
    frag["acdcs"][1]["e"] = {"d": "", "up": {"d": "", "n": {"acdc": "G"}, "s": {"schema": "S1"},
                                            "o": "I2I"}}
    frag["acdcs"][1]["alter"] = [{"path": "e.up.n", "value": {"acdc": "N"}}]
    frag["acdcs"].append({"name": "G", "issuer": "R", "schema": "S1", "form": "expanded",
                          "a": {"d": "", "i": {"aid": "Q"}, "name": "G"}, "source_seal": "rixn"})
    result, b = run(frag)
    assert [(e.path, e.failure) for e in result.edges] == [("e.le", "far-said")]
    assert list(result.far) == [b.saids["F"]]


def test_edge_failures():
    frag = chain()
    frag["acdcs"][1]["a"]["i"] = {"aid": "H"}
    assert _edge(frag) == ["i2i-issuee"]
    frag = chain()
    del frag["acdcs"][1]["a"]["i"]
    frag["schemas"][0]["schema"]["properties"]["a"]["oneOf"][1]["required"] = ["d", "name"]
    assert _edge(frag) == ["i2i-untargeted"]
    frag = chain()
    frag["acdcs"][1]["form"] = "compact"
    assert _edge(frag) == ["i2i-hidden"]
    assert _edge(chain() | {"omit": ["F"]}) == ["far-absent"]
    frag = chain()
    frag["acdcs"][1]["alter"] = [{"path": "a.i", "value": {"aid": "H"}, "resaid": ["a"]}]
    assert _edge(frag) == ["far-said"]
    frag = chain()
    frag["acdcs"][1]["a"]["name"] = 7
    assert _edge(frag) == ["far-schema"]
    frag = chain(s={"schema": "S3"})
    frag["schemas"].append({"name": "S3", "schema": {**S1, "title": "S3",
                                                      "required": ["v", "d", "i", "s", "r"]}})
    assert _edge(frag) == ["edge-schema"]
    frag["schemas"][1]["schema"]["required"] = ["v"]
    assert _edge(frag) == [None]
    frag["omit"] = ["S3"]
    assert _edge(frag) == ["edge-schema"]


def test_a_far_node_that_does_not_frame_is_not_a_far_node():
    frag = chain()
    frag["acdcs"][1]["protocol"] = "KERI"
    assert _edge(frag) == ["far-absent"]


def test_edges_outside_the_first_batch_are_refused():
    with pytest.raises(ScenarioError, match="operator"):
        run(chain(o=None))
    with pytest.raises(ScenarioError, match="NI2I"):
        run(chain(o=["NI2I"]))


def test_a_diamond_evaluates_each_edge_once_and_each_far_node_once():
    frag = chain()
    frag["acdcs"][0]["e"]["b"] = {"d": "", "n": {"acdc": "F2"}, "o": "I2I"}
    frag["acdcs"][1]["e"] = {"d": "", "g": {"d": "", "n": {"acdc": "G"}, "o": "I2I"}}
    frag["acdcs"] += [
        {"name": "F2", "issuer": "Q", "schema": "S1", "form": "expanded",
         "a": {"d": "", "i": {"aid": "I"}, "name": "F2"}, "source_seal": "qixn",
         "e": {"d": "", "g": {"d": "", "n": {"acdc": "G"}, "o": "I2I"}}},
        {"name": "G", "issuer": "H", "schema": "S1", "form": "expanded",
         "a": {"d": "", "i": {"aid": "Q"}, "name": "G"}, "source_seal": "hixn"}]
    frag["events"][-1]["a"] = [{"acdc": "F"}, {"acdc": "F2"}]
    frag["events"].append({"name": "hixn", "aid": "H", "t": "ixn", "a": [{"acdc": "G"}]})
    frag["kels"] += [{"event": "Hicp", "sigs": ["H0"]}, {"event": "hixn", "sigs": ["H0"]}]
    result, b = run(frag)
    assert not result.failing()
    assert sorted((e.near, e.path) for e in result.edges) == sorted([
        (b.saids["N"], "e.le"), (b.saids["N"], "e.b"), (b.saids["F"], "e.g"),
        (b.saids["F2"], "e.g")])
    assert set(result.far) == {b.saids[n] for n in ("F", "F2", "G")}


def test_edge_blocks_are_found_in_maps_and_lists():
    e = {"d": "x", "grp": {"m": [{"n": "A"}, {"n": "B", "o": "I2I"}]}, "z": 3}
    assert am.edge_blocks(e) == [("e.grp.m.0", {"n": "A"}), ("e.grp.m.1", {"n": "B", "o": "I2I"})]


def _with_listed_block(block_d=None):
    """The presented A1 body with a SAIDed block inside a list in ``a``, its ``a`` and top-level
    SAIDs recomputed over it, so only the listed block's own SAID can be wrong."""
    _, b = run(base())
    model = am._Model(T, b.request, sa.DEFAULT)
    body, _ = model.node(bytes.fromhex(b.request["presented"]["stream"]))
    body = copy.deepcopy(body.body)
    block = {"d": "", "x": 1}
    block["d"] = sa.block_said(T, block)
    if block_d is not None:
        block["d"] = block_d(block["d"])
    body["a"]["items"] = [block]
    body["a"]["d"] = sa.block_said(T, body["a"])
    body["d"] = sa.acdc_said(T, body)
    return model, body


def test_a_saided_block_inside_a_list_must_verify_wherever_it_sits():
    model, body = _with_listed_block()
    assert model._intrinsic(body) == []
    model, body = _with_listed_block(lambda d: d[:-1] + ("A" if d[-1] != "A" else "B"))
    assert [f.tag for f in model._intrinsic(body)] == ["1/said"]


def _framed(body: dict) -> bytes:
    body = sa.sized(body)
    return am.GENUS + sa.serialize(body)


def _nested(depth: int):
    value = 1
    for _ in range(depth):
        value = {"x": value}
    return value


def test_nesting_beyond_the_bound_is_refused_with_a_coded_error():
    _, b = run(base())
    model = am._Model(T, b.request, sa.DEFAULT)
    body = {"v": sa.version_string(0), "d": "", "i": "I", "s": "S",
            "a": _nested(1100)}
    with pytest.raises(ScenarioError) as e:
        model.node(_framed(body))
    assert e.value.code == am.E_NESTING
    # The top-level map is one level, and "a" holds the rest, so this is exactly the bound.
    body["a"] = _nested(am.MAX_NESTING - 1)
    node, _ = model.node(_framed(body))
    assert "1/said" in tags(node)


def test_nesting_is_counted_outside_strings_only():
    assert am._nesting(b'{"a":"{[\\"{[","b":[{}]}') == 3
    assert am._nesting(b'"\\\\"') == 0
