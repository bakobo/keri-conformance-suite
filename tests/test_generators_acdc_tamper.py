"""The ACDC builder's tampers: what a scenario may change on purpose so that a case tests one
defect (docs/design.md, ACDC, "Construction properties": a tamper never changes framing by
accident, so it preserves length unless it recomputes the version string).

The builder applies only what a scenario asks for and never judges the result; the model
validator (acdc_model) does that."""

import json
import os
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from generators.spec_tables import acdc_build as ab
from generators.spec_tables import acdc_saids as sa
from generators.spec_tables import keri_events, spec_source, tables
from generators.spec_tables.errors import ScenarioError

try:
    CESR_TEXT = spec_source.load_spec()
except spec_source.SpecUnavailable as e:
    if os.environ.get("KCS_REQUIRE_SPEC") == "1":
        raise
    pytest.skip(f"a pinned specification text is unavailable: {e}", allow_module_level=True)

T = tables.load(CESR_TEXT)
GENUS = b"-_AAACAA"
S1 = {"$id": "", "$schema": "https://json-schema.org/draft/2020-12/schema", "version": "1.0.0",
      "type": "object", "required": ["v", "d", "i", "s"]}


def frag(**acdc_over):
    acdc = {"name": "A1", "issuer": "I", "schema": "S1", "form": "expanded",
            "a": {"d": "", "i": {"aid": "H"}, "name": "Zoe"}, "source_seal": "ixn1"}
    acdc.update(acdc_over)
    return {
        "events": [{"name": "Iicp", "aid": "I", "t": "icp", "keys": ["i0"], "next": ["i1"]},
                   {"name": "Hicp", "aid": "H", "t": "icp", "keys": ["h0"], "next": ["h1"]},
                   {"name": "ixn1", "aid": "I", "t": "ixn", "a": [{"acdc": "A1"}]}],
        "kels": [{"event": "Iicp", "sigs": ["i0"]}, {"event": "ixn1", "sigs": ["i0"]}],
        "schemas": [{"name": "S1", "schema": dict(S1)}],
        "acdcs": [acdc],
        "presented": "A1",
    }


def presented(b) -> tuple[dict, bytes, str]:
    data = bytes.fromhex(b.request["presented"]["stream"]).removeprefix(GENUS)
    obj, end = json.JSONDecoder().raw_decode(data.decode())
    return obj, data[:end], data[end:].decode()


def test_said_over_the_expanded_form_is_keripy_1x_rule_and_is_what_the_seal_names():
    b = ab.build_bundle(T, frag(said="expanded"))
    acdc, _, _ = presented(b)
    assert acdc["d"] == sa.expanded_said(T, acdc) != sa.acdc_said(T, acdc)
    assert b.saids["A1"] == acdc["d"]
    ixn1 = json.loads(bytes.fromhex(b.request["kels"][1]["stream"]).removeprefix(GENUS)
                      .split(b"-C")[0])
    assert ixn1["a"] == [{"d": acdc["d"]}]


def test_an_unknown_said_rule_is_refused():
    with pytest.raises(ScenarioError, match="said"):
        ab.build_bundle(T, frag(said="sideways"))


@pytest.mark.parametrize("form", ["expanded", "compact", {"compact": []}])
def test_a_version_string_may_name_another_protocol_with_the_said_over_that_body(form):
    b = ab.build_bundle(T, frag(protocol="KERI", form=form))
    acdc, raw, _ = presented(b)
    assert acdc["v"].startswith("KERI") and acdc["v"][4:] == sa.version_string(len(raw))[4:]
    compact = sa.most_compact(T, {**acdc, "v": "ACDC" + acdc["v"][4:]})
    compact = {**compact, "v": "KERI" + compact["v"][4:], "d": sa.DUMMY}
    assert acdc["d"] == sa.digest(T, sa.serialize(compact)) == b.saids["A1"]


@pytest.mark.parametrize("protocol", ["KER", "keri", 7, "ACDCX"])
def test_a_protocol_must_be_four_uppercase_letters(protocol):
    with pytest.raises(ScenarioError, match="protocol"):
        ab.build_bundle(T, frag(protocol=protocol))


def test_top_level_fields_may_be_ordered_otherwise_with_the_said_over_that_order():
    order = ["v", "t", "d", "i", "a", "s"]
    b = ab.build_bundle(T, frag(order=order))
    acdc, _, _ = presented(b)
    assert list(acdc) == order
    assert sa.acdc_said(T, acdc) == acdc["d"] == b.saids["A1"]


def test_an_order_must_name_exactly_the_fields_the_acdc_has():
    with pytest.raises(ScenarioError, match="order"):
        ab.build_bundle(T, frag(order=["v", "d", "i", "s"]))


def test_an_acdc_may_have_no_schema_field():
    b = ab.build_bundle(T, frag(schema=None))
    acdc, _, _ = presented(b)
    assert "s" not in acdc and sa.acdc_said(T, acdc) == acdc["d"]


def test_an_alteration_changes_the_presented_bytes_and_no_said():
    clean = presented(ab.build_bundle(T, frag()))[0]
    b = ab.build_bundle(T, frag(alter=[{"path": "a.name", "value": "Zed"}]))
    acdc, raw, _ = presented(b)
    assert acdc["a"]["name"] == "Zed"
    assert acdc["d"] == clean["d"] and acdc["a"]["d"] == clean["a"]["d"]
    assert acdc["v"] == clean["v"] and len(raw) == sa.b64.b64_to_int(acdc["v"][14:18])
    # Seals and edges still name the SAID the ACDC had before.
    assert b.saids["A1"] == clean["d"]


def test_an_alteration_may_recompute_a_block_said_and_resolve_a_reference():
    clean = presented(ab.build_bundle(T, frag()))[0]
    b = ab.build_bundle(T, frag(alter=[{"path": "a.i", "value": {"aid": "I"},
                                        "resaid": ["a"]}]))
    acdc, _, _ = presented(b)
    assert acdc["a"]["i"] == acdc["i"]
    assert acdc["a"]["d"] == sa.block_said(T, acdc["a"]) != clean["a"]["d"]
    assert acdc["d"] == clean["d"]


@pytest.mark.parametrize("alter,words", [
    ([{"path": "a.name", "value": "Zoe Doe"}], ("length",)),
    ([{"path": "a.nope.x", "value": "1"}], ("a.nope.x",)),
    ([{"path": "a.zzz", "value": "1"}], ("a.zzz",)),
    ([{"path": "a.name.x", "value": "1"}], ("a.name.x",)),
    ([{"path": "a.name", "value": "Zed", "resaid": ["a.name"]}], ("a.name", "SAIDed")),
    ([{"value": "x"}], ("path",)),
])
def test_alteration_refusals(alter, words):
    with pytest.raises(ScenarioError) as e:
        ab.build_bundle(T, frag(alter=alter))
    for w in words:
        assert w in e.value.message


def test_a_schema_may_be_altered_after_its_said_is_computed():
    f = frag()
    f["schemas"][0]["alter"] = [{"path": "required", "value": ["v", "d"]}]
    b = ab.build_bundle(T, f)
    schema = json.loads(bytes.fromhex(b.request["schemas"][0]))
    assert schema["required"] == ["v", "d"]
    assert schema["$id"] == b.saids["S1"] != sa.schema_said(T, schema)


def _registry_frag():
    f = frag(registry="rip1", source_seal=None)
    f["events"] += [{"name": "ixn2", "aid": "I", "t": "ixn", "a": [{"registry": "rip1"}]},
                    {"name": "ixn3", "aid": "I", "t": "ixn", "a": [{"registry": "bup1"}]}]
    f["events"][2]["a"] = []
    f["kels"] += [{"event": "ixn2", "sigs": ["i0"]}, {"event": "ixn3", "sigs": ["i0"]}]
    f["registries"] = [
        {"name": "rip1", "t": "rip", "issuer": "I", "source_seal": "ixn2"},
        {"name": "bup1", "t": "bup", "registry": "rip1", "source_seal": "ixn3",
         "state": {"u": "s1", "td": {"acdc": "A1"}, "ts": "issued"}, "disclose": True}]
    return f


def _bup(b):
    data = bytes.fromhex(b.request["registry"][1]["stream"]).removeprefix(GENUS).decode()
    obj, end = json.JSONDecoder().raw_decode(data)
    return obj, data[end:]


def test_an_acdc_source_seal_may_be_omitted_by_null():
    b = ab.build_bundle(T, _registry_frag())
    assert presented(b)[2] == ""


def test_a_registry_event_may_be_altered_after_its_said_is_computed():
    f = _registry_frag()
    f["registries"][1]["alter"] = [{"path": "dt", "value": "2026-07-04T17:50:00.000000+00:00"}]
    b = ab.build_bundle(T, f)
    body, _ = _bup(b)
    assert body["dt"].startswith("2026") and body["d"] == b.saids["bup1"]
    assert sa.said(T, body) != body["d"]
    f["registries"][1]["alter"] = [{"path": "dt", "value": "now"}]
    with pytest.raises(ScenarioError, match="length"):
        ab.build_bundle(T, f)


def test_a_disclosed_block_may_keep_the_real_blid_over_other_content():
    f = _registry_frag()
    f["registries"][1]["disclose"] = {"td": {"nothing": "A2"}, "blid": "kept"}
    b = ab.build_bundle(T, f)
    body, att = _bup(b)
    other = keri_events.label_digest(T, "A2")
    real = sa.blinded_block(T, ab.blind(T, "s1"), b.saids["A1"], "issued")
    forged = sa.blinded_block(T, ab.blind(T, "s1"), other, "issued")
    assert att.endswith(real[:44] + forged[44:])
    assert body["b"] == real[:44]


def test_a_disclosed_block_may_carry_its_own_blid_for_other_content():
    f = _registry_frag()
    f["registries"][1]["disclose"] = {"td": {"nothing": "A2"}, "ts": "revoked", "blid": "own"}
    b = ab.build_bundle(T, f)
    body, att = _bup(b)
    own = sa.blinded_block(T, ab.blind(T, "s1"), keri_events.label_digest(T, "A2"), "revoked")
    assert att.endswith(own) and body["b"] != own[:44]


def test_a_disclosure_must_say_which_blid_it_carries():
    f = _registry_frag()
    f["registries"][1]["disclose"] = {"td": {"nothing": "A2"}}
    with pytest.raises(ScenarioError, match="blid"):
        ab.build_bundle(T, f)


def test_a_source_seal_may_name_an_event_by_a_wrong_said():
    b = ab.build_bundle(T, frag(source_seal={"event": "ixn1", "wrong_said": "x"}))
    _, _, att = presented(b)
    assert att.endswith(keri_events.label_digest(T, "x"))
    assert att.startswith("-CAS-SAR0A" + "A" * 21 + "B")


def test_a_source_seal_map_names_an_event():
    with pytest.raises(ScenarioError, match="source seal"):
        ab.build_bundle(T, frag(source_seal={"wrong_said": "x"}))
