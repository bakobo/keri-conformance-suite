"""The ACDC generator's SAID primitives: the SAID protocol over an ACDC field map, the most compact
form, schema SAIDs, the aggregate (AGID) and the blinded state block's BLID.

Every worked example in the pinned ACDC specification (tag v1.0, 4a543c5) that these primitives
can compute is reproduced here from the text itself: each test reads the example out of the pinned
file at the line it cites and recomputes it, so a wrong line number or an edited example fails the
test rather than passing silently. Where the text leaves bytes open (generators/SPEC-ISSUES.md,
A-B1 to A-B3, and A-C1 for the aggregate), each reading is a parameter, and the tests show which
reading the examples support."""

import json
import os
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from generators.spec_tables import acdc_saids as sa
from generators.spec_tables import json_schema_subset as js
from generators.spec_tables import spec_source, tables
from generators.spec_tables.errors import GeneratorError

try:
    CESR_TEXT = spec_source.load_spec()
    ACDC_TEXT = spec_source.load_spec(pin=spec_source.ACDC)
except spec_source.SpecUnavailable as e:
    if os.environ.get("KCS_REQUIRE_SPEC") == "1":
        raise
    pytest.skip(f"a pinned specification text is unavailable: {e}", allow_module_level=True)

T = tables.load(CESR_TEXT)
LINES = ACDC_TEXT.splitlines()


def _json_at(line: int):
    """The JSON value that opens on ``line`` (1-based) of the pinned ACDC text."""
    depth, out = 0, []
    for text in LINES[line - 1:]:
        out.append(text)
        depth += text.count("{") + text.count("[") - text.count("}") - text.count("]")
        if depth == 0:
            return json.loads("\n".join(out))
    raise AssertionError(f"no balanced JSON value opens on line {line}")  # pragma: no cover


def _says(line: int, value: str):
    assert value in LINES[line - 1], f"line {line} of the pinned ACDC text does not hold {value!r}"


def test_the_acdc_pin_is_the_v1_0_tag():
    pin = spec_source.ACDC
    assert (pin.name, pin.label, pin.tag) == ("ACDC", "acdc", "v1.0")
    assert pin.commit == "4a543c549fd9811c23bf97b0daaf48400f4005c2"
    assert pin.repo == "https://github.com/trustoverip/kswg-acdc-specification"
    assert spec_source.sha256(ACDC_TEXT) == pin.sha256


def test_version_string_is_the_2_00_form_of_line_64():
    assert sa.version_string(218) == "ACDCCAACAAJSONAADa."
    _says(2240, sa.version_string(218))


# -- the SAID protocol over registry events, reproduced from the text -------------------------------

@pytest.mark.parametrize("line", [
    2239,  # rip, "Blinded State Registry Example"
    2257,  # placeholder bup, n 1
    2295,  # bup issuing, n 2
    2331,  # bup revoking, n 3
    2375,  # rip, "Public Non-Blindable State Update Registry Example"
    3538,  # rip for Amy, Annex
    3553,  # rip for Bob
])
def test_registry_event_saids_reproduce_the_spec_examples(line):
    event = _json_at(line)
    assert sa.said(T, event) == event["d"]
    assert sa.version_string(len(sa.serialize(sa.saidify(T, event)))) == event["v"]
    assert sa.saidify(T, event) == event


def test_a_said_does_not_depend_on_the_values_its_fields_held_before():
    event = _json_at(2239)
    scrambled = {**event, "v": "ACDCCAACAAJSONAAAA.", "d": "x"}
    assert sa.said(T, scrambled) == event["d"]


def test_a_block_without_a_version_string_is_hashed_as_it_stands():
    block = _json_at(909)[1]  # Issuee block, line 912 holds its SAID
    _says(912, block["d"])
    assert sa.said(T, block) == block["d"]
    assert sa.block_said(T, block) == block["d"]


# -- the most compact form ------------------------------------------------------------------------

def test_the_accreditation_acdc_reproduces_its_most_compact_said_from_both_variants():
    """Lines 3679 to 3703 give the expanded ACDC and lines 3707 to 3717 its most compact form, with
    the same top-level SAID (line 3720) and, per variant, a version string sized to that variant
    (A-B1: line 62's size reading, which the example supports)."""
    expanded, compact = _json_at(3679), _json_at(3707)
    assert sa.acdc_said(T, expanded) == expanded["d"] == compact["d"]
    assert sa.acdc_said(T, compact) == compact["d"]
    assert sa.most_compact(T, expanded) == compact
    assert sa.block_said(T, expanded["a"]) == compact["a"]
    assert sa.block_said(T, expanded["r"]) == compact["r"]
    assert sa.version_string(len(sa.serialize(expanded))) == expanded["v"]


def test_the_presented_size_reading_gives_a_different_said_for_an_expanded_acdc():
    expanded, compact = _json_at(3679), _json_at(3707)
    presented = sa.Readings(compact_v="presented")
    assert sa.most_compact(T, expanded, presented)["v"] == expanded["v"]
    assert sa.acdc_said(T, expanded, presented) != expanded["d"]
    # For a compact ACDC the two readings coincide.
    assert sa.acdc_said(T, compact, presented) == compact["d"]


def test_the_ascii_reading_changes_only_non_ascii_content():
    ascii_ = sa.Readings(ascii=True)
    plain = {"d": "", "u": "x", "name": "Zoe"}
    accented = {"d": "", "u": "x", "name": "Zoë"}
    assert sa.said(T, plain, readings=ascii_) == sa.said(T, plain)
    assert sa.said(T, accented, readings=ascii_) != sa.said(T, accented)


def test_the_expanded_form_said_is_not_the_most_compact_said():
    expanded = _json_at(3679)
    assert sa.expanded_said(T, expanded) != expanded["d"]
    assert sa.expanded_said(T, expanded) == sa.said(T, expanded)


def test_nested_blocks_compact_depth_first_and_non_said_blocks_stay_expanded():
    leaf = {"d": "", "u": "0ABhY2Rjc3BlY3dvcmtyYXcw", "x": 1}
    leaf_said = sa.said(T, leaf)
    inner = {"d": "", "leaf": leaf, "plain": {"deep": leaf}}
    # A non-leaf block's SAID is computed with its SAIDed subblocks compacted, at any depth
    # below fields that are not themselves SAIDed blocks.
    expect_inner = sa.said(T, {"d": "", "leaf": leaf_said, "plain": {"deep": leaf_said}})
    assert sa.block_said(T, inner) == expect_inner
    assert sa.compact_value(T, inner) == expect_inner
    assert sa.compact_value(T, {"plain": {"k": leaf}}) == {"plain": {"k": leaf_said}}
    assert sa.compact_value(T, "x") == "x"
    # Only a dict whose d is a string is a SAIDed block.
    assert sa.compact_value(T, {"d": {"type": "string"}}) == {"d": {"type": "string"}}


def test_a_block_inside_a_list_is_left_alone_unless_the_traverse_reading_is_chosen():
    """Lines 140 to 147 compact fields whose values are blocks; a list is not a block, and the
    text says nothing of blocks inside one. The default leaves a list as it stands, which is
    also what keripy does; the other reading compacts the blocks inside it."""
    leaf = {"d": "", "u": "0ABhY2Rjc3BlY3dvcmtyYXcw", "x": 1}
    leaf_said = sa.said(T, leaf)
    traverse = sa.Readings(lists="traverse")
    assert sa.compact_value(T, [leaf, "s", 3]) == [leaf, "s", 3]
    assert sa.compact_value(T, [leaf, "s", 3], traverse) == [leaf_said, "s", 3]
    group = {"d": "", "m": [leaf]}
    assert sa.block_said(T, group) == sa.said(T, group)
    assert sa.block_said(T, group, traverse) == sa.said(T, {"d": "", "m": [leaf_said]})


def test_partial_disclosure_variants_share_the_top_level_said():
    acdc = {"v": "", "d": "", "i": "EIssuer", "s": "ESchema",
            "a": {"d": "", "u": "0ABhY2Rjc3BlY3dvcmtyYXcw", "name": "n",
                  "inner": {"d": "", "u": "0ABhY2Rjc3BlY3dvcmtyYXcx", "lei": "L"}},
            "e": {"d": "", "le": {"d": "", "n": "EFar", "s": "ESchema"}}}
    top = sa.acdc_said(T, acdc)
    partial = {**acdc, "e": sa.block_said(T, acdc["e"])}
    nested_partial = {**acdc, "a": {**acdc["a"], "inner": sa.block_said(T, acdc["a"]["inner"])}}
    assert sa.acdc_said(T, partial) == top
    assert sa.acdc_said(T, nested_partial) == top
    assert sa.most_compact(T, acdc)["d"] == top


def test_an_embedded_schema_compacts_to_its_own_said_without_entering_it():
    schema = _json_at(3725)
    acdc = {**_json_at(3707), "s": schema}
    assert sa.most_compact(T, acdc)["s"] == schema["$id"]
    assert sa.acdc_said(T, acdc) == _json_at(3707)["d"]


def test_a_most_compact_form_needs_a_version_string_under_the_presented_reading():
    with pytest.raises(GeneratorError) as e:
        sa.most_compact(T, {"d": "", "i": "x", "s": "y"}, sa.Readings(compact_v="presented"))
    assert e.value.code == sa.E_READING
    # Under the own-size reading a map without a version string is hashed without one.
    assert "v" not in sa.most_compact(T, {"d": "", "i": "x", "s": "y"})


# -- schemas --------------------------------------------------------------------------------------

def test_the_accreditation_schema_said_reproduces_under_the_compact_reading_only():
    """The schema at lines 3725 to 3803 is printed pretty; its $id (line 3726) is the SAID of its
    compact re-serialization, not of the printed bytes (A-B2)."""
    schema = _json_at(3725)
    printed = "\n".join(LINES[3724:3803]).encode()
    _says(3726, schema["$id"])
    assert sa.schema_said(T, schema) == schema["$id"]
    assert sa.schema_said(T, schema, raw=printed) == schema["$id"]  # compact ignores raw
    received = sa.Readings(schema="received")
    assert sa.schema_said(T, schema, received, raw=printed) != schema["$id"]
    compact = json.dumps(schema, separators=(",", ":")).encode()
    assert sa.schema_said(T, schema, received, raw=compact) == schema["$id"]


def test_the_received_reading_dummies_an_unfilled_id_as_the_said_protocol_does():
    """An unfilled ``"$id":""`` is dummied to 44 ``#`` in place, so over compact bytes the
    received reading agrees with the dict-based one (the SAID protocol, CESR line 1194)."""
    schema = {"$id": "", "type": "object", "title": "unfilled"}
    raw = sa.serialize(schema)
    received = sa.schema_said(T, schema, sa.Readings(schema="received"), raw=raw)
    assert received == sa.schema_said(T, schema)


def test_the_received_reading_dummies_only_the_root_id_token():
    """The root ``$id`` is found by the document's structure, not by its text: a subschema's
    ``$id`` with the same value before it, and the value inside a string, stay as they are."""
    for value in ("", "EBdXt3gIXOf2BBWNHdSXCJnFJL5OuQPyM5K0neuniccM"):
        schema = {"description": f"names {value} and \"$id\":\"{value}\"",
                  "properties": {"x": {"$id": value, "type": "string"}},
                  "$id": value, "type": "object"}
        raw = sa.serialize(schema)
        assert raw.count(value.encode()) >= 3
        received = sa.schema_said(T, schema, sa.Readings(schema="received"), raw=raw)
        assert received == sa.schema_said(T, schema)
        pretty = json.dumps(schema, indent=2).encode()
        expected = sa.digest(T, pretty.replace(f'\n  "$id": "{value}"'.encode(),
                                               f'\n  "$id": "{sa.DUMMY}"'.encode()))
        assert sa.schema_said(T, schema, sa.Readings(schema="received"), raw=pretty) == expected


def test_the_received_reading_refuses_bytes_without_one_string_root_id():
    received = sa.Readings(schema="received")
    for raw in (b'{"$id":"a","$id":"a"}', b'{"$id":3}', b'["$id"]', b'{"$id":""} x',
                b'{"x":{"$id":""}}', b'not json', b'\xff{"$id":""}', b'{"$id":"",}',
                b'{1:"","$id":""}', b'{"$id" ""}', b'{"$id":"" "a":1}', b'{"$id":""',
                b'{', b'{}'):
        with pytest.raises(GeneratorError) as e:
            sa.schema_said(T, {"$id": ""}, received, raw=raw)
        assert e.value.code == sa.E_READING, raw


def test_the_received_schema_reading_needs_the_bytes():
    with pytest.raises(GeneratorError) as e:
        sa.schema_said(T, {"$id": ""}, sa.Readings(schema="received"))
    assert e.value.code == sa.E_READING
    with pytest.raises(GeneratorError) as e:
        sa.schema_said(T, {"$id": ""}, sa.Readings(schema="received"), raw=b'{"type":"x"}')
    assert e.value.code == sa.E_READING


def test_the_accreditation_example_acdc_does_not_satisfy_its_own_example_schema():
    """A spec-example finding, not a generator rule: the schema at line 3725 requires "score" in
    the attribute section (line 3760) and names no "score" property, while the ACDC it describes
    (line 3679) has "level" and no "score". The schema also uses additionalProperties, which is
    outside the declared subset, so the generator would refuse it as a scenario schema."""
    schema, acdc = _json_at(3725), _json_at(3679)
    _says(3760, "\"score\", \"name\"")
    with pytest.raises(GeneratorError) as e:
        js.check(schema)
    assert e.value.code == js.E_KEYWORD

    def strip(node):
        if isinstance(node, dict):
            return {k: strip(v) for k, v in node.items()
                    if k not in ("additionalProperties", "credentialType")}
        if isinstance(node, list):
            return [strip(v) for v in node]
        return node

    reduced = strip(schema)
    assert not js.validate(reduced, acdc)
    assert js.validate(reduced, {**acdc, "a": {**acdc["a"], "score": 1}})


# -- the aggregate --------------------------------------------------------------------------------

def test_the_agid_reproduces_the_line_954_example_under_the_list_reading():
    preimage = _json_at(954)
    _says(929, "EN5d44fTNM0M4kmMMVrsH0HwMLRLyb6SoJEV0ogkLdXx")
    assert preimage[0] == sa.DUMMY
    assert sa.agid(T, preimage[1:]) == "EN5d44fTNM0M4kmMMVrsH0HwMLRLyb6SoJEV0ogkLdXx"
    # A bare concatenation of the SAIDs (line 110) gives a different digest.
    concat = sa.Readings(aggregate="concat")
    assert sa.agid(T, preimage[1:], concat) != "EN5d44fTNM0M4kmMMVrsH0HwMLRLyb6SoJEV0ogkLdXx"


def test_the_aggregate_list_and_selective_disclosure_reproduce_the_example():
    full, selective = _json_at(909), _json_at(962)
    assert sa.aggregate(T, full[1:]) == [full[0]] + [b["d"] for b in full[1:]]
    assert sa.aggregate(T, selective[1:]) == sa.aggregate(T, full[1:])
    assert sa.compact_value(T, full, sa.Readings(lists="traverse")) == sa.aggregate(T, full[1:])
    acdc = {"v": "", "d": "", "i": "EIssuer", "s": "ESchema", "A": full}
    compact = {"v": "", "d": "", "i": "EIssuer", "s": "ESchema", "A": full[0]}
    assert sa.most_compact(T, acdc)["A"] == full[0]
    assert sa.acdc_said(T, acdc) == sa.acdc_said(T, compact)
    assert sa.acdc_said(T, {**acdc, "A": selective}) == sa.acdc_said(T, compact)


def test_a_wrong_agid_in_the_list_does_not_survive_compaction():
    full = _json_at(909)
    forged = [sa.DUMMY.replace("#", "E")] + full[1:]
    assert sa.most_compact(T, {"d": "", "i": "x", "s": "y", "A": forged})["A"] == full[0]


# -- blinded state blocks -------------------------------------------------------------------------

@pytest.mark.parametrize("line,u,td,ts,blid", [
    (2167, "aG1lSjdJSNl7TiroPl67Uqzd5eFvzmr6bPlL7Lh4ukv8", "", "",
     "ECVr7QWEp_aqVQuz4yprRFXVxJ-9uWLx_d6oDinlHU6J"),
    (2210, "aLfCdNAnc-0P2SiruarZSajXiUWu5iU2VfQahvpNCyzB",
     "EMLjZLIMlfUOoKox_sDwQaJO-0wdoGW0uNbmI28Wwc4M", "issued",
     "EOtWw6X_aoOJlkzNaLj23IC6MXHl7ZSYSWVulFW_Hr_t"),
    (2347, "aGx7b16vGHVPT56tX30kYOEzTwiVY4aabc4k9AawYyZG",
     "EMLjZLIMlfUOoKox_sDwQaJO-0wdoGW0uNbmI28Wwc4M", "revoked",
     "EPj3sZj8OOWTkTgAN5vzVYdANeoj3zxgEn5APb8fCRRN"),
])
def test_blids_reproduce_the_spec_examples_under_the_tag_reading(line, u, td, ts, blid):
    _says(line, blid)
    assert sa.blid(T, u, td, ts) == blid
    block = sa.blinded_block(T, u, td, ts)
    assert block.startswith(blid + u)
    assert block in ACDC_TEXT  # the expanded block appears verbatim in the text


def test_the_bup_examples_commit_to_the_example_blids():
    assert _json_at(2295)["b"] == sa.blid(T, "aLfCdNAnc-0P2SiruarZSajXiUWu5iU2VfQahvpNCyzB",
                                          "EMLjZLIMlfUOoKox_sDwQaJO-0wdoGW0uNbmI28Wwc4M", "issued")


@pytest.mark.parametrize("state,tag", [
    ("", "1AAP"), ("ab", "0Kab"), ("abc", "Xabc"), ("abcd", "1AAFabcd"), ("issued", "0Missued"),
    ("revoked", "Yrevoked"), ("abcdefgh", "1AANabcdefgh"), ("abcdefghij", "0Oabcdefghij"),
    ("abcdefghijk", "Zabcdefghijk"),
])
def test_state_values_use_the_tag_codes(state, tag):
    assert sa.state_primitive(T, state) == tag


@pytest.mark.parametrize("state", ["a", "abcde", "abcdefghi"])
def test_a_tag_that_needs_a_pre_pad_character_is_refused(state):
    with pytest.raises(GeneratorError) as e:
        sa.state_primitive(T, state)
    assert e.value.code == sa.E_STATE


@pytest.mark.parametrize("state", ["abcdefghijkl", "is sued", "naïve"])
def test_a_state_no_tag_can_carry_is_refused(state):
    with pytest.raises(GeneratorError) as e:
        sa.state_primitive(T, state)
    assert e.value.code == sa.E_STATE


def test_the_other_candidate_state_codes_give_other_blids():
    u, td = "aLfCdNAnc-0P2SiruarZSajXiUWu5iU2VfQahvpNCyzB", "EMLjZLIMlfUOoKox_sDwQaJO-0wdoGW0uNbmI28Wwc4M"
    strb64, raw = sa.Readings(ts_code="strb64"), sa.Readings(ts_code="bytes")
    assert sa.state_primitive(T, "issued", strb64) == "5AACAAissued"
    assert sa.state_primitive(T, "issued", raw) == "4BACaXNzdWVk"
    blids = {sa.blid(T, u, td, "issued", r) for r in (sa.DEFAULT, strb64, raw)}
    assert len(blids) == 3
    # The empty placeholder's code is fixed by line 2087 under every reading.
    assert {sa.state_primitive(T, "", r) for r in (sa.DEFAULT, strb64, raw)} == {"1AAP"}
    with pytest.raises(GeneratorError):
        sa.state_primitive(T, "is sued", strb64)


def test_a_transaction_said_must_be_a_qualified_digest_or_empty():
    with pytest.raises(GeneratorError) as e:
        sa.blid(T, "aLfCdNAnc-0P2SiruarZSajXiUWu5iU2VfQahvpNCyzB", "not a said", "issued")
    assert e.value.code == sa.E_STATE


# -- readings -------------------------------------------------------------------------------------

@pytest.mark.parametrize("field,value", [("compact_v", "both"), ("schema", "pretty"),
                                         ("ts_code", "label"), ("aggregate", "merkle"),
                                         ("ascii", "yes"), ("lists", "flatten")])
def test_an_unknown_reading_is_refused(field, value):
    with pytest.raises(GeneratorError) as e:
        sa.Readings(**{field: value})
    assert e.value.code == sa.E_READING


def test_the_default_readings_are_the_designs():
    d = sa.DEFAULT
    assert (d.compact_v, d.ascii, d.schema, d.ts_code, d.aggregate, d.lists) == (
        "own", False, "compact", "tag", "list", "opaque")
    assert set(sa.CANDIDATES) == {"compact_v", "ascii", "schema", "ts_code", "aggregate",
                                  "lists"}
    for field, values in sa.CANDIDATES.items():
        assert getattr(d, field) == values[0]
