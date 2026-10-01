"""The scenario builder, the reference parser it is checked against, and the regeneration
driver. The committed cases exercise the happy paths; these tests pin each refusal, because a
generator that quietly accepts a malformed scenario or a parser that quietly accepts a malformed
stream would let a wrong expectation into the suite."""

import json
import os
import pathlib
import runpy
import shutil
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from generators.spec_tables import (
    b64,
    build,
    decoding,
    encoding,
    keripy1x,
    regenerate,
    spec_source,
    tables,
)

try:
    SPEC = spec_source.load_spec()
except spec_source.SpecUnavailable as e:
    if os.environ.get("KCS_REQUIRE_SPEC") == "1":
        raise
    pytest.skip(f"the pinned CESR specification text is unavailable: {e}", allow_module_level=True)

T = tables.load(SPEC)
GENUS = b"-_AAACAA"
SIG = encoding.indexed(T, "A", bytes(64), 0).encode()
KEY = encoding.primitive(T, "D", bytes(32)).encode()


def parse(stream: bytes, legacy=None, one_x=None):
    return decoding.Parser(T, legacy, one_x).parse(stream)


def rejected(stream: bytes, legacy=None) -> str:
    with pytest.raises(decoding.Rejected) as e:
        parse(stream, legacy)
    return e.value.cls


def body(fields: dict, size: int | None = None, kind: str = "JSON") -> bytes:
    def vs(n):
        return f"KERICAACAA{kind}{b64.int_to_b64(n, 4)}."

    fields = {"v": vs(0), **fields}
    n = len(json.dumps(fields, separators=(",", ":")).encode())
    fields["v"] = vs(size if size is not None else n)
    return json.dumps(fields, separators=(",", ":")).encode()


# --- The reference parser refuses each malformed stream -------------------------------------


def test_a_digit_cannot_start_a_top_level_frame():
    assert rejected(GENUS + b"0BAA") == "bad-frame-start"


def test_non_base64_text_is_refused():
    assert rejected(GENUS + b"-J!!") == "bad-frame-start"


def test_count_code_before_any_genus_code_is_refused():
    assert rejected(b"-JAA") == "unsupported"


def test_genus_version_other_than_aaa_2_00_is_refused():
    assert rejected(b"-_AAABAA") == "unsupported"


def test_genus_code_inside_a_non_overrideable_group_is_refused():
    assert rejected(GENUS + b"-JAC" + GENUS) == "unsupported"


def test_genus_code_not_first_in_an_overrideable_group_is_refused():
    assert rejected(GENUS + b"-AAD" + b"-JAA" + GENUS) == "unsupported"


def test_genus_override_to_1_00_needs_the_1_00_table():
    assert rejected(GENUS + b"-CAC" + b"-_AAABAA") == "unsupported"


def test_genus_override_applies_inside_its_group_and_ends_with_it():
    stream = GENUS + b"-CAZ-_AAABAA-AAB" + SIG + b"-CAX-KAW" + SIG
    items = parse(stream, one_x=keripy1x.TABLE)
    assert [i.get("code") for i in items] == ["-_AAACAA", "-C", "-_AAABAA", "-A", "A", "-C", "-K", "A"]
    assert items[2] == {"kind": "genus", "start": 12, "end": 20, "code": "-_AAABAA",
                        "genus": "AAA", "version": "1.00"}


def test_top_level_genus_code_switches_tables_for_the_rest_of_the_stream():
    items = parse(b"-_AAABAA-AAB" + SIG, one_x=keripy1x.TABLE)
    stream = b"-_AAABAA-AAB" + SIG
    assert items[1]["size"] == 1 and items[1]["group_end"] == len(stream)


def test_letter_count_code_outside_the_table_is_refused():
    assert rejected(GENUS + b"-dAA") == "unknown-code"


def test_nested_group_running_past_its_parent_is_refused():
    assert rejected(GENUS + b"-JAB" + b"-JAB" + b"AAAA") == "group-boundary"


def test_primitive_with_no_table_selector_is_refused():
    assert rejected(GENUS + b"-JAB" + b"_AAA") == "unknown-code"


def test_primitive_code_outside_the_master_table_is_refused():
    assert rejected(GENUS + b"-JAL" + b"b" + KEY[1:]) == "unknown-code"


def test_indexed_code_outside_the_indexed_table_is_refused():
    assert rejected(GENUS + b"-KAW" + b"E" + SIG[1:]) == "unknown-code"


def test_message_without_a_version_string_is_refused():
    assert rejected(b'{"x":"KERICAACAAJSONAAAA."}') == "malformed-message"


def test_message_of_another_serialization_is_not_framed_here():
    assert rejected(body({"t": "x"}, kind="CBOR")) == "unsupported"


def test_message_body_that_is_not_json_is_refused():
    good = body({"t": "x"})
    assert rejected(good[:-1] + b",") == "malformed-message"


def test_message_crossing_its_group_end_is_refused():
    msg = body({"t": "x"})
    assert rejected(GENUS + b"-CAB" + msg) == "group-boundary"


def test_binary_op_code_is_refused():
    assert rejected(bytes([0xFC, 0, 0])) == "unsupported"


def test_byte_that_starts_no_frame_is_refused():
    assert rejected(b"\x00") == "bad-frame-start"


def test_legacy_unknown_count_code_is_refused():
    assert rejected(b"-ZAB" + SIG, keripy1x.TABLE) == "unknown-code"


def test_legacy_item_count_past_the_stream_is_refused():
    assert rejected(b"-AAC" + SIG, keripy1x.TABLE) == "count-overrun"


def test_binary_counter_inside_a_binary_group_is_found():
    stream = encoding.to_binary(
        "-_AAACAA" + encoding.counter(T, "-J", 12) + encoding.counter(T, "-J", 11)
        + encoding.primitive(T, "D", bytes(32))
    )
    items = parse(stream)
    assert [i["code"] for i in items] == ["-_AAACAA", "-J", "-J", "D"]
    assert items[2]["group_end"] == len(stream)


# --- The builder refuses malformed scenarios ------------------------------------------------


def test_clause_with_an_unknown_level_is_refused():
    with pytest.raises(build.ScenarioError, match="has level"):
        build.resolve_clauses({"x": {"level": "OUGHT", "section": "", "quote": ""}}, SPEC)


def test_clause_under_the_wrong_heading_is_refused():
    clause = {"level": "MUST", "section": "Text Code Size",
              "quote": "The size component MUST count the Quadlets/triplets in its following group."}
    with pytest.raises(build.ScenarioError, match="not 'Text Code Size'"):
        build.resolve_clauses({"x": clause}, SPEC)


def test_clause_whose_quote_does_not_state_its_level_is_refused():
    clause = {"level": "SHOULD", "section": "Count Code tables",
              "quote": "The size component MUST count the Quadlets/triplets in its following group."}
    with pytest.raises(build.ScenarioError, match="does not say so"):
        build.resolve_clauses({"x": clause}, SPEC)


def test_unknown_tamper_is_refused():
    with pytest.raises(build.ScenarioError, match="Unknown tamper"):
        build.StreamBuilder(T).node({"primitive": "D", "raw": "x", "tamper": "flip"})


def test_unknown_stream_element_is_refused():
    with pytest.raises(build.ScenarioError, match="Unknown stream element"):
        build.StreamBuilder(T).node({"widget": 1})


CLAUSES = build.resolve_clauses(
    json.loads((ROOT / "scenarios" / "cesr" / "clauses.json").read_text(encoding="utf-8"))["clauses"],
    SPEC,
)


def _case(**over):
    case = {
        "id": "CESR-9999", "key": "k", "title": "t", "description": "d", "profile": "cesr-1.0",
        "operation": "cesr.parse",
        "stream": [{"genus": "AAA", "major": 2, "minor": 0},
                   {"group": "-J", "items": [{"primitive": "D", "raw": "x"}]}],
        "assertions": [{"check": "decoded", "clause": "count-quadlets"}],
    }
    case.update(over)
    return case


def test_unsupported_operation_is_refused():
    with pytest.raises(build.ScenarioError, match="Unsupported operation"):
        build.build_case(T, "s", _case(operation="keri.process"), CLAUSES, None, None)


def test_check_that_does_not_fit_the_operation_is_refused():
    case = _case(assertions=[{"check": "encoded", "clause": "count-quadlets"}])
    with pytest.raises(build.ScenarioError, match="does not fit"):
        build.build_case(T, "s", case, CLAUSES, None, None)


def test_rejection_expected_of_a_stream_that_parses_is_refused():
    case = _case(assertions=[{"check": "rejected", "clause": "count-quadlets"}])
    with pytest.raises(build.ScenarioError, match="expected a rejection"):
        build.build_case(T, "s", case, CLAUSES, None, None)


def test_builder_and_reference_parser_must_agree():
    built = build.build_case(T, "s", _case(), CLAUSES, None, None)
    built["assertions"][0]["expected"][1]["size"] = 2  # an item-counting answer
    with pytest.raises(build.ScenarioError, match="disagrees"):
        build.check_case(T, built, None)


def test_raw_values_are_shake256_of_the_label():
    import hashlib

    assert build.raw_bytes("kcs", 5) == hashlib.shake_256(b"kcs").digest(5)


# --- Regeneration ---------------------------------------------------------------------------


@pytest.fixture
def tree(tmp_path):
    shutil.copytree(ROOT / "scenarios", tmp_path / "scenarios")
    return tmp_path


def _scenario(tree, name, cases, **extra):
    path = tree / "scenarios" / "cesr" / name
    path.write_text(json.dumps({"about": "test", "profile": "cesr-1.0", "cases": cases, **extra}))


def test_generate_refuses_a_duplicate_case_id(tree):
    _scenario(tree, "zz.json", [_case(id="CESR-0001")])
    with pytest.raises(build.ScenarioError, match="used twice"):
        regenerate.generate(tree)


def test_generate_refuses_an_unknown_profile(tree):
    _scenario(tree, "zz.json", [_case(id="CESR-0051", profile="nope")])
    with pytest.raises(build.ScenarioError, match="unknown profile"):
        regenerate.generate(tree)


def test_generate_refuses_an_undocumented_gap(tree):
    _scenario(tree, "zz.json", [_case(id="CESR-0053")])
    with pytest.raises(build.ScenarioError, match="undocumented gaps"):
        regenerate.generate(tree)


def test_generate_accepts_a_documented_gap(tree):
    _scenario(tree, "zz.json", [_case(id="CESR-0053")],
              id_gaps=[{"number": n, "reason": "test"} for n in range(49, 53)])
    files = regenerate.generate(tree)
    assert "cases/cesr/CESR-0053.json" in files


def test_generate_with_no_scenarios_produces_only_empty_profiles(tmp_path):
    (tmp_path / "scenarios" / "cesr").mkdir(parents=True)
    shutil.copy(ROOT / "scenarios" / "cesr" / "clauses.json", tmp_path / "scenarios" / "cesr")
    files = regenerate.generate(tmp_path)
    assert sorted(files) == ["profiles/cesr-1.0.json", "profiles/cesr-strict.json",
                             "profiles/keripy-1x-interop.json"]


def test_differences_names_missing_extra_and_differing_files():
    lines = regenerate.differences({"a": b"1", "b": b"2"}, {"b": b"3", "c": b"4"})
    assert lines == [
        "missing: a is generated but not committed",
        "differs: b does not match what its scenario generates",
        "extra: c is committed but no scenario generates it",
    ]


def test_write_and_committed_round_trip(tmp_path):
    files = {"cases/cesr/CESR-0001.json": b"{}\n", "profiles/cesr-1.0.json": b"[]\n"}
    regenerate.write(tmp_path, files)
    assert regenerate.committed(tmp_path) == files


def test_script_writes_under_out(tmp_path, capsys):
    script = runpy.run_path(str(ROOT / "scripts" / "regenerate"))
    assert script["main"](["--out", str(tmp_path)]) == 0
    assert (tmp_path / "cases" / "cesr" / "CESR-0025.json").exists()
    assert "Wrote" in capsys.readouterr().out


def test_script_check_fails_and_lists_differences(monkeypatch, capsys):
    script = runpy.run_path(str(ROOT / "scripts" / "regenerate"))
    monkeypatch.setattr(script["regenerate"], "differences", lambda want, have: ["differs: x"])
    assert script["main"](["--check"]) == 1
    out = capsys.readouterr().out
    assert "differs: x" in out and "never edit a case by hand" in out


def test_script_check_passes_on_the_committed_tree(capsys):
    script = runpy.run_path(str(ROOT / "scripts" / "regenerate"))
    assert script["main"](["--check"]) == 0
    assert "match the committed ones" in capsys.readouterr().out


def test_literal_text_inside_a_group_counts_toward_its_size_but_reports_no_item():
    text, items = build.StreamBuilder(T).node({"group": "-J", "items": [{"literal": "AAAA"}]})
    assert text == "-JABAAAA"
    assert items == [{"kind": "counter", "start": 0, "end": 4, "code": "-J", "size": 1,
                      "group_end": 8}]


def test_genus_override_must_be_first_in_an_overrideable_group():
    with pytest.raises(build.ScenarioError, match="overrides only as the first"):
        build.StreamBuilder(T).node({"group": "-J", "items": [{"genus": "AAA", "major": 2,
                                                               "minor": 0}]})


def test_builder_switches_to_the_1_00_table_inside_an_override():
    sb = build.StreamBuilder(T, one_x=keripy1x.TABLE)
    text, _ = sb.node({"group": "-C", "items": [
        {"genus": "AAA", "major": 1, "minor": 0},
        {"group": "-A", "items": [{"indexed": "A", "raw": "x", "index": 0}]}]})
    assert text.startswith("-CAZ-_AAABAA-AAB")
    assert sb.legacy is None  # the override ended with the group


def test_datetime_element_uses_the_1aag_code():
    text, items = build.StreamBuilder(T).node({"datetime": "2026-01-01T00:00:00.000000+00:00"})
    assert text == "1AAG2026-01-01T00c00c00d000000p00c00"
    assert items[0]["raw"] == b64.decode(text[4:]).hex()


def test_only_inception_bodies_are_built():
    with pytest.raises(build.ScenarioError, match="Only icp"):
        build.StreamBuilder(T).message({"ilk": "rot"})


def test_named_messages_resolve_and_carry_a_verifiable_said():
    from generators.spec_tables import blake3

    m = {"proto": "KERI", "version": [2, 0], "genus_version": [2, 0], "keys": ["a"],
         "kt": "1", "next": ["b"], "nt": "1"}
    body, item = build.StreamBuilder(T, messages={"m": m}).message("m")
    fields = json.loads(body)
    assert list(fields) == ["v", "t", "d", "i", "s", "kt", "k", "nt", "n", "bt", "b", "c", "a"]
    said = fields["d"]
    dummied = body.replace(said.encode(), b"#" * 44)
    assert encoding.primitive(T, "E", blake3.digest(dummied)) == said == fields["i"]
    assert item["size"] == len(body) and fields["v"].startswith("KERICAACAAJSON")


def test_blake3_refuses_more_than_one_chunk():
    from generators.spec_tables import blake3

    with pytest.raises(ValueError, match="at most 1024"):
        blake3.digest(bytes(1025))


def test_variable_size_element_reports_its_hard_code_and_raw_without_lead_bytes():
    text, items = build.StreamBuilder(T).node({"variable": "B", "raw": "v", "length": 7})
    assert text.startswith("6BAD") and len(text) == 16
    assert items[0]["code"] == "6B" and len(bytes.fromhex(items[0]["raw"])) == 7


def test_a_level_below_the_clause_needs_an_inference():
    case = _case(assertions=[{"check": "decoded", "clause": "count-quadlets", "level": "SHOULD"}])
    with pytest.raises(build.ScenarioError, match="without an inference"):
        build.build_case(T, "s", case, CLAUSES, None, None)


def test_an_inference_must_be_graded_should():
    case = _case(assertions=[{"check": "decoded", "clause": "count-quadlets",
                              "inferred_from": "count-quadlets"}])
    with pytest.raises(build.ScenarioError, match="graded SHOULD"):
        build.build_case(T, "s", case, CLAUSES, None, None)


def test_conflict_record_under_the_wrong_heading_is_refused():
    record = {"section": "Text Code Size", "why": "w",
              "quote": "The size component MUST count the Quadlets/triplets in its following group."}
    with pytest.raises(build.ScenarioError, match="not 'Text Code Size'"):
        build.resolve_records({"x": record}, SPEC, "why")
