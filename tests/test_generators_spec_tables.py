"""The spec-table generator reads the CESR code tables from the pinned specification text and
encodes from them. These tests pin the encoding rules the specification states, so that a case's
expected value is the specification's answer and not the generator's accident.

Each test names the rule it checks. Where the specification gives a worked example, the test uses
it verbatim.
"""

import os
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from generators.spec_tables import b64, encoding, spec_source, tables


def spec_text() -> str:
    """The pinned spec text from the cache, fetched if need be; skipped with the reason when it
    cannot be had, unless KCS_REQUIRE_SPEC=1, when the failure stands."""
    try:
        return spec_source.load_spec()
    except spec_source.SpecUnavailable as e:
        if os.environ.get("KCS_REQUIRE_SPEC") == "1":
            raise
        pytest.skip(f"the pinned CESR specification text is unavailable: {e}")

# --- Base64 integers and the URL-safe alphabet -------------------------------------------------


def test_alphabet_is_rfc4648_url_safe_in_order():
    assert b64.ALPHABET == (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    )


@pytest.mark.parametrize(
    ("value", "length", "text"),
    [(0, 1, "A"), (63, 1, "_"), (1, 2, "AB"), (64, 2, "BA"), (4095, 2, "__"), (8192, 3, "CAA"),
     (0, 0, "")],
)
def test_int_to_b64_is_big_endian_base64_digits(value, length, text):
    assert b64.int_to_b64(value, length) == text
    assert b64.b64_to_int(text) == value


def test_int_to_b64_refuses_a_value_that_does_not_fit():
    with pytest.raises(ValueError, match="does not fit"):
        b64.int_to_b64(4096, 2)


def test_int_to_b64_refuses_a_negative_value():
    with pytest.raises(ValueError, match="negative"):
        b64.int_to_b64(-1, 2)


def test_b64_to_int_refuses_a_character_outside_the_alphabet():
    with pytest.raises(ValueError, match="not a Base64"):
        b64.b64_to_int("A=")


def test_encode_and_decode_are_naive_base64_without_padding():
    assert b64.encode(b"\x00\x00\x01") == "AAAB"
    assert b64.decode("AAAB") == b"\x00\x00\x01"
    assert b64.encode(b"\xfb\xff") == "-_8"


def test_decode_refuses_text_that_is_not_a_whole_number_of_quadlets():
    with pytest.raises(ValueError, match="multiple of 4"):
        b64.decode("AAA")


def test_decode_refuses_characters_outside_the_url_safe_alphabet():
    with pytest.raises(ValueError, match="not a Base64"):
        b64.decode("AA+/")


# --- Reading the tables out of the pinned specification --------------------------------------


def test_cached_spec_is_the_pinned_commit():
    text = spec_text()
    assert spec_source.SPEC_COMMIT == "037129608b9e6960858b752019ac273d40d7386c"
    assert spec_source.sha256(text) == spec_source.SPEC_SHA256


def test_slugify_matches_github_heading_anchors():
    assert spec_source.slugify("Count Code tables") == "count-code-tables"
    assert (
        spec_source.slugify(
            "Master code table for genus/version `-_AAACAA` (KERI/ACDC protocol stack Version 2.00)"
        )
        == "master-code-table-for-genusversion--_aaacaa-keriacdc-protocol-stack-version-200"
    )
    assert spec_source.slugify("Version 2.XX string field format") == "version-2xx-string-field-format"


def test_section_of_a_quote_is_its_nearest_preceding_heading():
    text = spec_text()
    quote = "The size component MUST count the Quadlets/triplets in its following group."
    line = spec_source.find_quote(text, quote)
    assert line == 591
    heading = spec_source.section_of_line(text, line)
    assert heading.text == "Count Code tables"
    assert heading.anchor == "count-code-tables"


def test_find_quote_refuses_a_quote_that_is_not_verbatim():
    text = spec_text()
    with pytest.raises(LookupError, match="not found verbatim"):
        spec_source.find_quote(text, "The size component MUST count the primitives.")


def test_find_quote_refuses_a_quote_that_appears_twice():
    with pytest.raises(LookupError, match="more than once"):
        spec_source.find_quote("# A\nsame\nsame\n", "same")


def test_heading_anchor_disambiguates_repeated_headings_like_github():
    text = "## Examples\nx\n## Examples\ny\n"
    heads = spec_source.headings(text)
    assert [h.anchor for h in heads] == ["examples", "examples-1"]


def test_section_of_line_before_any_heading_is_refused():
    with pytest.raises(LookupError, match="no heading"):
        spec_source.section_of_line("text\n# H\n", 1)


def test_table_after_heading_reads_rows_and_strips_backticks():
    text = "### T\n\n| a | b |\n|:-:|:-:|\n| `x` | 1 |\n|  |  |\n| y | 2 |\n\nafter\n"
    assert spec_source.table_after(text, "T") == [["x", "1"], ["", ""], ["y", "2"]]


def test_table_after_refuses_a_missing_heading():
    with pytest.raises(LookupError, match="no heading"):
        spec_source.table_after("# A\n", "B")


def test_table_after_refuses_a_heading_with_no_table():
    with pytest.raises(LookupError, match="no table"):
        spec_source.table_after("# A\ntext\n# B\n", "A")


@pytest.fixture(scope="module")
def t():
    return tables.load(spec_text())


def test_selector_sizes_come_from_the_encoding_scheme_formats(t):
    # `$&&&` one-char fixed; `*$&&` two-char; `*$$$%&&&` large fixed one lead byte;
    # `*$##%%&&` small variable two lead bytes; `**$#####` large count; `**$$$###` genus.
    assert t.scheme_for_code("D") == tables.Scheme(hs=1, ss=0, ls=0)
    assert t.scheme_for_code("0B") == tables.Scheme(hs=2, ss=0, ls=0)
    assert t.scheme_for_code("1AAB") == tables.Scheme(hs=4, ss=0, ls=0)
    assert t.scheme_for_code("2AAA") == tables.Scheme(hs=4, ss=0, ls=1)
    assert t.scheme_for_code("6B") == tables.Scheme(hs=2, ss=2, ls=2)
    assert t.scheme_for_code("9AAB") == tables.Scheme(hs=4, ss=4, ls=2)
    assert t.count_scheme("-K") == tables.Scheme(hs=2, ss=2, ls=0)
    assert t.count_scheme("--K") == tables.Scheme(hs=3, ss=5, ls=0)
    assert t.count_scheme("-_AAA") == tables.Scheme(hs=5, ss=3, ls=0)


def test_scheme_for_unknown_selector_is_refused(t):
    with pytest.raises(KeyError, match="selector"):
        t.scheme_for_code("_A")


def test_master_table_primitives_have_the_spec_total_lengths(t):
    assert t.primitives["D"].fs == 44
    assert t.primitives["0B"].fs == 88
    assert t.primitives["1AAB"].fs == 48
    assert t.primitives["1AAE"].fs == 156
    assert t.primitives["M"].fs == 4
    assert t.primitives["4B"].fs is None  # variable size
    assert "b" not in t.primitives  # unassigned one-character code


def test_raw_size_follows_from_full_size_code_size_and_lead_bytes(t):
    assert t.raw_size("D") == 32
    assert t.raw_size("0B") == 64
    assert t.raw_size("0A") == 16
    assert t.raw_size("1AAB") == 33
    assert t.raw_size("1AAD") == 57
    assert t.raw_size("1AAE") == 114
    assert t.raw_size("M") == 2


def test_raw_size_of_a_variable_code_is_refused(t):
    with pytest.raises(ValueError, match="variable"):
        t.raw_size("5B")


def test_count_codes_are_read_for_genus_2_00(t):
    assert t.count_codes["-K"] == "Indexed controller signature group up to 4,095 quadlets/triplets"
    assert "--K" in t.count_codes
    assert "-J" in t.count_codes and "--J" in t.count_codes
    assert "-c" in t.count_codes
    assert "-d" not in t.count_codes


def test_indexed_codes_come_from_the_annex_table(t):
    a = t.indexed["A"]
    assert (a.cs, a.ms, a.os, a.fs) == (2, 1, 0, 88)
    big = t.indexed["2B"]
    assert (big.cs, big.ms, big.os, big.fs) == (6, 2, 2, 92)
    ed448 = t.indexed["0A"]
    assert (ed448.cs, ed448.ms, ed448.os, ed448.fs) == (4, 1, 1, 156)
    assert t.indexed["3A"].fs == 160
    assert "E" not in t.indexed  # keripy has it; spec v1.0 does not


# --- Encoding rules ------------------------------------------------------------------------------


def test_spec_example_short_number_text_and_binary(t):
    # "Examples of pre-padding": ("M", 0x0001) -> "MAAB" -> 0x300001, and ("M", 0xffff) -> "MP__".
    assert encoding.primitive(t, "M", bytes.fromhex("0000")) == "MAAA"
    assert encoding.primitive(t, "M", bytes.fromhex("0001")) == "MAAB"
    assert encoding.primitive(t, "M", bytes.fromhex("ffff")) == "MP__"
    assert encoding.to_binary("MAAB") == bytes.fromhex("300001")


def test_one_lead_pad_character_is_replaced_by_a_one_character_code(t):
    raw = bytes(range(32))
    text = encoding.primitive(t, "D", raw)
    assert len(text) == 44 and text[0] == "D"
    # The value is right aligned: the conversion of one zero byte plus raw, minus its first char.
    assert text[1:] == b64.encode(b"\x00" + raw)[1:]


def test_two_pad_characters_are_replaced_by_a_two_character_code(t):
    raw = bytes(range(64))
    text = encoding.primitive(t, "0B", raw)
    assert len(text) == 88 and text.startswith("0B")
    assert text[2:] == b64.encode(b"\x00\x00" + raw)[2:]


def test_zero_pad_four_character_code_is_prepended(t):
    raw = bytes(range(33))
    text = encoding.primitive(t, "1AAB", raw)
    assert text == "1AAB" + b64.encode(raw)


def test_lead_bytes_are_zero_bytes_before_the_raw_value(t):
    raw = bytes(range(1, 8))  # 7 bytes: lead size 2 to reach 9
    text = encoding.variable(t, "B", raw)
    assert text == "6BAD" + b64.encode(b"\x00\x00" + raw)
    assert encoding.variable(t, "B", bytes(range(1, 9))) == "5BAD" + b64.encode(b"\x00" + bytes(range(1, 9)))
    assert encoding.variable(t, "B", bytes(range(1, 10))) == "4BAD" + b64.encode(bytes(range(1, 10)))


def test_variable_size_beyond_small_table_uses_the_large_table(t):
    raw = bytes(4096 * 3)
    text = encoding.variable(t, "B", raw)
    assert text.startswith("7AABABAA")


def test_variable_encoding_refuses_a_type_with_no_variable_code(t):
    with pytest.raises(KeyError, match="no variable-size code"):
        encoding.variable(t, "Z", b"abc")


def test_primitive_refuses_a_raw_value_of_the_wrong_size(t):
    with pytest.raises(ValueError, match="raw size"):
        encoding.primitive(t, "D", bytes(31))


def test_primitive_refuses_a_code_not_in_the_master_table(t):
    with pytest.raises(KeyError, match="not in the master table"):
        encoding.primitive(t, "b", bytes(32))


def test_primitive_refuses_a_variable_code(t):
    with pytest.raises(ValueError, match="variable"):
        encoding.primitive(t, "4B", bytes(3))


def test_every_fixed_primitive_is_a_whole_number_of_quadlets(t):
    for code, prim in t.primitives.items():
        if prim.fs is None or prim.special:
            continue
        text = encoding.primitive(t, code, bytes(t.raw_size(code)))
        assert len(text) == prim.fs, code
        assert len(text) % 4 == 0, code
        assert len(encoding.to_binary(text)) % 3 == 0, code


def test_count_code_text_is_code_plus_base64_size(t):
    assert encoding.counter(t, "-K", 44) == "-KAs"
    assert encoding.counter(t, "--K", 44) == "--KAAAAs"
    assert encoding.to_binary("-KAs") == bytes.fromhex("f8a02c")


def test_count_code_refuses_a_size_that_does_not_fit(t):
    with pytest.raises(ValueError, match="does not fit"):
        encoding.counter(t, "-K", 4096)


def test_count_code_refuses_an_unknown_code(t):
    with pytest.raises(KeyError, match="not a genus 2.00 count code"):
        encoding.counter(t, "-d", 1)


def test_genus_version_code(t):
    assert encoding.genus_version("AAA", 2, 0) == "-_AAACAA"
    assert encoding.genus_version("AAA", 2, 16) == "-_AAACAQ"


def test_indexed_signature_single_index(t):
    raw = bytes(range(64))
    text = encoding.indexed(t, "A", raw, index=5)
    assert text[:2] == "AF" and len(text) == 88
    assert text[2:] == b64.encode(b"\x00\x00" + raw)[2:]


def test_indexed_signature_dual_index(t):
    raw = bytes(range(64))
    text = encoding.indexed(t, "2A", raw, index=65, ondex=70)
    assert text[:6] == "2ABBBG" and len(text) == 92


def test_indexed_refuses_an_ondex_on_a_code_without_an_ondex_field(t):
    with pytest.raises(ValueError, match="no ondex field"):
        encoding.indexed(t, "A", bytes(64), index=0, ondex=0)


def test_indexed_refuses_a_missing_ondex_on_a_code_with_an_ondex_field(t):
    with pytest.raises(ValueError, match="needs an ondex"):
        encoding.indexed(t, "2A", bytes(64), index=0)


def test_indexed_refuses_an_index_that_does_not_fit(t):
    with pytest.raises(ValueError, match="does not fit"):
        encoding.indexed(t, "A", bytes(64), index=64)


def test_indexed_refuses_the_wrong_raw_size(t):
    with pytest.raises(ValueError, match="raw size"):
        encoding.indexed(t, "A", bytes(63), index=0)


def test_indexed_refuses_an_unknown_code(t):
    with pytest.raises(KeyError, match="not in the indexed code table"):
        encoding.indexed(t, "E", bytes(64), index=0)


def test_to_binary_of_a_non_quadlet_text_is_refused():
    with pytest.raises(ValueError, match="multiple of 4"):
        encoding.to_binary("ABC")


# --- Edge paths -----------------------------------------------------------------------------------


def test_file_url_points_at_the_pinned_commit():
    assert spec_source.file_url("count-code-tables") == (
        "https://github.com/trustoverip/kswg-cesr-specification/blob/"
        "037129608b9e6960858b752019ac273d40d7386c/spec/spec-body.md#count-code-tables"
    )


def test_table_at_end_of_text_is_read():
    assert spec_source.table_after("# T\n| a |\n|-|\n| x |", "T") == [["x"]]


def test_count_scheme_refuses_a_numeral_secondary_selector(t):
    with pytest.raises(KeyError, match="No count code table"):
        t.count_scheme("-0A")


def test_variable_rows_are_not_marked_special(t):
    assert not t.primitives["4B"].special
    assert t.primitives["X"].special and t.primitives["V"].special


def test_assemble_refuses_a_code_whose_length_does_not_match_the_pad(t):
    with pytest.raises(ValueError, match="pad size"):
        encoding._assemble("AB", bytes(32), 0)


SYNTHETIC = """
##### Encoding Scheme Table
| Table | U | S | T | V | C | L | P | Format |
|-|-|-|-|-|-|-|-|-|
| 1-char fixed | [A-Z,a-z] | | 1* | 0 | 1 | 0 | 1 | $&&& |
| small cnt code | - | [A-Z,a-z] | 1* | 0 | 4 | 0 | 0 | *$## |
| large code cnt | - | - | 1 | 0 | 8 | 0 | 0 | **$##### |
| proto + genus | - | _ | 1 | 0 | 8 | 0 | 0 | **$$$### |

#### Master code table for genus/version `-_AAACAA` (KERI/ACDC protocol stack Version 2.00)
| Code | Description | Code Length | Count Length | Total Length |
|-|-|-|-|-|
| -A## | group | 4 | 2 | 4 |
| X | stray row before the primitives | 1 | | 4 |
| | Primitive Matter Codes | | | |
| D | key | 1 | | 44 |

#### Indexed code table for genus/version `--AAACAA` (KERI/ACDC protocol stack version 2.00)
| Code | Description | Code Length | Index Length | Ondex Length | Total Length |
|-|-|-|-|-|-|
| A# | sig | 2 | 1 | 0 | 88 |
| 3A###### | big | 6 | 3 | 3 | 160 |
"""


def test_inconsistent_indexed_row_is_left_out_and_recorded():
    t2 = tables.load(SYNTHETIC)
    assert "A" in t2.indexed and "3A" not in t2.indexed
    assert t2.anomalies == ["Indexed table row '3A######' is inconsistent; row left out."]
    assert t2.count_codes == {"-A": "group"}
    assert t2.primitives["D"].fs == 44
    assert "X" not in t2.primitives
