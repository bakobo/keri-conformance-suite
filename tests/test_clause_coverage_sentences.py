"""Clause coverage, first half: which sentences of a pinned specification carry an RFC 2119 keyword,
and which of them each case assertion cites. A sentence the enumeration misses is a clause the
report can never show as untested, so these tests pin the splitting rule, what is skipped, and
every refusal of an input the measurement cannot interpret."""

import os
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from generators.spec_tables import clause_coverage as cc
from generators.spec_tables import spec_source


def texts(sentences):
    return [s.text for s in sentences]


# --- Keywords and levels ------------------------------------------------------------------------


@pytest.mark.parametrize("sentence, level", [
    ("A parser MUST refuse it.", "MUST"),
    ("A parser MUST NOT accept it.", "MUST"),
    ("The field is REQUIRED.", "MUST"),
    ("A parser SHALL refuse it.", "MUST"),
    ("A parser SHALL NOT accept it.", "MUST"),
    ("A parser SHOULD refuse it.", "SHOULD"),
    ("A parser SHOULD NOT accept it.", "SHOULD"),
    ("Refusing it is RECOMMENDED.", "SHOULD"),
    ("Accepting it is NOT RECOMMENDED.", "SHOULD"),
    ("A parser MAY refuse it.", "MAY"),
    ("The field is OPTIONAL.", "MAY"),
    ("It MAY be sent, and a parser MUST then read it.", "MUST"),
    ("It MAY be sent, and a parser SHOULD then read it.", "SHOULD"),
    # Copilot on #15: a negated REQUIRED obliges nothing, so it does not set the level.
    ("It is NOT REQUIRED, but it MAY be sent.", "MAY"),
    ("It is NOT REQUIRED, but a parser MUST read it.", "MUST"),
    ("It is NOT RECOMMENDED and NOT REQUIRED.", "SHOULD"),
])
def test_the_strongest_keyword_sets_the_level(sentence, level):
    assert cc.level_of(sentence) == level


@pytest.mark.parametrize("sentence", [
    "A parser must refuse it.",  # lowercase is not a keyword
    "A parser may refuse it.",
    "MUSTARD is not a keyword.",  # whole words only
    "The REQUIREDNESS of it.",
    "NOT alone is not a keyword.",
    "No keyword here.",
    "Sending it is NOT REQUIRED.",  # a negated REQUIRED is the absence of an obligation
])
def test_a_sentence_without_an_uppercase_whole_word_keyword_has_no_level(sentence):
    assert cc.level_of(sentence) is None


# --- Sentence splitting -------------------------------------------------------------------------


def test_a_line_splits_after_a_full_stop_followed_by_space_and_a_capital():
    line = "First it MUST parse. Then it SHOULD check! Is it OPTIONAL? Yes."
    assert [line[a:b] for a, b in cc.split_sentences(line)] == [
        "First it MUST parse.", "Then it SHOULD check!", "Is it OPTIONAL?", "Yes."]


@pytest.mark.parametrize("line", [
    "Use version 2.00 of the table, which MUST apply.",  # no space after the stop
    "Codes, e.g. Base64 ones, MUST align.",  # a known abbreviation
    "It MUST drop it (i.e. Not escrow it).",
    "Compare with v1, cf. Section 5, which MUST hold.",
    "The next item MUST follow. and so on",  # a lowercase letter does not start a sentence
    "The code `a. B` MUST appear.",  # inside inline code
    "See [[ref: Key. Event]] which MUST hold.",  # inside a spec-up reference
    "Therefore either A. or B. MUST be satisfied, or C. Applies.",  # rule labels, not stops
])
def test_these_stops_do_not_end_a_sentence(line):
    assert cc.split_sentences(line) == [(0, len(line))]


@pytest.mark.parametrize("line, second", [
    ("It MUST align. `-A` is a code.", "`-A` is a code."),
    ("It MUST align. [[ref: KEL]]s are logs.", "[[ref: KEL]]s are logs."),
    ("It MUST align. (This is why.)", "(This is why.)"),
    ("It MUST align. \"Quoted\" text.", "\"Quoted\" text."),
    ("It MUST align. 24 bits is the unit.", "24 bits is the unit."),
    ("It MUST align. *Emphasis* follows.", "*Emphasis* follows."),
    ("It MUST align.) Then more.", "Then more."),  # closing punctuation stays with its sentence
])
def test_a_sentence_can_start_with_code_a_reference_a_bracket_a_quote_or_a_digit(line, second):
    spans = cc.split_sentences(line)
    assert line[spans[-1][0]:spans[-1][1]] == second


def test_split_spans_exclude_surrounding_whitespace():
    line = "  One MUST.   Two MAY.  "
    assert [line[a:b] for a, b in cc.split_sentences(line)] == ["One MUST.", "Two MAY."]


def test_an_empty_line_has_no_sentences():
    assert cc.split_sentences("   ") == []


SPEC = """\
Preamble text that MUST be reported before any heading.

# Title

## Rules

A parser MUST refuse it. Some context follows. A parser MAY log it.
This line SHOULD be its own paragraph.

```
Code that MUST be ignored. It SHOULD not count.
```

### Lists

- An item that MUST hold. A second sentence in it SHOULD too.
* A starred item that MAY hold.
1. A numbered item that is REQUIRED.
  2) An indented numbered item that SHALL hold.
> A quoted line that MUST hold.

### Tables

|Code|Rule|
|:---|:---|
|`A`| It MUST be first. It is short. |
|`B`| No keyword here. |

Final text with no keyword.
"""


def test_keyword_sentences_are_enumerated_in_order_with_line_level_kind_and_section():
    found = cc.keyword_sentences(SPEC)
    rows = [(s.line, s.level, s.kind, s.section.text if s.section else None, s.text)
            for s in found]
    assert rows == [
        (1, "MUST", "prose", None, "Preamble text that MUST be reported before any heading."),
        (7, "MUST", "prose", "Rules", "A parser MUST refuse it."),
        (7, "MAY", "prose", "Rules", "A parser MAY log it."),
        (8, "SHOULD", "prose", "Rules", "This line SHOULD be its own paragraph."),
        (16, "MUST", "list", "Lists", "An item that MUST hold."),
        (16, "SHOULD", "list", "Lists", "A second sentence in it SHOULD too."),
        (17, "MAY", "list", "Lists", "A starred item that MAY hold."),
        (18, "MUST", "list", "Lists", "A numbered item that is REQUIRED."),
        (19, "MUST", "list", "Lists", "An indented numbered item that SHALL hold."),
        (20, "MUST", "list", "Lists", "A quoted line that MUST hold."),
        (26, "MUST", "table", "Tables", "|`A`| It MUST be first. It is short. |"),
    ]


def test_a_sentence_whose_only_keyword_is_a_negated_required_is_not_a_keyword_sentence():
    found = cc.keyword_sentences("It is NOT REQUIRED. It is NOT RECOMMENDED. It MUST NOT be.\n")
    assert [(s.level, s.text) for s in found] == [("SHOULD", "It is NOT RECOMMENDED."),
                                                  ("MUST", "It MUST NOT be.")]


def test_a_sentences_span_locates_its_text_on_its_line():
    lines = SPEC.splitlines()
    for s in cc.keyword_sentences(SPEC):
        assert lines[s.line - 1][s.start:s.end] == s.text


def test_headings_and_fenced_code_are_not_sentences():
    text = "# A heading that MUST not count\n\n```\nIt MUST not count.\n```\nIt MUST count.\n"
    assert texts(cc.keyword_sentences(text)) == ["It MUST count."]


# --- Polarity -----------------------------------------------------------------------------------


@pytest.mark.parametrize("check, expected, polarity", [
    ("decoded", [], "positive"),
    ("encoded", "00", "positive"),
    ("rejected", None, "negative"),
    ("disposition", "seen", "positive"),
    ("disposition", "not-seen", "negative"),
    ("disposition", "rejected", "negative"),
    ("disposition", "pending", "negative"),
    ("trunk", True, "positive"),
    ("trunk", False, "negative"),
    ("key_state", {"sn": 0}, "positive"),
])
def test_each_check_has_a_polarity(check, expected, polarity):
    assert cc.polarity({"check": check, "expected": expected}, "KERI-0001 a1") == polarity


@pytest.mark.parametrize("assertion, message", [
    ({"check": "verdict", "expected": "valid"}, "unknown check 'verdict'"),
    ({"check": "disposition", "expected": "duplicitous"}, "disposition 'duplicitous'"),
    ({"check": "trunk", "expected": "yes"}, "trunk"),
    # Hostile pass on #15: JSON allows an unhashable expected value.
    ({"check": "disposition", "expected": []}, "disposition"),
    ({"check": "disposition", "expected": {"x": 1}}, "disposition"),
])
def test_an_unknown_check_or_value_is_a_coded_error(assertion, message):
    with pytest.raises(cc.CoverageError, match=message) as e:
        cc.polarity(assertion, "KERI-0001 a1")
    assert e.value.code == cc.E_CASE
    assert "KERI-0001 a1" in str(e.value)


# --- Mapping quotes onto sentences --------------------------------------------------------------

MAP_SPEC = """\
# Rules

First it MUST parse. Then it SHOULD check. It MAY log.
A plain line with no keyword at all.
"""


def sentences_on(text):
    return cc.keyword_sentences(text)


def test_a_quote_inside_a_sentence_maps_to_that_sentence():
    found = cc.map_quote(MAP_SPEC, sentences_on(MAP_SPEC), "it SHOULD check")
    assert texts(found) == ["Then it SHOULD check."]


def test_a_quote_spanning_sentences_maps_to_each_sentence_it_contains():
    found = cc.map_quote(MAP_SPEC, sentences_on(MAP_SPEC),
                         "First it MUST parse. Then it SHOULD check.")
    assert texts(found) == ["First it MUST parse.", "Then it SHOULD check."]


def test_a_quote_that_only_straddles_two_sentences_maps_to_neither():
    found = cc.map_quote(MAP_SPEC, sentences_on(MAP_SPEC), "parse. Then it")
    assert found == []


def test_a_quote_on_a_line_with_no_keyword_sentence_maps_to_nothing():
    assert cc.map_quote(MAP_SPEC, sentences_on(MAP_SPEC), "A plain line") == []


def test_a_quote_repeated_on_its_line_is_a_coded_error():
    # Hostile pass on #15: one quote must not credit two obligations.
    text = "# Rules\n\nIt MUST parse. Then it MUST parse.\n"
    with pytest.raises(cc.CoverageError, match="more than once") as e:
        cc.map_quote(text, sentences_on(text), "MUST parse.")
    assert e.value.code == cc.E_CASE


@pytest.mark.parametrize("quote", ["Nowhere in the text.", "MUST"])
def test_a_quote_not_found_exactly_once_is_a_coded_error(quote):
    text = MAP_SPEC + "It MUST again.\n"
    with pytest.raises(cc.CoverageError) as e:
        cc.map_quote(text, sentences_on(text), quote)
    assert e.value.code == cc.E_CASE


# --- The real pinned texts ----------------------------------------------------------------------


def pinned(pin):
    try:
        return spec_source.load_spec(pin=pin)
    except spec_source.SpecUnavailable as e:
        if os.environ.get("KCS_REQUIRE_SPEC") == "1":
            raise
        return pytest.skip(f"the pinned {pin.name} specification text is unavailable: {e}")


@pytest.mark.parametrize("pin", [spec_source.cesr_pin(), spec_source.KERI], ids=["cesr", "keri"])
def test_every_keyword_line_of_a_pinned_text_yields_a_sentence(pin):
    """No line outside fenced code and headings that carries a keyword is lost by the splitter."""
    text = pinned(pin)
    found = {s.line for s in cc.keyword_sentences(text)}
    heading_lines = {h.line for h in spec_source.headings(text)}
    fenced = False
    for number, line in enumerate(text.splitlines(), start=1):
        if line.startswith("```"):
            fenced = not fenced
            continue
        if fenced or number in heading_lines:
            continue
        assert (cc.level_of(line) is not None) == (number in found), number
