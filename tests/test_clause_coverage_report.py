"""Clause coverage, second half: reading the cases and the triage sidecars, measuring which
keyword sentences the cases cite, and writing the generated report that scripts/clause-coverage
--check holds the committed one to. Every input the measurement cannot interpret is refused with a
coded error, because a coverage report built from a misread input would overstate the suite."""

import dataclasses
import errno
import hashlib
import json
import os
import pathlib
import re
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from generators.spec_tables import clause_coverage as cc
from generators.spec_tables import spec_source

FAKE_TEXT = """\
# Fake

## Parsing

A parser MUST refuse a bad code. A parser SHOULD log it. A parser MAY stop.
Any producer MUST send the version first.

## Keys

The controller MUST keep its keys secret. A validator SHOULD hold the key state.
A plain line with no keyword.
"""

FAKE = spec_source.Pin(name="FAKE", label="fake", repo="https://github.com/example/fake-spec",
                       tag="v9", commit="f" * 40, file="spec/spec-body.md",
                       sha256=hashlib.sha256(FAKE_TEXT.encode()).hexdigest())
FAKE2 = dataclasses.replace(FAKE, tag="v10", commit="e" * 40)
FAKE2_TEXT = FAKE_TEXT.replace("A parser MAY stop.", "A parser MUST stop.")


def clause(quote, pin=FAKE):
    return {"spec": pin.label, "commit": pin.commit, "quote": quote, "section": "x", "url": "u"}


def case(case_id, *assertions, status="active"):
    return {"id": case_id, "status": status, "assertions": [
        {"id": f"a{n}", **a} for n, a in enumerate(assertions, start=1)]}


def must(quote, check="rejected", expected=None, pin=FAKE):
    return {"check": check, "level": "MUST", "expected": expected, "clause": clause(quote, pin)}


def should(quote, inferred, line, check="disposition", expected="seen"):
    return {"check": check, "level": "SHOULD", "expected": expected, "clause": clause(quote),
            "inferred_from": {"quote": inferred, "line": line, "inference": "i", "section": "x"}}


def interop():
    return {"check": "rejected", "level": "INTEROP", "basis": "keripy does it"}


def triage_file(entries=None):
    return {"about": "Hand-kept triage.", "entries": entries or {}}


@pytest.fixture
def tree(tmp_path, monkeypatch):
    """A repository with fake cases, a fake pinned text and an empty triage sidecar."""
    monkeypatch.setattr(cc, "known_pins", lambda: [FAKE, FAKE2])
    monkeypatch.setattr(cc, "load_text", lambda pin: {FAKE: FAKE_TEXT, FAKE2: FAKE2_TEXT}[pin])

    def put(*cases, triage=None):
        for one in cases:
            path = tmp_path / "cases" / one["id"].split("-")[0].lower() / f"{one['id']}.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(one))
        path = tmp_path / "scenarios" / "fake" / "triage.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(triage if triage is not None else triage_file()))
        return tmp_path

    return put


# --- Reading cases ------------------------------------------------------------------------------


def test_cases_are_read_in_id_order(tree):
    root = tree(case("KERI-0002", must("A parser MUST refuse a bad code.")),
                case("CESR-0001", must("A parser MUST refuse a bad code.")))
    assert [c["id"] for c in cc.load_cases(root)] == ["CESR-0001", "KERI-0002"]


@pytest.mark.parametrize("mangle, message", [
    (lambda c: c.update(id="KERI-1"), "not a case id"),
    (lambda c: c.update(status="retired"), "status"),
    (lambda c: c.update(assertions=[]), "assertions"),
    (lambda c: c.update(assertions="a1"), "assertions"),
    (lambda c: c["assertions"].append("a2"), "assertion"),
    (lambda c: c["assertions"][0].update(check=7), "check"),
    (lambda c: c["assertions"][0].update(level="MAYBE"), "level"),
    (lambda c: c["assertions"][0].update(id=None), "assertion id"),
    (lambda c: c["assertions"][0].update(clause="x"), "clause"),
    (lambda c: c["assertions"][0]["clause"].update(commit=None), "clause"),
    (lambda c: c["assertions"][0].update(inferred_from={"quote": "q", "line": 1}) or
     c["assertions"][0].pop("clause"), "inferred_from without a clause"),
    (lambda c: c["assertions"][0].update(inferred_from={"quote": "q"}), "inferred_from"),
    (lambda c: c["assertions"][0].update(inferred_from={"quote": "q", "line": True}),
     "inferred_from"),
    # Hostile pass on #15: an assertion with nothing to check must not count as coverage.
    (lambda c: c["assertions"][0].update(check="decoded") or c["assertions"][0].pop("expected"),
     "no expected result"),
])
def test_a_malformed_case_is_a_coded_error(tree, mangle, message):
    bad = case("KERI-0001", must("A parser MUST refuse a bad code."))
    mangle(bad)
    root = tree()
    path = root / "cases" / "keri" / "KERI-0001.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(bad))
    with pytest.raises(cc.CoverageError, match=message) as e:
        cc.load_cases(root)
    assert e.value.code == cc.E_CASE and "KERI-0001.json" in str(e.value)


def test_a_case_that_is_not_an_object_is_a_coded_error(tree):
    root = tree()
    (root / "cases" / "keri").mkdir(parents=True)
    (root / "cases" / "keri" / "KERI-0001.json").write_text("[]")
    with pytest.raises(cc.CoverageError, match="not an object") as e:
        cc.load_cases(root)
    assert e.value.code == cc.E_CASE


def test_a_case_whose_file_name_is_not_its_id_is_a_coded_error(tree):
    root = tree()
    (root / "cases" / "keri").mkdir(parents=True)
    (root / "cases" / "keri" / "KERI-0009.json").write_text(json.dumps(
        case("KERI-0001", must("A parser MUST refuse a bad code."))))
    with pytest.raises(cc.CoverageError, match="KERI-0009.json") as e:
        cc.load_cases(root)
    assert e.value.code == cc.E_CASE


def test_a_case_that_is_not_json_is_a_coded_error(tree):
    root = tree()
    (root / "cases" / "keri").mkdir(parents=True)
    (root / "cases" / "keri" / "KERI-0001.json").write_text("{not json")
    with pytest.raises(cc.CoverageError, match="could not be read as JSON") as e:
        cc.load_cases(root)
    assert e.value.code == cc.E_CASE


def test_an_unreadable_case_is_a_coded_error(tree):
    root = tree()
    (root / "cases" / "keri" / "KERI-0001.json").mkdir(parents=True)  # a directory, not a file
    with pytest.raises(cc.CoverageError, match="could not be read") as e:
        cc.load_cases(root)
    assert e.value.code == cc.E_CASE


def test_an_oversized_case_is_refused_before_it_is_parsed(tree, monkeypatch):
    root = tree(case("KERI-0001", must("A parser MUST refuse a bad code.")))
    monkeypatch.setattr(cc, "MAX_FILE_BYTES", 10)
    with pytest.raises(cc.CoverageError, match="larger than 10 bytes") as e:
        cc.load_cases(root)
    assert e.value.code == cc.E_SIZE


def test_an_unknown_check_type_anywhere_is_refused(tree):
    root = tree(case("KERI-0001", {"check": "verdict", "level": "INTEROP", "expected": "valid"}))
    with pytest.raises(cc.CoverageError, match="unknown check 'verdict'"):
        cc.generate(root)


# --- Pins ---------------------------------------------------------------------------------------


def test_the_known_pins_are_the_cesr_keri_and_acdc_texts():
    # Hostile pass on #22: an IPEX practice basis cites the ACDC text, so it must be known.
    assert cc.known_pins() == [spec_source.cesr_pin(), spec_source.KERI, spec_source.ACDC]


def test_load_text_reads_the_pinned_text(monkeypatch):
    calls = []
    monkeypatch.setattr(cc.spec_source, "load_spec",
                        lambda allow_fetch=True, pin=None: calls.append(pin) or "text")
    assert cc.load_text(FAKE) == "text" and calls == [FAKE]


def test_a_clause_citing_an_unpinned_commit_is_a_coded_error(tree):
    stale = dataclasses.replace(FAKE, commit="0" * 40)
    root = tree(case("KERI-0001", must("A parser MUST refuse a bad code.", pin=stale)))
    with pytest.raises(cc.CoverageError, match="0000000000") as e:
        cc.generate(root)
    assert e.value.code == cc.E_PIN


def test_a_quote_not_in_its_pinned_text_is_a_coded_error(tree):
    root = tree(case("KERI-0001", must("Nowhere in the text.")))
    with pytest.raises(cc.CoverageError, match="KERI-0001 a1") as e:
        cc.generate(root)
    assert e.value.code == cc.E_CASE
    # Copilot on #15: re-wrapping the error must not repeat its code.
    assert str(e.value) == (f"{cc.E_CASE}: KERI-0001 a1: Quote not found verbatim in the "
                            f"specification: 'Nowhere in the text.'")


def test_an_inferred_quote_not_in_its_pinned_text_is_a_coded_error(tree):
    root = tree(case("KERI-0001", should("A parser MUST refuse a bad code.", "Nowhere.", 10)))
    with pytest.raises(cc.CoverageError, match="KERI-0001 a1: Quote not found") as e:
        cc.generate(root)
    assert e.value.code == cc.E_CASE


def test_an_inference_whose_line_does_not_match_the_text_is_a_coded_error(tree):
    root = tree(case("KERI-0001", should("A parser MUST refuse a bad code.",
                                         "A validator SHOULD hold the key state.", 99)))
    with pytest.raises(cc.CoverageError, match="line 99") as e:
        cc.generate(root)
    assert e.value.code == cc.E_CASE


# --- Triage -------------------------------------------------------------------------------------


def test_triage_is_validated_and_returned(tree):
    entries = {"A parser MUST refuse a bad code.": {"scope": "validator", "security": True},
               "The controller MUST keep its keys secret.": {
                   "scope": "out-of-scope", "security": True, "note": "Controller only."},
               "Any producer MUST send the version first.": {
                   "scope": "untestable", "reason": "No adapter produces.", "security": False},
               "A parser SHOULD log it.": [{"scope": "validator", "security": False,
                                            "section": "Logging", "occurrence": 2}]}
    root = tree(triage=triage_file(entries))
    assert cc.load_triage(root, "fake") == entries


def test_a_missing_triage_file_is_a_coded_error(tmp_path):
    with pytest.raises(cc.CoverageError, match="scenarios/fake/triage.json") as e:
        cc.load_triage(tmp_path, "fake")
    assert e.value.code == cc.E_TRIAGE


@pytest.mark.parametrize("triage, message", [
    ([], "an object"),
    ({"entries": {}}, "about"),
    ({"about": "", "entries": {}}, "about field is not text"),
    ({"about": "x", "entries": {}, "extra": 1}, "extra"),
    ({"about": "x", "entries": []}, "entries"),
    (triage_file({"s": "validator"}), "an object"),
    (triage_file({"s": {"scope": "maybe", "security": False}}), "scope"),
    (triage_file({"s": {"scope": "validator"}}), "security"),
    (triage_file({"s": {"scope": "validator", "security": "yes"}}), "security"),
    (triage_file({"s": {"scope": "untestable", "security": False}}), "reason"),
    (triage_file({"s": {"scope": "untestable", "security": False, "reason": ""}}), "reason"),
    (triage_file({"s": {"scope": "validator", "security": False, "reason": "r"}}), "reason"),
    (triage_file({"s": {"scope": "validator", "security": False, "note": 3}}), "note"),
    (triage_file({"s": {"scope": "validator", "security": False, "colour": "red"}}), "colour"),
    (triage_file({"s": []}), "empty list"),
    (triage_file({"s": [{"scope": "validator", "security": False}, 3]}), "is not an object"),
    (triage_file({"s": {"scope": "validator", "security": False, "section": ""}}), "section that is not"),
    (triage_file({"s": {"scope": "validator", "security": False, "section": 2}}), "section that is not"),
    (triage_file({"s": {"scope": "validator", "security": False, "occurrence": 0}}),
     "occurrence that is not"),
    (triage_file({"s": {"scope": "validator", "security": False, "occurrence": True}}),
     "occurrence that is not"),
    (triage_file({"s": {"scope": "validator", "security": False, "occurrence": "1"}}),
     "occurrence that is not"),
])
def test_a_malformed_triage_file_is_a_coded_error(tree, triage, message):
    root = tree(triage=triage)
    with pytest.raises(cc.CoverageError, match=message) as e:
        cc.load_triage(root, "fake")
    assert e.value.code == cc.E_TRIAGE


def test_a_triage_file_that_is_not_json_is_a_coded_error(tree):
    root = tree()
    (root / "scenarios" / "fake" / "triage.json").write_text("{")
    with pytest.raises(cc.CoverageError) as e:
        cc.load_triage(root, "fake")
    assert e.value.code == cc.E_TRIAGE


@pytest.mark.parametrize("sentence", [
    "A plain line with no keyword.",  # not a keyword sentence
    "A parser MUST refuse a bad code",  # not exact
    "Nowhere in the text.",
])
def test_a_triage_entry_that_is_not_a_keyword_sentence_is_refused(tree, sentence):
    root = tree(case("KERI-0001", must("A parser MUST refuse a bad code.")),
                triage=triage_file({sentence: {"scope": "validator", "security": False}}))
    with pytest.raises(cc.CoverageError, match="not a keyword sentence") as e:
        cc.generate(root)
    assert e.value.code == cc.E_TRIAGE_STALE


def test_a_triage_entry_for_a_sentence_that_occurs_twice_needs_a_section(tree, monkeypatch):
    doubled = FAKE_TEXT + "A parser SHOULD log it.\n"
    monkeypatch.setattr(cc, "load_text", lambda pin: doubled)
    root = tree(case("KERI-0001", must("A parser MUST refuse a bad code.")),
                triage=triage_file({"A parser SHOULD log it.": {"scope": "validator",
                                                                 "security": False}}))
    with pytest.raises(cc.CoverageError, match="more than once.*section") as e:
        cc.generate(root)
    assert e.value.code == cc.E_TRIAGE_STALE


# "A parser SHOULD log it." is once under Parsing and twice under Logging; the rest are unique.
REPEATED_TEXT = FAKE_TEXT + "\n## Logging\n\nA parser SHOULD log it. A parser SHOULD log it.\n"
LOG = "A parser SHOULD log it."


def judged(scope="validator", **extra):
    return {"scope": scope, "security": False, **extra}


def resolved(entries, text=REPEATED_TEXT):
    """(line, start, section) of each sentence a triage resolves, with its entry's scope."""
    found = cc.resolve_triage("fake", entries, cc.keyword_sentences(text))
    return sorted((s.line, s.start, s.section.text, e["scope"]) for s, e in found.items())


def test_a_unique_sentence_resolves_by_its_text_alone():
    assert resolved({"A parser MUST refuse a bad code.": judged()}) == [
        (5, 0, "Parsing", "validator")]


def test_a_repeated_sentence_resolves_by_section_then_occurrence():
    assert resolved({LOG: [judged("untestable", section="Parsing", reason="r"),
                           judged(section="Logging", occurrence=2),
                           judged("out-of-scope", section="Logging", occurrence=1)]}) == [
        (5, 33, "Parsing", "untestable"), (15, 0, "Logging", "out-of-scope"),
        (15, 24, "Logging", "validator")]


def test_a_single_disambiguated_entry_may_be_an_object_rather_than_a_list():
    assert resolved({LOG: judged(section="Parsing")}) == [(5, 33, "Parsing", "validator")]


def test_a_sentence_that_is_not_in_this_pinned_text_resolves_to_nothing():
    """Another pin of the same spec may hold it; generate() refuses it if none does."""
    assert resolved({"A parser MUST stop.": judged()}) == []


@pytest.mark.parametrize("entry, message", [
    (judged(), "more than once.*section"),  # repeated, no section
    (judged(occurrence=1), "more than once.*section"),  # an occurrence is not a section
    (judged(section="Nowhere"), "no section"),  # matches nothing
    (judged(section="Logging"), "2 times.*occurrence"),  # repeats within its section
    (judged(section="Logging", occurrence=3), "occurrence 3"),  # out of range
    (judged(section="Parsing", occurrence=1), "once in section"),  # occurrence not needed
    ([judged(section="Parsing"), judged(section="Parsing")], "two triage entries"),
])
def test_a_repeated_sentence_with_a_missing_or_wrong_disambiguator_is_refused(entry, message):
    with pytest.raises(cc.CoverageError, match=message) as e:
        resolved({LOG: entry})
    assert e.value.code == cc.E_TRIAGE_STALE


@pytest.mark.parametrize("entry", [judged(section="Parsing"), judged(occurrence=1)])
def test_a_disambiguator_on_a_unique_sentence_is_refused(entry):
    with pytest.raises(cc.CoverageError, match="only once") as e:
        resolved({"A parser MUST refuse a bad code.": entry})
    assert e.value.code == cc.E_TRIAGE_STALE


def test_generate_reports_the_triage_of_each_occurrence_of_a_repeated_sentence(tree, monkeypatch):
    monkeypatch.setattr(cc, "load_text", lambda pin: REPEATED_TEXT)
    root = tree(case("KERI-0001", must("A parser MUST refuse a bad code.")),
                triage=triage_file({LOG: [judged(section="Parsing"),
                                          judged("out-of-scope", section="Logging",
                                                 occurrence=2)]}))
    text = cc.generate(root)["docs/coverage/fake.md"].decode()
    logs = [line for line in text.splitlines() if line.endswith(f"| {LOG} |")]
    assert [line.split(" | ")[2] for line in logs] == ["validator", "unassessed", "out-of-scope"]


def test_a_repeated_sentence_with_a_missing_disambiguator_fails_generate(tree, monkeypatch):
    monkeypatch.setattr(cc, "load_text", lambda pin: REPEATED_TEXT)
    root = tree(case("KERI-0001", must("A parser MUST refuse a bad code.")),
                triage=triage_file({LOG: [judged(section="Logging")]}))
    with pytest.raises(cc.CoverageError, match="occurrence") as e:
        cc.generate(root)
    assert e.value.code == cc.E_TRIAGE_STALE


def test_a_triage_entry_needs_only_one_pin_of_its_spec_to_hold_it(tree):
    """'A parser MUST stop.' is in the second pin's text only."""
    root = tree(case("KERI-0001", must("A parser MUST refuse a bad code.")),
                case("KERI-0002", must("A parser MUST stop.", pin=FAKE2)),
                triage=triage_file({"A parser MUST stop.": {"scope": "validator",
                                                             "security": False}}))
    assert "docs/coverage/fake.md" in cc.generate(root)


def test_a_triage_file_for_a_spec_no_case_cites_must_be_empty(tree):
    root = tree(case("KERI-0001", must("A parser MUST refuse a bad code.")))
    other = root / "scenarios" / "other" / "triage.json"
    other.parent.mkdir(parents=True)
    other.write_text(json.dumps(triage_file()))
    cc.generate(root)
    other.write_text(json.dumps(triage_file({"s": {"scope": "validator", "security": False}})))
    with pytest.raises(cc.CoverageError, match="not a keyword sentence") as e:
        cc.generate(root)
    assert e.value.code == cc.E_TRIAGE_STALE


# --- Measurement --------------------------------------------------------------------------------

CASES = [
    case("KERI-0001", must("A parser MUST refuse a bad code."),
         should("A parser MUST refuse a bad code.", "A validator SHOULD hold the key state.", 10),
         interop()),
    case("KERI-0002", must("A parser MUST refuse a bad code.", check="encoded", expected="00")),
    case("KERI-0003", must("The controller MUST keep its keys secret. "
                           "A validator SHOULD hold the key state.",
                           check="trunk", expected=False), status="disputed"),
    case("KERI-0004", must("Unmatched: a plain line", check="key_state", expected={}),
         should("A parser MUST refuse a bad code.", "A plain line with no keyword.", 11)),
]
CASES[3]["assertions"][0]["clause"]["quote"] = "A plain line with no keyword."


def measured():
    return cc.measure(CASES, {(FAKE.label, FAKE.commit): (FAKE, FAKE_TEXT)},
                      {"fake": {"A parser MUST refuse a bad code.": {"scope": "validator",
                                                                     "security": True}}})


def row(coverage, text):
    (found,) = [r for r in coverage.rows if r.sentence.text == text]
    return found


def test_measure_records_direct_and_inferred_citations_levels_polarity_and_disputes():
    (coverage,) = measured()
    bad_code = row(coverage, "A parser MUST refuse a bad code.")
    assert bad_code.direct == ["KERI-0001", "KERI-0002"]
    assert bad_code.inferred == ["KERI-0001", "KERI-0004"]
    assert bad_code.levels == {"MUST": 2, "SHOULD": 2}
    assert bad_code.polarity == "both"
    assert bad_code.disputed == 0
    assert bad_code.covered
    assert bad_code.triage == {"scope": "validator", "security": True}


def test_an_assertion_with_an_inference_cites_its_clause_by_inference_too():
    (coverage,) = measured()
    key_state = row(coverage, "A validator SHOULD hold the key state.")
    assert key_state.direct == ["KERI-0003"] and key_state.inferred == ["KERI-0001"]


def test_a_sentence_cited_only_by_a_disputed_case_is_not_covered():
    (coverage,) = measured()
    secret = row(coverage, "The controller MUST keep its keys secret.")
    assert secret.direct == ["KERI-0003"] and secret.disputed == 1
    assert not secret.covered and secret.polarity == ""
    assert secret.triage is None


def test_an_uncited_sentence_is_uncovered_with_no_polarity():
    (coverage,) = measured()
    stop = row(coverage, "A parser MAY stop.")
    assert (stop.direct, stop.inferred, stop.levels, stop.polarity, stop.covered) == (
        [], [], {}, "", False)


def test_a_quote_matching_no_keyword_sentence_is_listed_not_refused():
    (coverage,) = measured()
    assert coverage.unmapped == [
        cc.Unmapped(line=11, quote="A plain line with no keyword.", cited_as="clause",
                    cases=["KERI-0004"]),
        cc.Unmapped(line=11, quote="A plain line with no keyword.", cited_as="inference",
                    cases=["KERI-0004"]),
    ]


def test_every_keyword_sentence_has_exactly_one_row_in_order():
    (coverage,) = measured()
    assert [(r.sentence.line, r.sentence.text) for r in coverage.rows] == [
        (s.line, s.text) for s in cc.keyword_sentences(FAKE_TEXT)]


# --- Rendering ----------------------------------------------------------------------------------


def report_rows(markdown):
    """(line, sentence) for every sentence row of a rendered per-spec report."""
    out = []
    for line in markdown.splitlines():
        cells = cc.split_row(line)
        if cells and cells[0].isdigit():
            out.append((int(cells[0]), cells[-1]))
    return out


def test_a_table_cell_escapes_pipes_and_split_row_reads_it_back():
    line = "| 3 | " + cc.cell("|`A`| It MUST be first. |") + " |"
    assert cc.split_row(line) == ["3", "|`A`| It MUST be first. |"]
    assert cc.split_row("not a row") == []


def test_a_backslash_before_a_pipe_survives_a_cell():
    """Hostile pass on #15: an existing backslash must not unescape the pipe after it."""
    text = r"Logs \| are private. C:\path"
    line = "| 1 | " + cc.cell(text) + " | 2 |"
    # Markdown escapes a pipe only after an odd run of backslashes; count the delimiters it sees.
    delimiters = [m for m in re.finditer(r"(\\*)\|", line) if len(m.group(1)) % 2 == 0]
    assert len(delimiters) == 4
    # The text is markdown, so its own "\\|" was already an escaped pipe.
    assert cc.split_row(line) == ["1", r"Logs | are private. C:\path", "2"]


def test_write_refuses_a_report_it_could_not_read_back(tmp_path, monkeypatch):
    """Hostile pass on #15: write() and committed() share one size bound."""
    monkeypatch.setattr(cc, "MAX_REPORT_BYTES", len(cc.NOTICE) + 6)
    big = {"docs/coverage/fake.md": cc.NOTICE.encode() + b"longer\n"}
    with pytest.raises(cc.CoverageError, match="larger than") as e:
        cc.write(tmp_path, big)
    assert e.value.code == cc.E_SIZE
    assert not (tmp_path / "docs" / "coverage" / "fake.md").exists()


def test_the_spec_report_starts_with_the_notice_and_lists_sections_in_order():
    text = cc.render_spec("fake", measured())
    assert text.startswith(cc.NOTICE)
    assert text.index("Parsing") < text.index("Keys")
    assert text.index("### Obligations") < text.index("### Permissions")
    assert "https://github.com/example/fake-spec/blob/" + "f" * 40 + "/spec/spec-body.md#parsing" \
        in text
    assert report_rows(text) == [  # spec order, obligations first
        (s.line, s.text) for s in cc.keyword_sentences(FAKE_TEXT) if s.level != "MAY"
    ] + [(5, "A parser MAY stop.")]


def test_the_spec_report_rows_carry_triage_counts_polarity_and_case_marks():
    text = cc.render_spec("fake", measured())
    (bad_code,) = [line for line in text.splitlines() if line.endswith("refuse a bad code. |")]
    assert bad_code == ("| 5 | MUST | validator, security | 2 | 2 | 0 | MUST 2, SHOULD 2 | both "
                        "| KERI-0001, KERI-0002, KERI-0004 (inferred) "
                        "| A parser MUST refuse a bad code. |")
    (secret,) = [line for line in text.splitlines() if line.endswith("keys secret. |")]
    assert "| unassessed | 1 | 0 | 1 | MUST 1 | — | KERI-0003 (disputed) |" in secret


def test_the_spec_report_lists_unmapped_quotes():
    text = cc.render_spec("fake", measured())
    assert "### Quotes that match no keyword sentence" in text
    assert "| KERI-0004 | inference | 11 | A plain line with no keyword. |" in text


def test_a_spec_report_with_nothing_unmapped_says_so():
    coverage = cc.measure([], {(FAKE.label, FAKE.commit): (FAKE, FAKE_TEXT)}, {})
    assert "Every quoted clause matches a keyword sentence." in cc.render_spec("fake", coverage)


def test_a_triage_reason_is_escaped_like_any_other_cell():
    """Copilot on #15: a pipe or a newline in a reason must not break the table row."""
    coverage = cc.measure([], {(FAKE.label, FAKE.commit): (FAKE, FAKE_TEXT)}, {"fake": {
        "A parser SHOULD log it.": {"scope": "untestable", "reason": "Logs | are\nprivate.",
                                    "security": False}}})
    (line,) = [line for line in cc.render_spec("fake", coverage).splitlines()
               if "SHOULD log it." in line]
    cells = cc.split_row(line)
    assert len(cells) == 10
    assert cells[2] == "untestable: Logs | are private."


def test_an_untestable_triage_shows_its_reason():
    coverage = cc.measure([], {(FAKE.label, FAKE.commit): (FAKE, FAKE_TEXT)}, {"fake": {
        "A parser SHOULD log it.": {"scope": "untestable", "reason": "Logs are private.",
                                    "security": False}}})
    assert "| untestable: Logs are private. |" in cc.render_spec("fake", coverage)


def test_a_sentence_before_any_heading_is_reported_under_its_own_heading():
    text = "Before any heading it MUST hold.\n"
    coverage = cc.measure([], {(FAKE.label, FAKE.commit): (FAKE, text)}, {})
    assert "#### Before the first heading" in cc.render_spec("fake", coverage)


def test_each_pin_of_a_spec_is_reported_separately():
    coverage = cc.measure([], {(FAKE.label, FAKE.commit): (FAKE, FAKE_TEXT),
                               (FAKE2.label, FAKE2.commit): (FAKE2, FAKE2_TEXT)}, {})
    assert [c.pin for c in coverage] == [FAKE2, FAKE]  # by label, then tag as text
    text = cc.render_spec("fake", coverage)
    assert "## v9, commit " + "f" * 12 in text and "## v10, commit " + "e" * 12 in text


def test_the_summary_counts_obligations_triage_and_security():
    (coverage,) = measured()
    summary = cc.summarize(coverage)
    assert summary == {
        "MUST": 3, "SHOULD": 2, "MAY": 1, "covered": 2, "uncovered": 3, "both": 1,
        "validator": 1, "out-of-scope": 0, "untestable": 0, "unassessed": 4,
        "security covered": 1, "security uncovered": 0, "practice": 0, "practice covered": 0,
        "unmapped": 2,
    }


def test_the_index_has_the_notice_a_column_per_pin_and_a_row_per_measure():
    index = cc.render_index(measured())
    assert index.startswith(cc.NOTICE)
    assert "[FAKE v9](fake.md)" in index
    assert "| Obligations covered by an active case | 2 |" in index
    assert "| Security-bearing obligations not covered | 0 |" in index
    assert "scripts/clause-coverage" in index


# --- Generation, writing and checking -----------------------------------------------------------


def test_generate_writes_a_report_per_spec_and_an_index(tree):
    root = tree(*CASES[:2])
    files = cc.generate(root)
    assert sorted(files) == ["docs/coverage/README.md", "docs/coverage/fake.md"]
    assert files == cc.generate(root)  # deterministic


def test_generate_reports_both_pins_of_a_spec_in_one_file(tree):
    root = tree(case("KERI-0001", must("A parser MUST refuse a bad code.")),
                case("KERI-0002", must("A parser MUST stop.", pin=FAKE2)))
    text = cc.generate(root)["docs/coverage/fake.md"].decode()
    assert "## v9," in text and "## v10," in text


def test_write_then_committed_round_trips_and_removes_stale_reports(tmp_path):
    (tmp_path / "docs" / "coverage").mkdir(parents=True)
    (tmp_path / "docs" / "coverage" / "old.md").write_text(cc.NOTICE + "stale")
    (tmp_path / "docs" / "coverage" / "notes.txt").write_text("not owned")
    files = {"docs/coverage/README.md": cc.NOTICE.encode() + b"a\n",
             "docs/coverage/fake.md": cc.NOTICE.encode() + b"b\n"}
    cc.write(tmp_path, files)
    assert cc.committed(tmp_path) == files
    assert (tmp_path / "docs" / "coverage" / "notes.txt").exists()


def test_a_hand_written_markdown_file_beside_the_reports_is_not_owned(tmp_path):
    """A dated assessment lives in docs/coverage/ but is written by hand, without the notice."""
    (tmp_path / "docs" / "coverage").mkdir(parents=True)
    assessment = tmp_path / "docs" / "coverage" / "assessment-2026-10.md"
    assessment.write_text("# An assessment\n")
    files = {"docs/coverage/README.md": cc.NOTICE.encode() + b"a\n"}
    cc.write(tmp_path, files)
    assert assessment.read_text() == "# An assessment\n"
    assert cc.committed(tmp_path) == files
    assert cc.differences(files, cc.committed(tmp_path)) == []


def test_an_oversized_generated_report_is_refused_but_a_hand_written_file_is_not_read(
        tmp_path, monkeypatch):
    """Copilot on #15: committed() reads each file in docs/coverage/ with a bound."""
    (tmp_path / "docs" / "coverage").mkdir(parents=True)
    (tmp_path / "docs" / "coverage" / "assessment.md").write_text("# By hand\n" + "x" * 500)
    report = tmp_path / "docs" / "coverage" / "fake.md"
    report.write_bytes(cc.NOTICE.encode() + b"short\n")
    monkeypatch.setattr(cc, "MAX_REPORT_BYTES", len(cc.NOTICE) + 6)
    assert list(cc.committed(tmp_path)) == ["docs/coverage/fake.md"]
    report.write_bytes(cc.NOTICE.encode() + b"longer\n")
    with pytest.raises(cc.CoverageError, match=f"larger than {len(cc.NOTICE) + 6} bytes") as e:
        cc.committed(tmp_path)
    assert e.value.code == cc.E_SIZE


def test_an_unreadable_committed_report_is_a_coded_error(tmp_path):
    (tmp_path / "docs" / "coverage" / "fake.md").mkdir(parents=True)  # a directory, not a file
    with pytest.raises(cc.CoverageError, match="docs/coverage/fake.md could not be read") as e:
        cc.committed(tmp_path)
    assert e.value.code == cc.E_FILE


def failing(number):
    def fail(*args, **kwargs):
        raise OSError(number, os.strerror(number), "somewhere")
    return fail


@pytest.mark.parametrize(("number", "code"), [(errno.EIO, "E_FILE_TRANSIENT"),
                                              (errno.EACCES, "E_FILE")])
def test_a_committed_report_read_failure_says_whether_retrying_could_help(tmp_path, monkeypatch,
                                                                         number, code):
    (tmp_path / "docs" / "coverage").mkdir(parents=True)
    (tmp_path / "docs" / "coverage" / "fake.md").write_text("x")
    monkeypatch.setattr(pathlib.Path, "open", failing(number))
    with pytest.raises(cc.CoverageError) as e:
        cc.committed(tmp_path)
    assert e.value.code == getattr(cc, code)


def test_differences_names_missing_extra_and_differing_reports():
    assert cc.differences({"a": b"1", "b": b"2"}, {"b": b"3", "c": b"4"}) == [
        "missing: a is generated but not committed",
        "differs: b does not match what the cases and triage generate",
        "extra: c is committed but nothing generates it",
    ]


def test_main_writes_under_out_then_check_passes_and_a_changed_byte_fails(tree, capsys,
                                                                        monkeypatch):
    root = tree(*CASES[:2])
    monkeypatch.setattr(cc, "ROOT", root)
    assert cc.main([]) == 0
    assert "Wrote 2 files" in capsys.readouterr().out
    assert cc.main(["--check"]) == 0
    assert "2 generated files match" in capsys.readouterr().out
    report = root / "docs" / "coverage" / "fake.md"
    report.write_bytes(report.read_bytes() + b" ")
    assert cc.main(["--check"]) == 1
    out = capsys.readouterr().out
    assert "differs: docs/coverage/fake.md" in out and "scripts/clause-coverage" in out


def test_main_out_writes_elsewhere(tree, tmp_path_factory, monkeypatch, capsys):
    root = tree(*CASES[:2])
    monkeypatch.setattr(cc, "ROOT", root)
    out = tmp_path_factory.mktemp("out")
    assert cc.main(["--out", str(out)]) == 0
    assert (out / "docs" / "coverage" / "fake.md").exists()
    assert not (root / "docs").exists()


def test_main_exits_2_when_a_specification_text_is_unavailable(tree, monkeypatch, capsys):
    root = tree(*CASES[:2])
    monkeypatch.setattr(cc, "ROOT", root)

    def unavailable(pin):
        raise spec_source.SpecUnavailable(spec_source.E_FETCH, "offline")

    monkeypatch.setattr(cc, "load_text", unavailable)
    assert cc.main(["--check"]) == 2
    assert capsys.readouterr().err.strip() == "e.env.kcs-spec.fetch.r: offline"


def test_main_exits_3_on_a_coded_input_error(tree, monkeypatch, capsys):
    root = tree(case("KERI-0001", {"check": "verdict", "level": "MUST", "expected": 1}))
    monkeypatch.setattr(cc, "ROOT", root)
    assert cc.main(["--check"]) == 3
    assert capsys.readouterr().err.startswith(cc.E_CASE + ": ")


def test_main_check_exits_4_when_a_committed_report_cannot_be_read(tree, monkeypatch, capsys):
    """Copilot on #15: a filesystem failure in --check is a coded error, not a traceback."""
    root = tree(*CASES[:2])
    monkeypatch.setattr(cc, "ROOT", root)
    (root / "docs" / "coverage" / "fake.md").mkdir(parents=True)
    assert cc.main(["--check"]) == 4
    assert capsys.readouterr().err.startswith(cc.E_FILE + ": ")


@pytest.mark.parametrize(("number", "code"), [(errno.EIO, "E_FILE_TRANSIENT"),
                                              (errno.ENOSPC, "E_FILE")])
def test_main_check_exits_4_when_the_temporary_copy_cannot_be_made(tree, monkeypatch, capsys,
                                                                   number, code):
    root = tree(*CASES[:2])
    monkeypatch.setattr(cc, "ROOT", root)
    monkeypatch.setattr(cc.tempfile, "TemporaryDirectory", failing(number))
    assert cc.main(["--check"]) == 4
    assert capsys.readouterr().err.startswith(getattr(cc, code) + ": ")


@pytest.mark.parametrize(("number", "code"), [(errno.EAGAIN, "E_FILE_TRANSIENT"),
                                              (errno.EROFS, "E_FILE")])
def test_main_check_exits_4_when_the_temporary_copy_cannot_be_written(tree, monkeypatch, capsys,
                                                                      number, code):
    root = tree(*CASES[:2])
    monkeypatch.setattr(cc, "ROOT", root)
    monkeypatch.setattr(pathlib.Path, "write_bytes", failing(number))
    assert cc.main(["--check"]) == 4
    assert capsys.readouterr().err.startswith(getattr(cc, code) + ": ")


@pytest.mark.parametrize("operation", ["mkdir", "write_bytes", "unlink"])
@pytest.mark.parametrize(("number", "code"), [(errno.EBUSY, "E_FILE_TRANSIENT"),
                                              (errno.EACCES, "E_FILE")])
def test_main_write_exits_4_when_the_report_cannot_be_written(tree, monkeypatch, capsys,
                                                              operation, number, code):
    """Copilot on #15: write mode classifies mkdir, unlink and write failures too."""
    root = tree(*CASES[:2])
    monkeypatch.setattr(cc, "ROOT", root)
    (root / "docs" / "coverage").mkdir(parents=True)
    (root / "docs" / "coverage" / "old.md").write_text(cc.NOTICE + "stale")  # so unlink runs
    monkeypatch.setattr(pathlib.Path, operation, failing(number))
    assert cc.main([]) == 4
    assert capsys.readouterr().err.startswith(getattr(cc, code) + ": ")


def test_the_wrapper_script_runs_main():
    script = (ROOT / "scripts" / "clause-coverage").read_text()
    assert "from generators.spec_tables.clause_coverage import main" in script
    assert os.access(ROOT / "scripts" / "clause-coverage", os.X_OK)


# --- The committed report -----------------------------------------------------------------------


def real_files():
    try:
        return cc.generate(ROOT)
    except spec_source.SpecUnavailable as e:
        if os.environ.get("KCS_REQUIRE_SPEC") == "1":
            raise
        return pytest.skip(f"a pinned specification text is unavailable: {e}")


def test_the_committed_report_is_what_the_cases_and_triage_generate():
    assert cc.differences(real_files(), cc.committed(ROOT)) == []


@pytest.mark.parametrize("pin", [spec_source.cesr_pin(), spec_source.KERI], ids=["cesr", "keri"])
def test_every_keyword_sentence_of_each_pinned_text_is_in_the_report_exactly_once(pin):
    files = real_files()
    text = spec_source.load_spec(pin=pin)
    want = sorted((s.line, s.text) for s in cc.keyword_sentences(text))
    rows = report_rows(files[f"docs/coverage/{pin.label}.md"].decode())
    assert sorted(rows) == want
    assert len(rows) == len(set(rows))


# --- Practice ------------------------------------------------------------------------------------
# A keyword sentence in text that disclaims normativity, or that states common practice rather than
# a requirement, is triaged practice. It is counted apart from the obligations and permissions, and
# a case covers it by citing it as a clause or by quoting it in an INTEROP assertion's basis.

PRACTICE = {"scope": "practice", "security": False}


def basis(quote, pin=FAKE):
    return {"check": "rejected", "level": "INTEROP", "expected": None, "basis": {
        "text": "Common practice.", "spec": pin.label, "commit": pin.commit, "quote": quote,
        "section": "x", "url": "u"}}


def practice_measured(cases, triage=None):
    triage = {"A parser SHOULD log it.": PRACTICE, "A parser MAY stop.": PRACTICE,
              **(triage or {})}
    return cc.measure(cases, {(FAKE.label, FAKE.commit): (FAKE, FAKE_TEXT)}, {"fake": triage})


def test_practice_is_a_triage_scope_that_needs_no_reason(tree):
    entries = {"A parser SHOULD log it.": PRACTICE}
    assert cc.load_triage(tree(triage=triage_file(entries)), "fake") == entries


def test_a_case_may_quote_a_sentence_in_its_basis(tree):
    root = tree(case("IPEX-0001", basis("A parser SHOULD log it.")))
    assert [c["id"] for c in cc.load_cases(root)] == ["IPEX-0001"]


@pytest.mark.parametrize("value", [{"text": "t"}, {"text": "t", "spec": "fake", "commit": "c"},
                                   {"text": "t", "spec": "fake", "commit": "c", "quote": ""}, 7,
                                   # Hostile pass on #22: the schema requires section and url too.
                                   {"text": "t", "spec": "fake", "commit": "c", "quote": "q"},
                                   {"text": "t", "spec": "fake", "commit": "c", "quote": "q",
                                    "section": "s"}])
def test_a_basis_that_is_neither_text_nor_a_quoted_sentence_is_a_coded_error(tree, value):
    bad = case("IPEX-0001", basis("A parser SHOULD log it."))
    bad["assertions"][0]["basis"] = value
    root = tree()
    path = root / "cases" / "ipex" / "IPEX-0001.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(bad))
    with pytest.raises(cc.CoverageError, match="basis") as e:
        cc.load_cases(root)
    assert e.value.code == cc.E_CASE


def test_a_basis_that_quotes_a_practice_sentence_covers_it():
    (coverage,) = practice_measured([case("IPEX-0001", basis("A parser SHOULD log it."))])
    log = row(coverage, "A parser SHOULD log it.")
    assert log.basis == ["IPEX-0001"] and log.direct == [] and log.inferred == []
    assert log.covered and log.polarity == "negative" and log.levels == {"INTEROP": 1}


def test_a_clause_that_cites_a_practice_sentence_covers_it():
    (coverage,) = practice_measured([case("KERI-0001", must("A parser MAY stop."))])
    assert row(coverage, "A parser MAY stop.").covered


def test_a_basis_never_covers_an_obligation():
    """An INTEROP assertion is never evidence about an obligation, so a basis quoting a sentence
    that is not triaged practice lists the case but covers nothing."""
    (coverage,) = practice_measured([case("IPEX-0001", basis("A parser MUST refuse a bad code."))])
    bad_code = row(coverage, "A parser MUST refuse a bad code.")
    assert bad_code.basis == ["IPEX-0001"] and not bad_code.covered and bad_code.polarity == ""


def test_a_practice_sentence_cited_only_by_an_inactive_case_is_not_covered():
    (coverage,) = practice_measured([case("IPEX-0001", basis("A parser SHOULD log it."),
                                          status="draft")])
    assert not row(coverage, "A parser SHOULD log it.").covered


def test_a_basis_quote_matching_no_keyword_sentence_is_listed_as_a_basis():
    (coverage,) = practice_measured([case("IPEX-0001", basis("A plain line with no keyword."))])
    assert coverage.unmapped == [cc.Unmapped(line=11, quote="A plain line with no keyword.",
                                             cited_as="basis", cases=["IPEX-0001"])]


def test_a_basis_quote_not_in_its_pinned_text_is_a_coded_error():
    with pytest.raises(cc.CoverageError, match="IPEX-0001 a1") as e:
        practice_measured([case("IPEX-0001", basis("Nowhere in the text."))])
    assert e.value.code == cc.E_CASE


def test_practice_sentences_are_counted_apart_from_obligations_and_permissions():
    (coverage,) = practice_measured([case("IPEX-0001", basis("A parser SHOULD log it.")),
                                     case("KERI-0001", must("A parser MUST refuse a bad code."))])
    summary = cc.summarize(coverage)
    assert summary == {
        "MUST": 3, "SHOULD": 1, "MAY": 0, "covered": 1, "uncovered": 3, "both": 0,
        "validator": 0, "out-of-scope": 0, "untestable": 0, "unassessed": 4,
        "security covered": 0, "security uncovered": 0,
        "practice": 2, "practice covered": 1, "unmapped": 0,
    }


def test_the_spec_report_lists_practice_sentences_in_their_own_part():
    (coverage,) = practice_measured([case("IPEX-0001", basis("A parser SHOULD log it."))])
    text = cc.render_spec("fake", [coverage])
    obligations, rest = text.split("### Permissions")
    permissions, practice = rest.split("### Practice")
    assert "SHOULD log it." not in obligations and "MAY stop." not in permissions
    assert "| practice | 0 | 0 | 0 | INTEROP 1 | negative | IPEX-0001 (basis) " \
           "| A parser SHOULD log it. |" in practice
    assert "| practice | 0 | 0 | 0 | — | — | — | A parser MAY stop. |" in practice
    assert "3 MUST, 1 SHOULD and 0 MAY or OPTIONAL, and 2 triaged as practice" in text


def test_a_spec_report_with_no_practice_sentence_says_so():
    (coverage,) = measured()
    assert "No sentence of this text is triaged as practice." in cc.render_spec("fake", [coverage])


def test_the_index_counts_practice_in_its_own_rows_and_explains_the_scope():
    index = cc.render_index(practice_measured([case("IPEX-0001", basis("A parser SHOULD log it."))]))
    assert "| Practice sentences | 2 |" in index
    assert "| Practice sentences covered by an active case | 1 |" in index
    assert "`practice`" in index and "basis" in index


def test_generate_reads_the_text_a_basis_quotes_even_when_no_clause_cites_it(tree):
    root = tree(case("IPEX-0001", basis("A parser SHOULD log it.")),
                triage=triage_file({"A parser SHOULD log it.": PRACTICE}))
    text = cc.generate(root)["docs/coverage/fake.md"].decode()
    assert "IPEX-0001 (basis)" in text


def test_a_basis_quoting_an_unpinned_commit_is_a_coded_error(tree):
    bad = basis("A parser SHOULD log it.")
    bad["basis"]["commit"] = "0" * 40
    root = tree(case("IPEX-0001", bad))
    with pytest.raises(cc.CoverageError, match="basis") as e:
        cc.generate(root)
    assert e.value.code == cc.E_PIN
