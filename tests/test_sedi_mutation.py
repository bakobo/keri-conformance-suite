"""sedi-1's mutation acceptance (test-plan item 15): each choice's wrong variant of the reference
model changes the outcome of at least one case resting on that choice, and the committed matrix
docs/profiles/sedi-mutation.md is what the scenarios generate."""

import contextlib
import os
import pathlib

import pytest

from generators.spec_tables import sedi_mutation, spec_source, tables

ROOT = pathlib.Path(__file__).resolve().parent.parent

try:
    CESR_TEXT = spec_source.load_spec()
except spec_source.SpecUnavailable as e:
    if os.environ.get("KCS_REQUIRE_SPEC") == "1":
        raise
    pytest.skip(f"a pinned specification text is unavailable: {e}", allow_module_level=True)

T = tables.load(CESR_TEXT)


@pytest.fixture(scope="module")
def matrix():
    return sedi_mutation.run(T, ROOT)


def test_every_choice_with_cases_has_a_mutant_its_cases_catch(matrix):
    for choice, row in matrix.items():
        if row["cases"]:
            assert row["mutant"], choice
            assert row["caught_by"], f"no case resting on {choice} catches its mutant"
            assert set(row["caught_by"]) <= set(row["cases"]), choice


def test_the_committed_matrix_is_what_the_scenarios_generate(matrix):
    committed = (ROOT / sedi_mutation.DOC).read_text(encoding="utf-8")
    assert committed == sedi_mutation.render(matrix)


def test_a_variant_that_changes_nothing_is_caught_by_nothing(monkeypatch):
    monkeypatch.setitem(sedi_mutation.MUTANTS, "revoked",
                        ("is the reference model", contextlib.nullcontext))
    row = sedi_mutation.run(T, ROOT, only={"revoked"})["revoked"]
    assert row["cases"] and row["caught_by"] == []


def test_the_aggregate_mutant_reads_a_plain_credential_as_the_model_does():
    from generators.spec_tables import sedi_model as sm
    plain = {"a": {"d": "E", "i": "EIssuee"}}
    assert sedi_mutation._issuee_at_first_block(plain, sm.issuee) == "EIssuee"
    assert sedi_mutation._issuee_at_first_block({"A": ["agid", {"i": "x"}]}, sm.issuee) is ...


def test_the_script_writes_the_matrix_and_checks_it(tmp_path, monkeypatch, capsys):
    assert sedi_mutation.main(["--check"]) == 0
    monkeypatch.setattr(sedi_mutation, "DOC", str(tmp_path / "matrix.md"))
    assert sedi_mutation.main(["--check"]) == 1
    assert "is not what the scenarios generate" in capsys.readouterr().err
    assert sedi_mutation.main([]) == 0
    assert (tmp_path / "matrix.md").read_text(encoding="utf-8").startswith("# sedi-1 mutation")
    assert sedi_mutation.main(["--check"]) == 0


def test_a_case_id_used_twice_is_refused(monkeypatch):
    real = sedi_mutation._scenarios

    def twice(root):
        cases = list(real(root))
        yield from cases
        yield cases[0]

    monkeypatch.setattr(sedi_mutation, "_scenarios", twice)
    with pytest.raises(ValueError, match="used twice"):
        sedi_mutation.run(T, ROOT)
