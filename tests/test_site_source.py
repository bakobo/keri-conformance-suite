"""tools/site_source.py: the site's markdown source, assembled from the README, docs/ and the
results, with the results pages generated from result files that are untrusted input."""

import json
import re

import pytest
from conftest import ROOT
from result_docs import REPRODUCED, SUBMITTED, case, record, report, result

from keri_conformance.errors import RunnerError
from tools import site_source as S
from tools.results import Result, result_path


def loaded(*docs):
    return [Result(result_path(doc), doc) for doc in docs]


# --- escaping -----------------------------------------------------------------------------------

def test_text_escapes_html_and_markdown():
    assert S.text("<script>alert(1)</script>") == (
        "&lt;script&gt;alert\\(1\\)&lt;/script&gt;")
    assert S.text("a|b *c* [d](e) `f` & 'g' \"h\"") == (
        "a\\|b \\*c\\* \\[d\\]\\(e\\) \\`f\\` &amp; &#39;g&#39; &quot;h&quot;")
    assert S.text("line\nbreak\ttab\x00nul") == "line break tab nul"
    assert S.text("2.1.0.dev1") == "2\\.1\\.0\\.dev1"


def test_text_bounds_what_it_shows():
    shown = S.text("x" * 1000, limit=10)
    assert shown == "xxxxxxxxxx…"


# --- link rewriting -----------------------------------------------------------------------------

@pytest.mark.parametrize(("source", "target", "before", "after"), [
    ("README.md", "index.md", "[d](docs/design.md)", "[d](design.md)"),
    ("README.md", "index.md", "[d](docs/design.md#versioning)", "[d](design.md#versioning)"),
    ("README.md", "index.md", "[l](LICENSE)",
     f"[l]({S.REPO_URL}/blob/main/LICENSE)"),
    ("docs/design.md", "design.md", "[s](../SECURITY.md)",
     f"[s]({S.REPO_URL}/blob/main/SECURITY.md)"),
    ("docs/design.md", "design.md", "[a](adapter-protocol.md)", "[a](adapter-protocol.md)"),
    ("docs/coverage/cesr.md", "coverage/cesr.md", "[d](../design.md)", "[d](../design.md)"),
    ("docs/coverage/cesr.md", "coverage/cesr.md", "[r](../../README.md)", "[r](../index.md)"),
    ("docs/design.md", "design.md", "[x](https://example.com/a.md)",
     "[x](https://example.com/a.md)"),
    ("docs/design.md", "design.md", "[x](#terms)", "[x](#terms)"),
    ("docs/design.md", "design.md", "[x](mailto:a@b.c)", "[x](mailto:a@b.c)"),
    ("docs/design.md", "design.md", "[x](../../outside.md)", "[x](../../outside.md)"),
    ("README.md", "index.md", '[d](docs/design.md "Design")', '[d](design.md "Design")'),
])
def test_rewrite_links(source, target, before, after):
    assert S.rewrite_links(before, source, target) == after


def test_rewrite_links_leaves_code_blocks_alone():
    text = "[d](docs/design.md)\n\n```md\n[d](docs/design.md)\n```\n[e](docs/x.md)\n"
    assert S.rewrite_links(text, "README.md", "index.md") == (
        "[d](design.md)\n\n```md\n[d](docs/design.md)\n```\n[e](x.md)\n")


# --- results pages ------------------------------------------------------------------------------

def test_no_results_still_gives_an_index():
    pages = S.render_results([])
    assert list(pages) == ["results/index.md"]
    assert "No results have been published yet" in pages["results/index.md"]


def _two_versions():
    old = result(report(suite_version="0.0.1"), REPRODUCED)
    new = result(report(suite_version="0.1.0", name="cesrox", version="0.1.8 (said 0.4.3)",
                        composes=["keri.escrow"]), SUBMITTED)
    keri = result(report([case("KERI-0001", profile="keri-1.0",
                               records=[record(self_agreement=True)])],
                         profile="keri-1.0", suite_version="0.1.0"), REPRODUCED)
    return loaded(old, new, keri)


def test_index_has_one_matrix_per_suite_version_newest_first():
    index = S.render_results(_two_versions())["results/index.md"]
    headings = re.findall(r"^## (.*)$", index, re.MULTILINE)
    assert headings == ["Suite version 0\\.1\\.0", "Suite version 0\\.0\\.1"]
    newer, older = index.split("## Suite version 0\\.0\\.1")
    assert "cesrox" in newer and "cesrox" not in older
    # Each table sits under exactly one suite version heading.
    assert newer.count("| Implementation |") == 2 and older.count("| Implementation |") == 2


def test_matrix_labels_provenance_on_every_row():
    index = S.render_results(_two_versions())["results/index.md"]
    rows = [line for line in index.splitlines() if line.startswith("| [")]
    assert rows
    for row in rows:
        assert ("Reproduced by CI" in row) != ("Submitted claim, not reproduced" in row)


def test_matrix_cells_carry_verdict_counts_and_a_link():
    index = S.render_results(_two_versions())["results/index.md"]
    assert ("[conformant](cesrox/0.1.8-said-0.4.3/cesr-1.0-submitted.md) "
            "· MUST 1 pass, 0 fail · SHOULD 0 pass, 0 fail") in index
    assert "[conformant](keripy/2.1.0.dev1/keri-1.0-reproduced.md)" in index
    assert "keri\\.escrow" in index
    assert "1 self\\-agreement pass" in index
    assert "2026\\-10\\-09" in index


def test_a_profile_a_row_lacks_is_marked_not_run():
    index = S.render_results(_two_versions())["results/index.md"]
    assert "not run" in index


def test_detail_page_states_the_claim_and_every_case():
    failing = case("CESR-0002", outcome="fail",
                   records=[record("a1", outcome="fail", detail="it <b>accepted</b> " + "x" * 400),
                            record("a2", level="SHOULD", self_agreement=True)])
    failing["failure"] = {"kind": "timeout", "detail": "no answer"}
    unsupported = case("CESR-0003", outcome="not-supported",
                       records=[record(outcome="not-supported")])
    unsupported["missing_features"] = ["cesr.native"]
    unsupported["missing_operation"] = "cesr.encode"
    aborted = {"code": "e.x.f", "reason": "it stopped <here>", "problems": [],
               "at_case": "CESR-0003", "exit_code": 3}
    doc = result(report([case(), failing, unsupported], aborted=aborted), SUBMITTED)
    pages = S.render_results(loaded(doc))
    page = pages["results/keripy/2.1.0.dev1/cesr-1.0-submitted.md"]
    assert page.startswith("# keripy 2\\.1\\.0\\.dev1, profile cesr\\-1\\.0\n")
    assert '!!! warning "Submitted claim, not reproduced"' in page
    assert "Jane Maintainer" in page and SUBMITTED["pull_request"] in page
    assert "| Verdict | aborted |" in page
    assert "it stopped &lt;here&gt;" in page
    assert "| CESR\\-0002 | active | cesr\\.parse | fail |" in page
    assert "failure: timeout" in page
    assert "it &lt;b&gt;accepted&lt;/b&gt;" in page and "<b>" not in page
    assert "x" * 300 not in page
    assert "a2 \\(SHOULD\\): self\\-agreement" in page
    assert "missing cesr\\.native" in page and "missing operation cesr\\.encode" in page
    assert "[the full report \\(JSON\\)](cesr-1.0-submitted.json)" in page
    raw = pages["results/keripy/2.1.0.dev1/cesr-1.0-submitted.json"]
    assert json.loads(raw) == doc


def test_detail_page_for_a_reproduced_result():
    pages = S.render_results(loaded(result(provenance=REPRODUCED)))
    page = pages["results/keripy/2.1.0.dev1/cesr-1.0-reproduced.md"]
    assert '!!! success "Reproduced by CI"' in page
    assert REPRODUCED["run"] in page and "0" * 40 in page


def test_implementation_page_lists_its_results_by_suite_version():
    pages = S.render_results(_two_versions())
    page = pages["results/keripy/index.md"]
    assert page.startswith("# keripy\n")
    assert page.index("Suite version 0\\.1\\.0") < page.index("Suite version 0\\.0\\.1")
    assert "[keri\\-1\\.0](2.1.0.dev1/keri-1.0-reproduced.md)" in page
    assert "cesrox" not in page


def test_hostile_text_never_reaches_a_page_unescaped():
    doc = result(report(name="<img src=x onerror=alert(1)>", version="1|2"), SUBMITTED)
    doc["provenance"]["submitter"] = "[click](javascript:alert(1))"
    pages = S.render_results(loaded(doc))
    for path, page in pages.items():
        if path.endswith(".md"):
            assert "<img" not in page
            assert "](javascript" not in page


def test_output_is_deterministic():
    first = S.render_results(_two_versions())
    second = S.render_results(list(reversed(_two_versions())))
    assert first == second


def test_suite_versions_sort_numerically():
    assert S.version_key("0.10.0") > S.version_key("0.9.1")
    assert S.version_key("1.0.0") > S.version_key("1.0.0rc1")


# --- assembling the site source -----------------------------------------------------------------

@pytest.fixture
def repo(tmp_path):
    root = tmp_path / "repo"
    (root / "docs" / "coverage").mkdir(parents=True)
    (root / "README.md").write_text("# Suite\n\nSee [design](docs/design.md) and "
                                    "[the licence](LICENSE).\n")
    (root / "docs" / "design.md").write_text("# Design\n\n[s](../SECURITY.md)\n")
    (root / "docs" / "coverage" / "README.md").write_text("[d](../design.md)\n")
    (root / "docs" / "picture.png").write_bytes(b"\x89PNG")
    return root


def test_assemble_builds_the_source_tree(repo, tmp_path):
    out = tmp_path / "out"
    S.assemble(repo, out, loaded(result()))
    assert (out / "index.md").read_text() == (
        f"# Suite\n\nSee [design](design.md) and [the licence]({S.REPO_URL}/blob/main/LICENSE).\n")
    assert (out / "design.md").read_text() == (
        f"# Design\n\n[s]({S.REPO_URL}/blob/main/SECURITY.md)\n")
    assert (out / "coverage" / "README.md").read_text() == "[d](../design.md)\n"
    assert (out / "picture.png").read_bytes() == b"\x89PNG"
    assert (out / "results" / "index.md").exists()
    assert (out / "results" / "keripy" / "2.1.0.dev1" / "cesr-1.0-submitted.md").exists()
    assert (out / S.MARKER).exists()


def test_assemble_replaces_its_own_previous_output(repo, tmp_path):
    out = tmp_path / "out"
    S.assemble(repo, out, loaded(result()))
    (out / "stale.md").write_text("old")
    S.assemble(repo, out, [])
    assert not (out / "stale.md").exists()
    assert not (out / "results" / "keripy").exists()


def test_assemble_refuses_a_directory_it_did_not_make(repo, tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    (out / "precious.txt").write_text("keep")
    with pytest.raises(RunnerError) as exc:
        S.assemble(repo, out, [])
    assert exc.value.code == S.E_SITE_OUT
    assert (out / "precious.txt").read_text() == "keep"


def test_assemble_refuses_a_docs_page_that_collides_with_the_results(repo, tmp_path):
    (repo / "docs" / "results").mkdir()
    (repo / "docs" / "results" / "index.md").write_text("mine")
    with pytest.raises(RunnerError) as exc:
        S.assemble(repo, tmp_path / "out", [])
    assert exc.value.code == S.E_SITE_COLLISION


# --- command line -------------------------------------------------------------------------------

def test_main_assembles_from_both_result_sources(repo, tmp_path, capsys):
    submitted = tmp_path / "submitted"
    reproduced = tmp_path / "reproduced"
    for root, doc in ((submitted, result(report(name="alpha"))),
                      (reproduced, result(provenance=REPRODUCED))):
        path = root / result_path(doc)
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps(doc))
    out = tmp_path / "out"
    assert S.main(["--repo", str(repo), "--out", str(out), "--results", str(submitted),
                   "--reproduced", str(reproduced)]) == 0
    index = (out / "results" / "index.md").read_text()
    assert "alpha" in index and "keripy" in index
    assert "2 results" in capsys.readouterr().out


def test_main_without_reproduced_results(repo, tmp_path):
    (repo / "results").mkdir()
    assert S.main(["--repo", str(repo), "--out", str(tmp_path / "out")]) == 0


def test_main_refuses_a_reproduced_result_in_the_committed_tree(repo, tmp_path, capsys):
    doc = result(provenance=REPRODUCED)
    path = repo / "results" / result_path(doc)
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(doc))
    assert S.main(["--repo", str(repo), "--out", str(tmp_path / "out")]) == 4
    assert "e.rule.result.provenance.f" in capsys.readouterr().err


def test_main_usage_error(capsys):
    assert S.main(["--bogus"]) == 2
    assert "e.input.format.f" in capsys.readouterr().err


def test_the_real_repository_assembles(tmp_path):
    assert S.main(["--repo", str(ROOT), "--out", str(tmp_path / "out")]) == 0
    assert (tmp_path / "out" / "index.md").exists()
    assert (tmp_path / "out" / "design.md").exists()
