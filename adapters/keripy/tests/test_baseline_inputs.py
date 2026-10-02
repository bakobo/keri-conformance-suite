"""The baseline tool's handling of missing, unreadable and malformed files (PR #6 round 2, H)."""

import json

import pytest
from test_baseline import BASE, report


@pytest.fixture
def files(tmp_path):
    base, rep = tmp_path / "baseline.json", tmp_path / "report.json"
    base.write_text(json.dumps(baseline.summarize(report(BASE))))
    return base, rep

from kcs_adapter_keripy import baseline

# -- unreadable inputs (H)

@pytest.mark.parametrize("which", ["baseline", "report"])
def test_a_missing_file_is_a_coded_error(files, capsys, which):
    base, rep = files
    rep.write_text(json.dumps(report(BASE)))
    (base if which == "baseline" else rep).unlink()
    assert baseline.main(["compare", str(base), str(rep)]) == 2
    err = capsys.readouterr().err
    assert "e.input.missing.file.f" in err and "does not exist" in err


def test_an_unreadable_file_is_a_coded_error(files, capsys, tmp_path):
    base, _ = files
    assert baseline.main(["compare", str(base), str(tmp_path)]) == 2  # a directory
    assert "e.env.filesystem.read.r" in capsys.readouterr().err


@pytest.mark.parametrize("content", ["{not json", "[1, 2]", '{"cases": "x"}', "\xff"])
def test_a_malformed_report_is_a_coded_error(files, capsys, content):
    base, rep = files
    rep.write_bytes(content.encode("latin-1"))
    assert baseline.main(["compare", str(base), str(rep)]) == 2
    assert "e.input.format.report.f" in capsys.readouterr().err


def test_a_malformed_baseline_is_a_coded_error(files, capsys):
    base, rep = files
    rep.write_text(json.dumps(report(BASE)))
    base.write_text('{"profile": "cesr-1.0"}')
    assert baseline.main(["compare", str(base), str(rep)]) == 2
    assert "e.input.format.baseline.f" in capsys.readouterr().err
