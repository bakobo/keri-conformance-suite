"""The baseline tool's handling of bad inputs and failed writes: every one is a coded error
with a non-zero exit, never a traceback, and write never emits an unusable baseline."""

import json

import pytest
from test_baseline import base_report, summary

from kcs_adapter_keripy import baseline


@pytest.fixture
def files(tmp_path):
    base, rep = tmp_path / "baseline.json", tmp_path / "report.json"
    base.write_text(json.dumps(summary()))
    rep.write_text(json.dumps(base_report()))
    return base, rep


def run(*args):
    return baseline.main([*map(str, args)])


# -- missing and unreadable files

@pytest.mark.parametrize("which", ["baseline", "report"])
def test_a_missing_file_is_a_coded_error(files, capsys, which):
    base, rep = files
    (base if which == "baseline" else rep).unlink()
    assert run("compare", base, rep) == 2
    err = capsys.readouterr().err
    assert "e.input.missing.file.f" in err and "does not exist" in err


def test_an_unreadable_file_is_a_coded_error(files, capsys, tmp_path):
    base, _ = files
    assert run("compare", base, tmp_path) == 2  # a directory
    assert "e.env.filesystem.read.r" in capsys.readouterr().err


# -- bounded reads (N)

def test_the_file_bound_is_64_mib():
    assert baseline.MAX_FILE_BYTES == 64 * 1024 * 1024


@pytest.mark.parametrize("which", ["baseline", "report"])
def test_a_file_over_the_bound_is_a_coded_size_error(files, capsys, monkeypatch, which):
    base, rep = files
    path = base if which == "baseline" else rep
    monkeypatch.setattr(baseline, "MAX_FILE_BYTES", path.stat().st_size - 1)
    assert run("compare", base, rep) == 2
    assert "e.input.range.file-size.f" in capsys.readouterr().err


def test_a_file_of_exactly_the_bound_is_read(files, monkeypatch):
    base, rep = files
    monkeypatch.setattr(baseline, "MAX_FILE_BYTES",
                        max(base.stat().st_size, rep.stat().st_size))
    assert run("compare", base, rep) == 0
