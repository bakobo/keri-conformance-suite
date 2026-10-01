import re
import runpy
import shutil
import subprocess
import sys

import pytest

import keri_conformance
from keri_conformance import cli, protocol

# PEP 440 public version, the subset this project uses (release segment plus optional pre/dev).
PEP440 = re.compile(r"^\d+(\.\d+)*((a|b|rc)\d+)?(\.dev\d+)?$")


def test_version_is_a_pep440_release():
    assert PEP440.match(keri_conformance.__version__)


def test_protocol_version_is_current_and_supported():
    assert protocol.PROTOCOL_VERSION == 1
    assert protocol.PROTOCOL_VERSION in protocol.SUPPORTED_PROTOCOLS


def test_supported_protocols_are_current_and_previous_only():
    current = protocol.PROTOCOL_VERSION
    expected = {current, current - 1} if current > 1 else {current}
    assert set(protocol.SUPPORTED_PROTOCOLS) == expected


def test_cli_prints_version(capsys):
    assert cli.main(["--version"]) == 0
    assert capsys.readouterr().out.strip() == f"kcs {keri_conformance.__version__}"


def test_cli_without_arguments_reports_a_coded_error(capsys):
    assert cli.main([]) == 2
    err = capsys.readouterr().err
    assert err.startswith("e.input.missing.f: ")
    assert "usage" in err.lower()


def test_cli_unknown_argument_reports_a_coded_error(capsys):
    assert cli.main(["--no-such-flag"]) == 2
    err = capsys.readouterr().err
    assert err.startswith("e.input.format.f: ")
    assert "usage" in err.lower()


@pytest.mark.skipif(shutil.which("kcs") is None, reason="kcs is not installed; run via `uv run pytest`")
def test_installed_entry_point_runs():
    out = subprocess.run(["kcs", "--version"], capture_output=True, text=True, check=True)
    assert out.stdout.startswith("kcs ")


def test_module_entry_point_runs():
    out = subprocess.run([sys.executable, "-m", "keri_conformance", "--version"],
                         capture_output=True, text=True, check=True)
    assert out.stdout.startswith("kcs ")


def test_module_main_in_process(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["kcs", "--version"])
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_module("keri_conformance", run_name="__main__")
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.startswith("kcs ")


def test_feature_vocabulary_is_well_formed():
    import json
    import pathlib

    root = pathlib.Path(__file__).resolve().parent.parent
    doc = json.loads((root / "profiles" / "features.json").read_text(encoding="utf-8"))
    assert doc["vocabulary_version"] == 1
    name = re.compile(r"^[a-z0-9]+(\.[a-z0-9-]+)+$")
    assert doc["features"], "the vocabulary must not be empty"
    for feature, entry in doc["features"].items():
        assert name.match(feature), feature
        assert set(entry) == {"description", "composable"}, feature
        assert entry["description"].strip(), feature
        assert isinstance(entry["composable"], bool), feature
    # The features the adapter-protocol example uses must exist, or the doc teaches invalid tokens.
    protocol_doc = (root / "docs" / "adapter-protocol.md").read_text(encoding="utf-8")
    example = re.search(r'"features": \[([^\]]*)\]', protocol_doc).group(1)
    for token in re.findall(r'"([^"]+)"', example):
        assert token in doc["features"], token
    composes = re.search(r'"composes": \[([^\]]*)\]', protocol_doc).group(1)
    for token in re.findall(r'"([^"]+)"', composes):
        assert doc["features"][token]["composable"], token
