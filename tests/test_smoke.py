import subprocess
import sys

import keri_conformance
from keri_conformance import cli


def test_version_is_a_string():
    assert isinstance(keri_conformance.__version__, str)


def test_cli_prints_version(capsys):
    assert cli.main(["--version"]) == 0
    assert capsys.readouterr().out.strip() == f"kcs {keri_conformance.__version__}"


def test_cli_without_arguments_prints_usage_and_fails(capsys):
    assert cli.main([]) == 2
    assert "usage" in capsys.readouterr().err.lower()


def test_installed_entry_point_runs():
    out = subprocess.run(["kcs", "--version"], capture_output=True, text=True, check=True)
    assert out.stdout.startswith("kcs ")


def test_module_entry_point_runs():
    out = subprocess.run([sys.executable, "-m", "keri_conformance", "--version"],
                         capture_output=True, text=True, check=True)
    assert out.stdout.startswith("kcs ")


def test_module_main_in_process(monkeypatch, capsys):
    import runpy

    import pytest

    monkeypatch.setattr(sys, "argv", ["kcs", "--version"])
    with pytest.raises(SystemExit) as exit_info:
        runpy.run_module("keri_conformance", run_name="__main__")
    assert exit_info.value.code == 0
    assert capsys.readouterr().out.startswith("kcs ")
