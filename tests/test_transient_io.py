"""Every file the runner reads or writes, and the adapter it starts, reports a transient I/O
failure (an errno that retrying could clear) under its own .r code, and anything else under .f."""

import errno
import json
import pathlib
import shlex

import pytest
from conftest import ROOT, assertion, good, make_case

from keri_conformance import cli, errors
from keri_conformance.session import AdapterSession, load_vocabulary
from keri_conformance.suite import read_suite_version


def failing_open(number):
    def broken(self, *args, **kwargs):
        raise OSError(number, "simulated")
    return broken


def test_vocabulary_read_eio_is_retryable(monkeypatch, tmp_path):
    (tmp_path / "profiles").mkdir()
    (tmp_path / "profiles" / "features.json").write_text('{"features": {}}')
    monkeypatch.setattr(pathlib.Path, "open", failing_open(errno.EIO))
    with pytest.raises(errors.RunnerError) as info:
        load_vocabulary(tmp_path)
    assert info.value.code == errors.E_VOCABULARY_TRANSIENT
    assert info.value.code.endswith(".r")


def test_vocabulary_read_eacces_is_final(monkeypatch, tmp_path):
    (tmp_path / "profiles").mkdir()
    (tmp_path / "profiles" / "features.json").write_text('{"features": {}}')
    monkeypatch.setattr(pathlib.Path, "open", failing_open(errno.EACCES))
    with pytest.raises(errors.RunnerError) as info:
        load_vocabulary(tmp_path)
    assert info.value.code == errors.E_VOCABULARY


@pytest.mark.parametrize(("number", "code"), [(errno.EIO, "E_SUITE_VERSION_TRANSIENT"),
                                              (errno.EACCES, "E_SUITE_VERSION")])
def test_suite_version_read_failures(monkeypatch, number, code):
    monkeypatch.setattr(pathlib.Path, "open", failing_open(number))
    with pytest.raises(errors.RunnerError) as info:
        read_suite_version(ROOT)
    assert info.value.code == getattr(errors, code)


@pytest.mark.parametrize(("number", "code"), [(errno.EAGAIN, "E_ADAPTER_START_TRANSIENT"),
                                              (errno.EMFILE, "E_ADAPTER_START_TRANSIENT"),
                                              (errno.ENOENT, "E_ADAPTER_START")])
def test_adapter_start_failures(monkeypatch, vocabulary, number, code):
    import subprocess

    def broken(*args, **kwargs):
        raise OSError(number, "simulated")

    monkeypatch.setattr(subprocess, "Popen", broken)
    with pytest.raises(errors.RunnerError) as info:
        AdapterSession(good(), vocabulary).open()
    assert info.value.code == getattr(errors, code)


def _run_with_report(tmp_path, report, before_run=lambda: None):
    case = make_case("CESR-0001", "cesr.parse", {"stream": "2d4b"}, [assertion("rejected")])
    directory = tmp_path / "cases"
    directory.mkdir()
    (directory / "CESR-0001.json").write_text(json.dumps(case))
    before_run()
    return cli.main(["run", "--adapter", shlex.join(good()), "--suite", str(ROOT), "--cases",
                     str(directory), "--report", str(report)])


def test_report_write_eio_is_retryable(monkeypatch, tmp_path, capsys):
    def broken(self, *args, **kwargs):
        raise OSError(errno.EIO, "simulated")

    code = _run_with_report(tmp_path, tmp_path / "r.json",
                            lambda: monkeypatch.setattr(pathlib.Path, "write_text", broken))
    assert code == errors.EXIT_FAULT
    assert errors.E_REPORT_WRITE_TRANSIENT in capsys.readouterr().err


def test_report_write_to_a_directory_is_final(tmp_path, capsys):
    code = _run_with_report(tmp_path, tmp_path)
    assert code == errors.EXIT_FAULT
    err = capsys.readouterr().err
    assert errors.E_REPORT_WRITE in err
    assert errors.E_REPORT_WRITE.endswith(".f")
