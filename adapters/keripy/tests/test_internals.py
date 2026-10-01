"""Defensive paths: what the adapter does when keripy behaves outside the adapter's assumptions."""

import io
import json
import sys

import pytest
from keri.core import parsing
from keri.core.counting import Counter

from kcs_adapter_keripy import cesr, errors, keripy_api, main, protocol


def test_keri_passes_adapter_bugs_through_unchanged():
    def bug():
        raise errors.AdapterBug("mine")

    with pytest.raises(errors.AdapterBug):
        errors.keri(bug)


def test_keri_turns_a_keripy_exception_into_a_rejection_naming_its_class():
    def refuse():
        raise KeyError("x")

    with pytest.raises(errors.Rejection) as info:
        errors.keri(refuse)
    assert info.value.klass == "KeyError"


def test_an_extractor_that_yields_despite_abort_is_an_adapter_bug():
    def greedy():
        yield

    with pytest.raises(errors.AdapterBug) as info:
        keripy_api.drive(greedy())
    assert "e.adapter.extractor.yielded.p" in str(info.value)


def test_implementation_without_direct_url_reports_unknown_commit(monkeypatch):
    class Dist:
        version = "9.9.9"

        def read_text(self, name):
            return None

    monkeypatch.setattr(keripy_api.importlib.metadata, "distribution", lambda name: Dist())
    assert keripy_api.implementation() == {"name": "keripy", "version": "9.9.9",
                                           "commit": "unknown"}


@pytest.mark.main
def test_main_a_1_00_code_with_neither_a_parser_method_nor_quadlet_counting_is_rejected(
        monkeypatch):
    # No such code exists in keripy main today; if one appears, the adapter must not guess.
    monkeypatch.setitem(parsing.Parser.Methods[1][0], "ControllerIdxSigs", None)
    stream = b"-_AAABAA" + bytes(Counter(code="-A", count=0, version=keripy_api.kering.Vrsn_1_0)
                                 .qb64b)
    assert cesr.parse(stream) == {"reject": {"class": "UnexpectedCountCodeError"}}


@pytest.mark.onex
def test_onex_a_known_code_without_a_transcription_is_rejected(monkeypatch):
    monkeypatch.setattr(keripy_api.OneX, "_sequences", lambda self: {})
    stream = bytes(Counter(code="-A", count=0, gvrsn=keripy_api.kering.Vrsn_1_0).qb64b)
    assert cesr.parse(stream) == {"reject": {"class": "UnexpectedCountCodeError"}}


def test_serve_skips_blank_lines_and_answers_each_request():
    stdin = io.BytesIO(b'{"id":0,"op":"hello","protocol":1}\n\n'
                       b'{"id":1,"op":"cesr.parse","stream":""}\n')
    stdout = io.BytesIO()
    protocol.serve(stdin, stdout)
    responses = [json.loads(line) for line in stdout.getvalue().splitlines()]
    assert [r["id"] for r in responses] == [0, 1]
    assert responses[1] == {"id": 1, "result": {"items": []}}


def test_main_routes_responses_to_stdout_and_everything_else_to_stderr(monkeypatch):
    class Std:
        def __init__(self, data=b""):
            self.buffer = io.BytesIO(data)

    stdin, stdout = Std(b'{"id":3,"op":"cesr.encode","code":"M","raw":"0102","domain":"text"}\n'), Std()
    monkeypatch.setattr(sys, "stdin", stdin)
    monkeypatch.setattr(sys, "stdout", stdout)
    assert main.main() == 0
    assert sys.stdout is sys.stderr
    assert json.loads(stdout.buffer.getvalue()) == {"id": 3, "result": {"encoded": "4d414543"}}
