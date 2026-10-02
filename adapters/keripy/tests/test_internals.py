"""Defensive paths: what the adapter does when keripy behaves outside the adapter's assumptions."""

import io
import json
import sys

import pytest
from keri.core.coring import Matter

from kcs_adapter_keripy import errors, keripy_api, main, measure, protocol


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


def test_implementation_without_direct_url_reports_unknown_commit(monkeypatch):
    class Dist:
        version = "9.9.9"

        def read_text(self, name):
            return None

    monkeypatch.setattr(keripy_api.importlib.metadata, "distribution", lambda name: Dist())
    assert keripy_api.implementation() == {"name": "keripy", "version": "9.9.9",
                                           "commit": "unknown"}


# -- the tracked buffer

def recorder():
    return measure.Recorder(keripy_api.load())


def test_tracked_slices_know_their_offset_and_deletions_advance_it():
    buf = measure.Tracked(b"abcdef", 10)
    sub = buf[2:5]
    assert isinstance(sub, measure.Tracked) and sub.base == 12 and bytes(sub) == b"cde"
    assert buf[0] == ord("a")
    assert not isinstance(buf[::2], measure.Tracked)
    del buf[:2]  # a buffer with no recorder just advances
    assert buf.base == 12 and bytes(buf) == b"cdef"


@pytest.mark.parametrize("key", [0, slice(1, 3), slice(0, 4, 2)])
def test_tracked_refuses_deletions_other_than_from_the_front(key):
    buf = measure.Tracked(b"abcdef", 0)
    with pytest.raises(errors.AdapterBug):
        del buf[key]


def test_an_untracked_buffer_is_an_adapter_bug():
    with pytest.raises(errors.AdapterBug):
        measure.base_of(bytearray(b"x"))


def test_an_extracted_object_of_an_unknown_kind_is_an_adapter_bug():
    with pytest.raises(errors.AdapterBug):
        recorder().extracted(object(), measure.Tracked(b""), 0, 0, True)


def test_a_deletion_that_is_neither_counter_body_nor_message_is_an_adapter_bug():
    rec = recorder()
    buf = measure.Tracked(bytes(Matter(raw=bytes(32), code="D").qb64b), 0, rec)
    with pytest.raises(errors.AdapterBug):
        del buf[:4]


def test_an_empty_deletion_outside_a_group_is_ignored():
    rec = recorder()
    buf = measure.Tracked(b"-AAB", 0, rec)
    del buf[:0]
    assert rec.items == []


def test_a_message_consumed_at_other_than_its_declared_size_is_an_adapter_bug():
    rec = recorder()
    body = b'{"v":"KERI10JSON000050_","t":"rpy","d":"","r":"/x","a":{"x":"' + b"y" * 40 + b'"}}'
    buf = measure.Tracked(body, 0, rec)
    with pytest.raises(errors.AdapterBug) as info:
        del buf[:60]
    assert "e.self.unknown.message-size.f" in str(info.value)


def test_a_parser_that_returns_without_consuming_is_an_adapter_bug(monkeypatch):
    keripy = keripy_api.load()

    def idle(parser, ims):
        return
        yield

    monkeypatch.setattr(keripy, "run", idle)
    with pytest.raises(errors.AdapterBug) as info:
        measure.parse(keripy, b"-AAB")
    assert "e.self.unknown.parse-stalled.f" in str(info.value)


@pytest.mark.main
def test_main_a_native_body_is_unsupported():
    from keri import kering
    from keri.core import eventing, signing
    signer = signing.Signer(raw=bytes(32), transferable=True)
    serder = eventing.incept(keys=[signer.verfer.qb64])  # keripy main's default: native CESR
    assert serder.kind == kering.Kinds.cesr
    with pytest.raises(errors.Unsupported) as info:
        measure.parse(keripy_api.load(), b"-_AAACAA" + serder.raw)
    assert "e.feature.unsupported.native-body.f" in str(info.value)


# -- the stdio loop

def test_serve_answers_a_blank_line_with_a_null_id_error_and_each_request():
    stdin = io.BytesIO(b'{"id":0,"op":"hello","protocol":1}\n\n'
                       b'{"id":1,"op":"cesr.parse","stream":""}\n')
    stdout = io.BytesIO()
    protocol.serve(stdin, stdout)
    responses = [json.loads(line) for line in stdout.getvalue().splitlines()]
    assert [r["id"] for r in responses] == [0, None, 1]
    assert responses[1]["error"]["kind"] == "harness"
    assert "e.input.format.request.f" in responses[1]["error"]["message"]
    assert responses[2] == {"id": 1, "result": {"items": []}}


def test_main_routes_responses_to_stdout_and_everything_else_to_stderr(monkeypatch):
    class Std:
        def __init__(self, data=b""):
            self.buffer = io.BytesIO(data)

    request = b'{"id":3,"op":"cesr.encode","code":"M","raw":"0102","domain":"text"}\n'
    stdin, stdout = Std(request), Std()
    monkeypatch.setattr(sys, "stdin", stdin)
    monkeypatch.setattr(sys, "stdout", stdout)
    assert main.main() == 0
    assert sys.stdout is sys.stderr
    assert json.loads(stdout.buffer.getvalue()) == {"id": 3, "result": {"encoded": "4d414543"}}


# -- review round 1 (PR #6)

def test_tracked_equality_is_bytearray_equality_and_it_is_unhashable():
    assert measure.Tracked(b"ab", 5) == measure.Tracked(b"ab", 9) == b"ab"
    assert measure.Tracked(b"ab", 5) != measure.Tracked(b"ac", 5)
    with pytest.raises(TypeError):
        hash(measure.Tracked(b"ab", 5))


@pytest.mark.parametrize("key", [0, slice(1, 3), slice(0, 4, 2)])
def test_a_refused_deletion_is_a_lookup_error_and_still_an_adapter_bug(key):
    buf = measure.Tracked(b"abcdef", 0)
    with pytest.raises(LookupError) as info:
        del buf[key]
    assert isinstance(info.value, errors.AdapterBug)
    assert bytes(buf) == b"abcdef" and buf.base == 0

