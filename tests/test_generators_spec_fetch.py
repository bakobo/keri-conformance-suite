"""The pinned CESR specification text is fetched into a cache, used only when its SHA-256 is the
pinned one, and refused with a coded error otherwise. None of these tests touches the network
except ``test_spec_text_is_available_when_required``, which CI runs with KCS_REQUIRE_SPEC=1 so that
an unavailable specification fails the build instead of skipping the tests that need it."""

import hashlib
import io
import os
import pathlib
import runpy
import sys
import urllib.error

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from generators.spec_tables import spec_source

FAKE = b"# Fake spec\n\nThe size component MUST count the Quadlets/triplets.\n"


@pytest.fixture
def cache(tmp_path, monkeypatch):
    monkeypatch.setenv(spec_source.CACHE_ENV, str(tmp_path))
    return tmp_path


@pytest.fixture
def fake_pin(monkeypatch):
    monkeypatch.setattr(spec_source, "SPEC_SHA256", hashlib.sha256(FAKE).hexdigest())


def _serve(monkeypatch, payload=None, error=None):
    calls = []

    def urlopen(url, timeout):
        calls.append((url, timeout))
        if error is not None:
            raise error
        return io.BytesIO(payload)

    monkeypatch.setattr(spec_source.urllib.request, "urlopen", urlopen)
    return calls


def test_spec_text_is_available_when_required():
    """Fails, rather than skips, when KCS_REQUIRE_SPEC=1 and the text cannot be had."""
    try:
        text = spec_source.load_spec()
    except spec_source.SpecUnavailable as e:
        if os.environ.get("KCS_REQUIRE_SPEC") == "1":
            pytest.fail(f"KCS_REQUIRE_SPEC=1 but the specification text is unavailable: {e}")
        pytest.skip(f"the pinned CESR specification text is unavailable: {e}")
    assert hashlib.sha256(text.encode("utf-8")).hexdigest() == spec_source.SPEC_SHA256


def test_cache_defaults_under_the_home_directory(monkeypatch):
    monkeypatch.delenv(spec_source.CACHE_ENV, raising=False)
    assert spec_source.cache_dir() == pathlib.Path.home() / ".cache" / "kcs" / "specs"


def test_cache_directory_follows_the_environment(cache):
    assert spec_source.cache_path() == cache / (
        "cesr-spec-body-037129608b9e6960858b752019ac273d40d7386c.md"
    )


def test_fetch_uses_the_pinned_commit_url(cache, fake_pin, monkeypatch):
    calls = _serve(monkeypatch, FAKE)
    assert spec_source.load_spec() == FAKE.decode()
    url = ("https://raw.githubusercontent.com/trustoverip/kswg-cesr-specification/"
           "037129608b9e6960858b752019ac273d40d7386c/spec/spec-body.md")
    assert calls == [(url, spec_source.FETCH_TIMEOUT_SECONDS)]
    assert spec_source.cache_path().read_bytes() == FAKE


def test_cached_text_is_used_without_fetching(cache, fake_pin, monkeypatch):
    spec_source.cache_path().write_bytes(FAKE)
    calls = _serve(monkeypatch, error=AssertionError("must not fetch"))
    assert spec_source.load_spec() == FAKE.decode()
    assert calls == []


def test_cached_file_with_another_hash_is_refused(cache, monkeypatch):
    spec_source.cache_path().write_bytes(FAKE)
    _serve(monkeypatch, error=AssertionError("must not fetch"))
    with pytest.raises(spec_source.SpecUnavailable) as e:
        spec_source.load_spec()
    assert e.value.code == "e.proof.kcs-spec.digest.f"
    assert "was not used" in str(e.value)


def test_fetched_text_with_another_hash_is_refused_and_not_cached(cache, monkeypatch):
    _serve(monkeypatch, FAKE)
    with pytest.raises(spec_source.SpecUnavailable) as e:
        spec_source.load_spec()
    assert e.value.code == "e.proof.kcs-spec.digest.f"
    assert not spec_source.cache_path().exists()


def test_oversized_response_is_refused(cache, monkeypatch):
    monkeypatch.setattr(spec_source, "MAX_SPEC_BYTES", 4)
    _serve(monkeypatch, FAKE)
    with pytest.raises(spec_source.SpecUnavailable, match="larger than") as e:
        spec_source.load_spec()
    assert e.value.code == "e.env.kcs-spec.oversize.f"


def test_offline_fetch_is_a_retryable_coded_error(cache, monkeypatch):
    _serve(monkeypatch, error=urllib.error.URLError("no route"))
    with pytest.raises(spec_source.SpecUnavailable) as e:
        spec_source.load_spec()
    assert e.value.code == "e.env.kcs-spec.fetch.r"
    assert str(e.value).startswith("e.env.kcs-spec.fetch.r: ")


def test_load_without_fetch_refuses_an_empty_cache(cache):
    with pytest.raises(spec_source.SpecUnavailable, match="not cached"):
        spec_source.load_spec(allow_fetch=False)


def test_regenerate_exits_2_with_the_coded_error_when_the_spec_is_unavailable(
        cache, monkeypatch, capsys):
    _serve(monkeypatch, error=urllib.error.URLError("no route"))
    script = runpy.run_path(str(ROOT / "scripts" / "regenerate"))
    assert script["main"](["--check"]) == 2
    assert "e.env.kcs-spec.fetch.r" in capsys.readouterr().err
