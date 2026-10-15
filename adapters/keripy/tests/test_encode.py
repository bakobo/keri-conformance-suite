"""cesr.encode: keripy's Matter does the encoding; the adapter only hexes it."""

import pytest
from keri.core.coring import Matter

from kcs_adapter_keripy import cesr

RAW32 = bytes(range(32))


def test_text_encoding_is_keripys_qb64b():
    result = cesr.encode("D", RAW32.hex(), "text")
    assert result == {"encoded": bytes(Matter(raw=RAW32, code="D").qb64b).hex()}
    assert bytes.fromhex(result["encoded"]).startswith(b"D")
    assert len(bytes.fromhex(result["encoded"])) == 44


def test_binary_encoding_is_keripys_qb2():
    result = cesr.encode("D", RAW32.hex(), "binary")
    assert result == {"encoded": bytes(Matter(raw=RAW32, code="D").qb2).hex()}
    assert len(bytes.fromhex(result["encoded"])) == 33


def test_short_number():
    assert cesr.encode("M", "0102", "text") == {"encoded": b"MAEC".hex()}


@pytest.mark.parametrize("domain", ["text", "binary"])
@pytest.mark.parametrize("code,raw", [("D", "00"), ("#", "00" * 32), ("Zz", "00")])
def test_keripy_refusing_the_input_is_a_rejection_naming_its_class(code, raw, domain, capsys):
    result = cesr.encode(code, raw, domain)
    assert list(result) == ["reject"]
    klass = result["reject"]["class"]
    assert isinstance(klass, str) and klass
    assert f"keripy refused to encode: {klass}" in capsys.readouterr().err
