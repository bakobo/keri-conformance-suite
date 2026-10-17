"""acdc.verify and exn.verify on keripy 1.2.14: not declared, and answered as undeclared
operations, because both carry 2.XX bodies that keripy 1.2.14 cannot read."""

import json

import pytest

from kcs_adapter_keripy import protocol

pytestmark = pytest.mark.onex


def test_keripy_1x_does_not_declare_or_perform_exn_verify():
    hello = json.loads(protocol.handle_line(b'{"id":0,"op":"hello","protocol":1}'))["result"]
    assert "exn.verify" not in hello["operations"]
    # Its ACDC features are the 1.x ones acdc.verify serves (test_acdc_onex.py), never 2.x.
    assert [f for f in hello["features"] if f.startswith("acdc.")] == ["acdc.keripy-1x",
                                                                       "acdc.ptel-1x"]
    response = json.loads(protocol.handle_line(b'{"id": 5, "op": "exn.verify"}'))
    assert response["error"]["kind"] == "unsupported"
