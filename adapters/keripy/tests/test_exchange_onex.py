"""acdc.verify and exn.verify on keripy 1.2.14: not declared, and answered as undeclared
operations, because both carry 2.XX bodies that keripy 1.2.14 cannot read."""

import json

import pytest

from kcs_adapter_keripy import protocol

pytestmark = pytest.mark.onex


@pytest.mark.parametrize("op", ["acdc.verify", "exn.verify"])
def test_keripy_1x_does_not_declare_or_perform_the_acdc_operations(op):
    hello = json.loads(protocol.handle_line(b'{"id":0,"op":"hello","protocol":1}'))["result"]
    assert op not in hello["operations"]
    assert not [f for f in hello["features"] if f.startswith("acdc.")]
    response = json.loads(protocol.handle_line(json.dumps({"id": 5, "op": op}).encode()))
    assert response["error"]["kind"] == "unsupported"
