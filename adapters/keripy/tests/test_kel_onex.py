"""keri.process on keripy 1.2.14: not declared, and answered as an undeclared operation."""

import json

import pytest

from kcs_adapter_keripy import kel, protocol

pytestmark = pytest.mark.onex


def test_keripy_1x_does_not_declare_or_perform_keri_process():
    hello = json.loads(protocol.handle_line(b'{"id":0,"op":"hello","protocol":1}'))["result"]
    assert "keri.process" not in hello["operations"]
    # Only the KEL features its 1.x acdc.verify relies on (acdc1x.py), not keri.process's.
    assert set(kel.FEATURES) & set(hello["features"]) == {"crypto.ed25519", "kel.basic"}
    request = {"id": 5, "op": "keri.process", "perspective": {"role": "validator"},
               "messages": []}
    response = json.loads(protocol.handle_line(json.dumps(request).encode()))
    assert response["error"]["kind"] == "unsupported"
