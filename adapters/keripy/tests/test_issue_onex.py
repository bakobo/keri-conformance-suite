"""acdc.issue on keripy 1.2.14 (issue1x.py): a 1.x issuance made with keripy's own issuer
functions, on the sedi-1x-interop issuance cases (cases/sedi1x), and the requests it declines."""

import copy
import json
import pathlib

import pytest

from kcs_adapter_keripy import protocol

pytestmark = pytest.mark.onex

CASES = pathlib.Path(__file__).resolve().parents[3] / "cases" / "sedi1x"


def case(case_id):
    return json.loads((CASES / f"{case_id}.json").read_text())


def issue(request):
    return json.loads(protocol.handle_line(json.dumps(
        {"id": 1, "op": "acdc.issue", **request}).encode()))


def bodies(stream_hex):
    """Each 1.x body in a stream, with what follows it before the next."""
    raw, out = bytes.fromhex(stream_hex), []
    while raw:
        size = int(raw[16:22], 16)
        nxt = raw.find(b'{"v":"', size)
        nxt = len(raw) if nxt < 0 else nxt
        out.append((json.loads(raw[:size]), raw[size:nxt]))
        raw = raw[nxt:]
    return out


def test_keripy_issues_a_1x_credential_with_its_own_salts_and_the_dt_it_always_adds():
    request = case("ACDC-0283")["input"]
    result = issue(request)["result"]
    assert set(result) == {"kels", "credentials"} and set(result["kels"]) == {"I", "H"}
    [(acdc, rest)] = bodies(result["credentials"]["core"]["acdc"])
    assert rest == b"" and list(acdc) == ["v", "d", "u", "i", "ri", "s", "a"]
    asked = request["credentials"][0]["attributes"]
    assert acdc["a"]["dt"] == asked["dt"] and acdc["a"]["givenName"] == asked["givenName"]
    assert acdc["a"]["u"].startswith("0A") and acdc["a"]["i"] == bodies(
        result["kels"]["H"])[0][0]["i"]
    vcp, iss = (b for b, _ in bodies(result["credentials"]["core"]["registry"]))
    assert (vcp["t"], vcp["c"], vcp["ii"]) == ("vcp", ["NB"], acdc["i"])
    assert (iss["t"], iss["i"], iss["ri"]) == ("iss", acdc["d"], vcp["i"])
    # The issuer's KEL anchors the vcp and then the iss, each by keripy's event seal.
    kel = bodies(result["kels"]["I"])
    assert [e["a"] for e, _ in kel[1:]] == [[{"i": vcp["i"], "s": "0", "d": vcp["d"]}],
                                             [{"i": acdc["d"], "s": "0", "d": iss["d"]}]]
    assert all(atc.startswith(b"-VA") for _, atc in kel)


def test_keripy_refuses_its_own_credential_when_the_dt_it_adds_breaks_the_schema():
    response = issue(case("ACDC-0282")["input"])
    reason = response["result"]["refused"]["reason"]
    assert reason.startswith("keripy 1.2.14's issuer refuses it: credential schema validation "
                             "failed: ") and "'dt' was unexpected" in reason
    assert "\n" not in reason


def test_an_untargeted_credential_has_no_issuee():
    request = copy.deepcopy(case("ACDC-0283")["input"])
    del request["credentials"][0]["issuee"]
    request["credentials"][0]["schema"], request["schemas"] = _open_schema()
    [(acdc, _)] = bodies(issue(request)["result"]["credentials"]["core"]["acdc"])
    assert "i" not in acdc["a"]


def _open_schema():
    from keri.core import scheming
    sad = {"$id": "", "$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object"}
    schemer = scheming.Schemer(sed=sad)
    return schemer.said, [bytes(schemer.raw).hex()]


@pytest.mark.parametrize("change", [
    lambda r: r.update(roles=[]),
    lambda r: r.update(roles=["I", "I"]),
    lambda r: r.update(credentials=[]),
    lambda r: r["credentials"][0].update(issuer="X"),
    lambda r: r["credentials"][0].update(attributes=[]),
    lambda r: r.update(credentials=r["credentials"] * 2),
    lambda r: r["credentials"][0].update(schema="E" + "X" * 43),
    lambda r: r["credentials"][0]["attributes"].update(u="0AAA"),
])
def test_a_request_the_adapter_cannot_read_is_a_harness_error(change):
    request = copy.deepcopy(case("ACDC-0283")["input"])
    change(request)
    assert issue(request)["error"]["kind"] == "harness"


@pytest.mark.parametrize("change", [
    lambda c: c.update(registry="bup"),
    lambda c: c.update(edges={}),
])
def test_a_keri_2_registry_or_an_edge_section_is_unsupported(change):
    request = copy.deepcopy(case("ACDC-0283")["input"])
    change(request["credentials"][0])
    error = issue(request)["error"]
    assert error["kind"] == "unsupported"
    assert error["message"].startswith("e.feature.unsupported.issue-1x.f: ")
