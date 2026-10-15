"""acdc.verify through heti: the bundle reaches heti's public verifier in the forms its API takes,
and heti's answer or refusal becomes the protocol's verdict."""

import json
import pathlib
import urllib.request

import pytest

from kcs_adapter_heti import verify

BUNDLES = json.loads((pathlib.Path(__file__).parent / "fixtures" / "bundles.json").read_text())


def request(name, **over):
    return {"id": 1, "op": "acdc.verify", "perspective": {"role": "validator"},
            **BUNDLES[name], **over}


def test_an_issued_credential_is_valid_and_reports_its_head():
    result = verify.verify(request("issued"))
    assert result["verdict"] == "valid" and result["edges"] == []
    head = result["registry"]
    assert head["n"] == 1 and head["ts"] == "issued" and head["td"] and head["rd"]


def test_a_revoked_credential_is_invalid():
    result = verify.verify(request("revoked"))
    assert result["verdict"] == "invalid" and "revoked" in result["reason"]
    assert result["registry"] is None


def test_heti_walks_a_chain_it_is_handed():
    assert verify.verify(request("chain"))["verdict"] == "valid"


def test_a_directly_sealed_credential_with_attachments_is_valid():
    result = verify.verify(request("direct"))
    assert result["verdict"] == "valid" and result["registry"] is None


def test_a_missing_far_node_is_incomplete():
    assert verify.verify(request("chain", acdcs=[]))["verdict"] == "incomplete"


def test_a_missing_kel_is_incomplete_and_a_refused_one_is_skipped():
    result = verify.verify(request("issued", kels=[]))
    assert result["verdict"] == "incomplete"
    # A KEL whose first event is cut short frames nothing, so heti is never asked for it.
    broken = [{"stream": k["stream"][:40]} for k in BUNDLES["issued"]["kels"]]
    assert verify.verify(request("issued", kels=broken))["verdict"] == "incomplete"


def test_schemas_heti_refuses_are_left_out(capsys):
    result = verify.verify(request("issued", schemas=["7b7d"]))
    assert result["verdict"] in ("invalid", "incomplete")
    assert "heti refused a schema" in capsys.readouterr().err


def test_a_kel_heti_refuses_is_left_out(monkeypatch, capsys):
    async def refuse(self, **kwargs):
        raise RuntimeError("no")

    monkeypatch.setattr(verify.Lockbox, "add_other", refuse)
    assert verify.verify(request("issued"))["verdict"] == "incomplete"
    assert "heti refused the KEL" in capsys.readouterr().err


def test_unparseable_presented_bytes_are_invalid():
    result = verify.verify(request("issued", presented={"stream": "2d5f414141434141"}))
    assert result["verdict"] == "invalid"


def test_an_uncoded_failure_inside_heti_is_an_adapter_error(monkeypatch):
    async def explode(self, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(verify.Lockbox, "verify_acdc", explode)
    with pytest.raises(RuntimeError, match="boom"):
        verify.verify(request("issued"))


@pytest.mark.parametrize("field,value", [
    ("kels", 7), ("kels", [7]), ("kels", [{"stream": "XY"}]), ("registry", [{"stream": 1}]),
    ("schemas", [1]), ("schemas", "7b"), ("presented", "00"), ("presented", {"stream": "Z"}),
])
def test_a_malformed_request_is_refused(field, value):
    with pytest.raises(verify.Malformed):
        verify.verify(request("issued", **{field: value}))


class Coded(Exception):
    def __init__(self, code, retryable=False):
        super().__init__(code)
        self.code, self.retryable = code, retryable


@pytest.mark.parametrize("error,grade", [
    (Coded("e.proof.said.f"), "invalid"),
    (Coded("e.state.conflict.acdc.revoked.f"), "invalid"),
    (Coded("e.net.unanswered.r", retryable=True), "incomplete"),
    (Coded("e.input.missing.evidence.farnode.f"), "incomplete"),
    (Coded("e.feature.unsupported.acdc.edges.operator.f"), "incomplete"),
    (Coded(None), "invalid"),
])
def test_codes_grade_to_verdicts(error, grade):
    assert verify.grade(error) == grade


def test_split_frames_only_a_json_body_its_version_string_sizes():
    stream = bytes.fromhex(BUNDLES["direct"]["presented"]["stream"])
    sad, raw, rest = verify.split(stream)
    assert sad["d"] and raw.endswith(b"}") and rest.startswith(b"-C")
    assert verify.split(stream[8:])[0] == sad  # the genus/version code is optional
    assert verify.split(b"nothing") is None
    assert verify.split(stream.replace(b"JSON", b"CBOR", 1)) is None
    assert verify.split(stream.replace(b'"t":', b'"t"!', 1)) is None
    as_list = b'{"v":"ACDCCAACAAJSONAAAA.",' + b"]"
    assert verify.split(as_list) is None


def test_registry_events_that_do_not_frame_or_name_no_registry_are_left_out():
    rip = bytes.fromhex(BUNDLES["issued"]["registry"][0]["stream"])
    nameless = rip.replace(b'"t":"rip"', b'"t":"xyz"', 1)
    assert verify.registries([b"junk", nameless]) == {}
    assert verify.evidence(b"junk", {}) == (b"junk", None)


@pytest.mark.parametrize("attachments,expected", [
    (b"-CAB-aAB" + b"ABCD", "ABCD"),
    (b"--CAAAAB-aAB" + b"ABCD", "ABCD"),
    (b"-CAC-SAB" + b"-aXY" + b"-aABWXYZ", "WXYZ"),  # "-aXY" inside -S is text, not a group
    (b"-CAB--aAAAAB" + b"ABCD", "ABCD"),
    (b"-CAB-SAA", None),
    (b"-CAB!!!!", None),
    (b"-CAB-a!!", None),
    (b"", None),
])
def test_disclosures_are_read_by_group_count(attachments, expected):
    assert verify._blinder(attachments) == expected


def test_the_kel_server_answers_only_for_prefixes_it_holds():
    server = verify._server({"Eabc": b"kel"})
    port = server.server_address[1]
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/oobi/Eabc") as answer:
            assert answer.read() == b"kel"
        for path in ("/oobi/Eother", "/elsewhere"):
            with pytest.raises(urllib.error.HTTPError):
                urllib.request.urlopen(f"http://127.0.0.1:{port}{path}")
    finally:
        server.shutdown()
        server.server_close()


def test_a_presented_acdc_with_trailing_bytes_goes_to_heti_as_it_came():
    stream = bytes.fromhex(BUNDLES["direct"]["presented"]["stream"])
    assert verify.evidence(stream + b"HOSTILE", {}) == (stream + b"HOSTILE", None)
    result = verify.verify(request("direct", presented={"stream": (stream + b"HOSTILE").hex()}))
    assert result["verdict"] == "invalid"


@pytest.mark.parametrize("attachments,expected", [
    (b"", True), (b"-CAB-SAA", True), (b"--CAAAAB-SAA", True), (b"-CAB-SAAjunk", False),
    (b"--CAAAAB", False), (b"-C!!", False), (b"junk", False),
])
def test_well_formed_attachments(attachments, expected):
    assert verify.well_formed(attachments) == expected


def test_a_disclosure_that_is_not_text_is_left_out():
    assert verify._blinder(b"-CAB-aAB\xff\xff\xff\xff") is None


def test_walked_edges_report_only_what_heti_walked():
    stream = bytes.fromhex(BUNDLES["chain"]["presented"]["stream"])
    near = verify.split(stream)[0]
    far = next(p for _, p in verify.edge_blocks(near["e"]))["n"]
    assert verify.walked_edges([stream, b"junk"], (far,)) == [
        {"near": near["d"], "path": "e.le", "n": far, "valid": True}]
    assert verify.walked_edges([stream], None) == []
    assert verify.walked_edges([stream], ("Eother",)) == []
    assert verify.edge_blocks("Ecompact") == []
