"""Grading a keripy 1.x issuance by verifying it (registry kind ptel-1x): every KEL, vcp/iss
registry and 1.x ACDC the issuer returned is checked for what it must be, in keripy 1.x's forms,
and each thing that can be wrong is reported."""

import json
import pathlib

import issued1x_world as w
import pytest

from keri_conformance import issued as iss
from keri_conformance import issued1x as one
from keri_conformance.issued import Unread

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


@pytest.mark.parametrize("name", ["keripy1x-issuance.json", "signify-keria-issuance.json"])
def test_what_real_1x_issuers_issue_verifies(name):
    fixture = json.loads((FIXTURES / name).read_text())
    assert iss.grade(fixture["request"], fixture["result"]) == []


def test_a_valid_1x_issuance_verifies_targeted_or_not():
    for issuee in (True, False):
        assert iss.grade(*w.issuance(issuee=issuee)) == []


def test_a_request_cannot_mix_1x_and_2x_registries():
    request, result = w.issuance()
    request["credentials"].append({**request["credentials"][0], "name": "d", "registry": "bup"})
    assert iss.grade(request, result) == [
        "the request mixes ptel-1x registries with KERI 2.0 ones, which no one issuance can hold"]


def test_an_issuer_that_adds_a_dt_it_was_not_asked_for_fails():
    """Incompatibility 8: keripy 1.x's issuer adds a.dt whether asked or not."""
    request, result = w.issuance()
    request["credentials"][0]["attributes"] = {"name": "Zoe"}
    assert iss.grade(request, result) == ["c: the ACDC's attributes are not exactly those asked for"]


@pytest.mark.parametrize("change, problem", [
    ({"a_over": {"name": "Ann"}}, "an attribute's value is not the one asked for"),
    ({"a_over": {"u": "short"}}, "the attribute section's salt is not a 128-bit salt"),
    ({"acdc_over": {"u": "short"}}, "the ACDC's top-level salt is not a 128-bit salt"),
    ({"acdc_over": {"i": "E" + "X" * 43}}, "the ACDC's issuer is not the identifier asked for"),
    ({"acdc_over": {"s": "E" + "X" * 43}}, "the ACDC's schema is not the one asked for"),
    ({"acdc_over": {"ri": "E" + "X" * 43}}, "the ACDC does not name its registry in ri"),
    ({"acdc_over": {"e": {"d": "E"}}}, "the ACDC has edges, and none was asked for"),
    ({"acdc_over": {"t": "acm"}}, "the ACDC's fields are not keripy 1.x's in its order"),
    ({"vcp_over": {"n": "short"}}, ("the registry inception's nonce is not a 128-bit salt or a "
                                    "256-bit seed")),
    ({"vcp_over": {"ii": "E" + "X" * 43}}, ("the registry inception is not the issuer's at "
                                            "sequence number 0")),
    ({"vcp_over": {"bt": "1"}}, "the registry has backers, which the runner does not verify"),
    ({"iss_over": {"dt": "yesterday"}}, "the issuance's stamp is not of the form it must be"),
    ({"iss_over": {"s": "1"}}, ("the issuance is not the credential's, at sequence number 0 of "
                                "its registry")),
])
def test_each_wrong_part_of_a_1x_issuance_is_named(change, problem):
    problems = iss.grade(*w.issuance(**change))
    assert f"c: {problem}" in problems


def test_a_signify_seed_is_a_registry_nonce():
    assert iss.grade(*w.issuance(vcp_over={"n": w.salt("seed", "A")[:44]})) == []


def test_the_issuee_must_be_the_one_asked_for_and_absent_when_none_was():
    request, result = w.issuance(issuee=False, a_over={"i": "E" + "X" * 43})
    assert "c: the ACDC's issuee is not the identifier asked for" in iss.grade(request, result)


def test_a_registry_event_must_be_anchored_by_keripys_event_seal():
    problems = iss.grade(*w.issuance(seal=lambda i, s, d: {"s": s, "d": d}))
    assert "c: the registry inception is anchored by a seal other than keripy's event seal " \
           "{i, s, d}" in problems
    assert "c: the issuance is anchored by a seal other than keripy's event seal {i, s, d}" \
           in problems
    problems = iss.grade(*w.issuance(seal=lambda i, s, d: {"i": i, "s": s, "d": "E" + "Y" * 43}))
    assert "c: the registry inception is not anchored on the issuer's verified KEL" in problems


def test_the_registry_is_its_inception_and_the_issuance_only():
    request, result = w.issuance(extra=iss.serialize(w.iss_event("E" + "Z" * 43, "E", s="1")))
    assert iss.grade(request, result) == [
        "c: the registry is not its inception and the credential's issuance"]
    out = result["credentials"]["c"]
    registry = bytes.fromhex(out["registry"])
    _, raw, _ = one.frame(registry, b"KERI")
    out["registry"] = (raw + raw).hex()
    assert "c: the registry's second event is not keripy's issuance (iss)" in \
        iss.grade(request, result)
    out["registry"] = ""
    assert "c: no registry was issued" in iss.grade(request, result)
    out["registry"] = (raw + b"-GAB").hex()
    assert iss.grade(request, result)[-1].startswith("c: the registry cannot be read: bytes "
                                                     "follow")
    out["registry"] = registry[len(raw):].hex()
    assert "c: the registry does not begin with keripy's inception (vcp)" in \
        iss.grade(request, result)
    del out["registry"]
    assert "c: no registry was issued" in iss.grade(request, result)


def test_a_registry_event_whose_said_is_wrong_is_named():
    request, result = w.issuance()
    out = result["credentials"]["c"]
    text = bytes.fromhex(out["registry"]).decode()
    vcp, _, rest = one.frame(text.encode(), b"KERI")
    issuance, _, _ = one.frame(rest, b"KERI")
    out["registry"] = (iss.serialize(one.sized({**vcp, "c": []}, "KERI"))
                       + iss.serialize(one.sized({**issuance, "dt": w.STAMP.replace("01T", "02T")},
                                                 "KERI"))).hex()
    problems = iss.grade(request, result)
    assert "c: the registry inception's SAID does not verify" in problems
    assert "c: the issuance's SAID does not verify" in problems


def test_an_acdc_whose_saids_or_size_are_wrong_is_named():
    request, result = w.issuance()
    out = result["credentials"]["c"]
    body = json.loads(bytes.fromhex(out["acdc"]))
    out["acdc"] = iss.serialize(one.sized({**body, "a": {**body["a"], "name": "Zoe "}},
                                          "ACDC")).hex()
    problems = iss.grade(request, result)
    assert "c: the ACDC's attribute section is not a map whose SAID verifies" in problems
    assert "c: the ACDC's SAID does not verify" in problems
    out["acdc"] = (bytes.fromhex(out["acdc"]) + b"-IAB").hex()
    assert "c: bytes follow the ACDC's body" in iss.grade(request, result)
    raw = iss.serialize({**body, "v": one.version("ACDC", 9999)})
    out["acdc"] = (raw + b" " * 9999).hex()
    assert "c: the ACDC's version string does not size its body" in iss.grade(request, result)
    out["acdc"] = iss.serialize(one.sized({**body, "a": "E"}, "ACDC")).hex()
    assert "c: the ACDC's attribute section is not a map whose SAID verifies" in \
        iss.grade(request, result)


def test_a_sad_that_cannot_be_hashed_is_named(monkeypatch):
    request, result = w.issuance()

    def broken(*_args):
        raise TypeError("no")

    monkeypatch.setattr(one, "block_said", broken)
    assert "c: the ACDC's SAID cannot be computed" in iss.grade(request, result)


def test_an_edge_section_asked_of_a_1x_issuance_is_beyond_the_runner():
    request, result = w.issuance()
    request["credentials"][0]["edges"] = {"x": {"credential": "c"}}
    assert "c: an edge section asked of a 1.x issuance is beyond what the runner grades" in \
        iss.grade(request, result)


def test_a_1x_registry_returns_no_disclosure():
    request, result = w.issuance()
    result["credentials"]["c"]["disclosure"] = "E"
    assert iss.grade(request, result) == [
        "c: a disclosure was returned, and a 1.x registry has no blinded state"]


def test_what_is_missing_from_the_result_is_named():
    request, result = w.issuance()
    del result["kels"]["holder"]
    result["credentials"]["c"]["acdc"] = "00"
    request["schemas"] = ["zz", iss.serialize({"$id": "E"}).hex()]
    assert iss.grade(request, result) == [
        "no KEL was returned for holder",
        f"c: no schema in the request verifies as {request['credentials'][0]['schema']}",
        "c: the ACDC cannot be read: a stream does not begin with a ACDC 1.x JSON body"]
    result["credentials"] = {}
    assert "c: no ACDC was returned" in iss.grade(request, result)


def test_the_acdc_and_registry_are_bounded_before_they_are_read():
    request, result = w.issuance()
    out = result["credentials"]["c"]
    out["acdc"] = "7b" * (iss.MAX_STREAM + 1)
    assert "c: the ACDC is longer than the runner reads" in iss.grade(request, result)
    big = bytes(iss.MAX_STREAM + 1)
    assert one.check_registry(big, "E", [], "E") == (
        None, ["the registry exceeds the runner's bounds"])


@pytest.mark.parametrize("stream, why", [
    (iss.GENUS + b'{"v":"KERI10JSON', "carries a genus/version code"),
    (b'{"v":"KERICAACAAJSON', "does not begin with a KERI 1.x JSON body"),
    (b'{"v":"KERI10JSON0000', "is not a 1.x JSON version string"),
    (b'{"v":"KERI10JSON00001x_"}', "is not a 1.x JSON version string"),
    (b'{"v":"KERI10JSON000019-"}', "is not a 1.x JSON version string"),
    (b'{"v":"KERI10JSON0000ff_"}', "declares 255 bytes, but only 25 follow"),
    (b'{"v":"KERI10JSON00001a_",}', "is not JSON"),
    (b'{"v":"KERI10JSON000063_","a":' + b"[" * 65 + b"]" * 65 + b"}",
     "nests deeper than 64 levels"),
])
def test_a_1x_stream_that_cannot_be_framed_is_unread(stream, why):
    with pytest.raises(Unread, match=why):
        one.frames(stream, b"KERI")


def test_a_stream_holds_a_bounded_number_of_messages():
    body = iss.serialize(one.sized({"v": "", "t": "ixn"}, "KERI"))
    assert len(one.frames(body * iss.MAX_EVENTS, b"KERI")) == iss.MAX_EVENTS
    with pytest.raises(Unread, match="more than 64 messages"):
        one.frames(body * (iss.MAX_EVENTS + 1), b"KERI")


SIG = "A" + "A" + "B" * 86
FIRST_SEEN = "0A" + "A" * 22 + "1AAG" + "2026-10-01T00c00c00d000000p00c00"


@pytest.mark.parametrize("text, count", [
    ("-AAB" + SIG, 1),
    ("-VAn-AAB" + SIG + "-EAB" + FIRST_SEEN, 1),
    ("-0VAAAAn-AAB" + SIG + "-EAB" + FIRST_SEEN, 1),
    ("", 0),
])
def test_1x_signatures_are_read_from_their_groups(text, count):
    assert len(one.signatures(text.encode())) == count


@pytest.mark.parametrize("text, why", [
    ("-VAB-AAB" + SIG, "does not measure what follows it"),
    ("-KAB" + SIG, "a '-K' group, which the runner does not read"),
    ("-AAC" + SIG, "cut short"),
    ("-AAB" + "0B" + "B" * 86, "not an Ed25519 indexed signature"),
    ("-AAB" + "AA" + "#" * 86, "not Base64"),
    ("-AAR" + SIG * 17, "more than 16 signatures"),
])
def test_1x_attachments_the_runner_cannot_read_are_unread(text, why):
    with pytest.raises(Unread, match=why):
        one.signatures(text.encode())


def test_a_kel_with_an_attachment_the_runner_cannot_read_stops_there():
    request, result = w.issuance()
    stream = bytes.fromhex(result["kels"]["holder"])
    result["kels"]["holder"] = (stream + b"-KAA").hex()
    assert "holder's KEL: event 0 cannot be verified: a 1.x event carries a '-K' group, which " \
           "the runner does not read" in iss.grade(request, result)


def test_a_seal_list_that_is_not_a_list_anchors_nothing():
    assert one.anchored([{"a": "x"}, {"a": ["x", {"d": "y"}]}], "i", "0", "d") == \
        "is not anchored on the issuer's verified KEL"
