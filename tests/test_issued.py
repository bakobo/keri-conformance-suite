"""Grading an issuance by verifying it (this.i 2u2ps8mt): every KEL, registry and ACDC the issuer
returned is checked for what it must be, and each thing that can be wrong is reported."""

import copy
import json
import pathlib

import issued_world as w
import pytest

from keri_conformance import issued as iss

HETI = json.loads((pathlib.Path(__file__).parent / "fixtures" / "heti-issuance.json").read_text())


def test_a_real_issuers_issuance_verifies():
    assert iss.grade(HETI["request"], HETI["result"]) == []


def test_a_valid_issuance_verifies_targeted_or_not():
    for issuee in (True, False):
        request, result, _ = w.issuance(issuee=issuee)
        assert iss.grade(request, result) == []


# -- primitives -------------------------------------------------------------------------------

def test_primitives():
    assert iss.b64_int("BA") == 64 and iss.int_b64(64, 2) == "BA"
    with pytest.raises(iss.Unread):
        iss.b64_int("!!")
    key = w.verkey("x")
    assert iss.qb64("D", iss.raw_of(key, "D", 32)) == key
    for bad in (key[:-1], "E" + key[1:], key[:-1] + "!", 7):
        with pytest.raises(iss.Unread):
            iss.raw_of(bad, "D", 32)
    with pytest.raises(iss.Unread):
        iss._state("way-too-long-a-state")
    assert iss._state("") == iss.EMPTY


@pytest.mark.parametrize("stream,words", [
    (b"nothing", "does not begin"),
    (b'{"v":"KERI.."}', "not a 2.00"),
    (b'{"v":"KERICAACAAJSONAAzz.","t":"icp"}', "only"),
    (b'{"v":"KERICAACAAJSONAAAZ.",}', "not JSON"),
])
def test_frames_that_do_not_read(stream, words):
    with pytest.raises(iss.Unread, match=words):
        iss.frame(stream, b"KERI")


def test_groups_are_read_by_count():
    sig = w.sig_group(b"x", [(0, "a")])
    assert [c for c, _ in iss.groups(w.outer(sig).encode())] == ["-K"]
    big = "--K" + iss.int_b64(len(sig[4:]) // 4, 5) + sig[4:]
    assert [c for c, _ in iss.groups(("--C" + iss.int_b64(len(big) // 4, 5) + big).encode())] \
        == ["--K"]
    assert iss.groups(b"") == [] and iss.groups(b"-KAA") == []
    with pytest.raises(iss.Unread, match="not a group"):
        iss.groups(b"-CABxxxx")
    with pytest.raises(iss.Unread, match="cut short"):
        iss.groups(b"-CAB-KAB")


def test_signatures_are_ed25519_indexed_signatures():
    sig = w.sig_group(b"x", [(0, "a")])
    assert len(iss.signatures(w.outer("-SAA", sig).encode())) == 1
    with pytest.raises(iss.Unread, match="code A or B"):
        iss.signatures(w.outer("-KAW" + "C" * 88).encode())
    many = w.sig_group(b"x", [(i, "a") for i in range(iss.MAX_SIGNATURES + 1)])
    with pytest.raises(iss.Unread, match="more than"):
        iss.signatures(w.outer(many).encode())


def test_a_stream_of_too_many_messages_is_refused(monkeypatch):
    kel = w.Kel("i")
    kel.ixn([])
    monkeypatch.setattr(iss, "MAX_EVENTS", 1)
    with pytest.raises(iss.Unread, match="more than 1"):
        iss.frames(kel.stream(), b"KERI")


# -- KELs -------------------------------------------------------------------------------------

def failed(kel_stream) -> list[str]:
    return iss.verify_kel(kel_stream)[2]


def test_a_kel_with_a_rotation_verifies():
    kel = w.Kel("i")
    kel.ixn([])
    kel.rot()
    kel.ixn([])
    prefix, trunk, problems = iss.verify_kel(kel.stream())
    assert problems == [] and prefix == kel.prefix and len(trunk) == 4


def tampered(kel: w.Kel, n: int, **fields) -> bytes:
    body, attachments = kel.events[n]
    kel.events[n] = ({**body, **fields}, attachments)
    return kel.stream()


@pytest.mark.parametrize("change,words", [
    (lambda k: tampered(k, 1, t="drt"), "does not verify"),
    (lambda k: tampered(k, 1, s="5"), "sequence number"),
    (lambda k: tampered(k, 1, d="E" + "A" * 43), "SAID does not verify"),
    (lambda k: k.stream()[8:].replace(b'"t":"icp"', b'"t":"ixn"', 1), "only inception"),
    (lambda k: b"", "empty"),
    (lambda k: b"junk", "cannot be read"),
])
def test_kel_events_that_do_not_verify(change, words):
    kel = w.Kel("i")
    kel.ixn([])
    assert any(words in p for p in failed(change(kel)))


def test_kel_structure():
    kel = w.Kel("i")
    body = {**kel.events[0][0], "s": "1"}
    kel.events.append((body, kel.events[0][1]))  # a second inception
    assert "begins with its only inception" in failed(kel.stream())[0]
    kel = w.Kel("i")
    body = {**kel.events[0][0], "i": "E" + "A" * 43}
    body = w.iss.sized({**body, "d": w.iss.said(body, "KERI", ("d", "i"))}, "KERI")
    kel.events[0] = (body, w.outer(w.sig_group(w.iss.serialize(body), [(0, "i/k0")])))
    assert "prefix is not its SAID" in failed(kel.stream())[0]
    kel = w.Kel("i")
    kel.ixn([], p="E" + "A" * 43)
    assert "does not follow" in failed(kel.stream())[0]


def icp_with(**fields):
    kel = w.Kel("i")
    body = w.saidify({**kel.events[0][0], **fields, "d": "", "i": ""}, "KERI", ("d", "i"))
    kel.events[0] = (body, w.outer(w.sig_group(w.iss.serialize(body), [(0, "i/k0")])))
    return kel.stream()


@pytest.mark.parametrize("fields,words", [
    ({"bt": "1"}, "witnesses"),
    ({"k": []}, "no signing keys"),
    ({"n": ["E" + "A" * 43] * (iss.MAX_KEYS + 1)}, "more than"),
    ({"kt": ["1/2", "1/2"]}, "weighted"),
    ({"kt": "zz"}, "not lowercase hex"),
    ({"kt": "2"}, "threshold"),
])
def test_establishment_events_the_runner_does_not_verify(fields, words):
    assert words in failed(icp_with(**fields))[0]


def test_a_rotation_to_uncommitted_keys_fails():
    kel = w.Kel("i")
    kel.next = ["other"]
    kel.rot()
    assert "prior next-key commitment" in failed(kel.stream())[0]


def test_an_unsigned_or_wrongly_signed_event_fails():
    kel = w.Kel("i")
    body = {"v": "", "t": "ixn", "d": "", "i": kel.prefix, "s": "1", "p": kel.events[0][0]["d"],
            "a": []}
    kel.add(w.saidify(body, "KERI"), signers=[(0, "i/stranger"), (5, "i/k0")])
    assert "not signed to its threshold" in failed(kel.stream())[0]


def test_a_kel_beyond_the_bound_is_refused(monkeypatch):
    monkeypatch.setattr(iss, "MAX_STREAM", 10)
    assert "longer than" in failed(w.Kel("i").stream())[0]


def test_an_event_with_an_unreadable_signature_is_reported():
    kel = w.Kel("i")
    kel.events[0] = (kel.events[0][0], w.outer("-KAW" + "C" * 88))
    assert "cannot be verified" in failed(kel.stream())[0]


# -- seals and registries ---------------------------------------------------------------------

def test_seal_shapes():
    rd, d = "Erd", "Ed"
    trunk = [{"a": ["junk", {"s": "1", "d": "Eother"}]}]
    assert "not anchored" in iss.sealed(trunk, rd, "1", d)
    for seal in ({"d": d}, {"i": "Eissuer", "s": "1", "d": d}, {"s": "1", "d": d, "x": "1"},
                 {"s": "2", "d": d}):
        assert "shape" in iss.sealed([{"a": [seal]}], rd, "1", d), seal
    for seal in ({"s": "1", "d": d}, {"i": rd, "s": "1", "d": d}):
        assert iss.sealed([{"a": [seal]}], rd, "1", d) is None


def registry_problems(change) -> list[str]:
    request, result, parts = w.issuance()
    change(result["credentials"]["c"], parts)
    return iss.grade(request, result)


def test_disclosure_forms():
    td = "E" + "A" * 43
    for code in ("0A", "a"):
        text = w.block(td, u_code=code)
        assert iss.disclosed(text)[2:] == (td, "issued")
    assert iss.disclosed(w.block("", ts=""))[2:] == ("", "")
    for bad in ("E" * 44 + "Zzz", w.block(td)[:-2]):
        with pytest.raises(iss.Unread):
            iss.disclosed(bad)


@pytest.mark.parametrize("change,words", [
    (lambda c, p: c.update(disclosure="-aAB" + c["disclosure"]), None),
    (lambda c, p: c.update(disclosure="--aAAAAB" + c["disclosure"]), None),
    (lambda c, p: c.update(disclosure=None), "no disclosure"),
    (lambda c, p: c.update(disclosure="E" * 44 + "zz"), "cannot be read"),
    (lambda c, p: c.update(disclosure=w.block(p["acdc"]["d"], ts="revoked")), "BLID"),
    (lambda c, p: c.update(registry=w.chain(p["rip"], p["bup"])[:-20]), "cannot be read"),
    (lambda c, p: c.update(registry=w.chain(p["rip"])), "no update"),
    (lambda c, p: c.update(registry=""), "no registry"),
    (lambda c, p: c.update(registry=w.chain(p["bup"])), "does not begin with"),
    (lambda c, p: c.update(registry=w.chain({**p["rip"], "dt": "2027" + p["rip"]["dt"][4:]},
                                            p["bup"])),
     "inception's SAID"),
    (lambda c, p: c.update(registry=w.chain(p["rip"], {**p["bup"],
                                                       "dt": "2027" + p["bup"]["dt"][4:]})),
     "event 1's SAID"),
    (lambda c, p: c.update(registry=w.chain(p["rip"], p["rip"])), "not a blindable update"),
])
def test_registry_failures(change, words):
    problems = registry_problems(change)
    assert (problems == []) if words is None else any(words in x for x in problems), problems


def test_registry_chain_and_anchoring():
    request, result, parts = w.issuance()
    rip = w.rip("E" + "A" * 43)
    rest = w.bup(rip["d"], 2, "E" + "B" * 43, parts["bup"]["b"])
    result["credentials"]["c"]["registry"] = w.chain(rip, rest)
    problems = iss.grade(request, result)
    for words in ("not the issuer's", "inception is not anchored", "does not follow",
                  "event 1 is not anchored", "rd"):
        assert any(words in p for p in problems), (words, problems)


def test_a_head_that_records_another_credential_fails():
    request, result, parts = w.issuance()
    other = w.block("E" + "C" * 43)
    update = w.bup(parts["rip"]["d"], 1, parts["rip"]["d"], other[:44])
    parts["issuer"].events.pop()
    parts["issuer"].ixn([{"s": "1", "d": update["d"]}])
    result["kels"]["issuer"] = parts["issuer"].stream().hex()
    result["credentials"]["c"].update(registry=w.chain(parts["rip"], update), disclosure=other)
    assert any("does not record the credential" in p for p in iss.grade(request, result))


def test_a_registry_or_acdc_beyond_the_bound_is_refused(monkeypatch):
    request, result, _ = w.issuance()
    result["kels"] = {}
    acdc = len(result["credentials"]["c"]["acdc"]) // 2
    assert len(result["credentials"]["c"]["registry"]) // 2 > acdc + 1
    monkeypatch.setattr(iss, "MAX_STREAM", acdc + 1)
    assert any("registry exceeds" in p for p in iss.grade(request, result))
    monkeypatch.setattr(iss, "MAX_STREAM", acdc - 1)
    assert any("ACDC is longer" in p for p in iss.grade(request, result))


# -- ACDCs ------------------------------------------------------------------------------------

def acdc_problems(change, **kwargs) -> list[str]:
    request, result, parts = w.issuance(**kwargs)
    change(request["credentials"][0], result["credentials"]["c"], parts)
    return iss.grade(request, result)


def rebuilt(parts, **fields):
    body = {k: v for k, v in parts["acdc"].items() if k != "d"}
    body.update(fields)
    body = {k: v for k, v in body.items() if v is not None}
    return (iss.GENUS + iss.serialize(iss.sized({**body, "d": iss.acdc_said({**body, "d": ""})},
                                                 "ACDC"))).hex()


@pytest.mark.parametrize("change,words", [
    (lambda r, c, p: c.update(acdc="00"), "cannot be read"),
    (lambda r, c, p: c.update(acdc=c["acdc"] + "2d"), "bytes follow"),
    (lambda r, c, p: c.update(acdc=rebuilt(p, x="1")), "line 32"),
    (lambda r, c, p: c.update(acdc=c["acdc"].replace("226163", "226164", 1)), "SAID"),
    (lambda r, c, p: c.update(acdc=rebuilt(p, i="E" + "A" * 43)), "issuer"),
    (lambda r, c, p: c.update(acdc=rebuilt(p, s="E" + "A" * 43)), "schema"),
    (lambda r, c, p: c.update(acdc=rebuilt(p, a="E" + "A" * 43)), "expanded map"),
    (lambda r, c, p: c.update(acdc=rebuilt(p, a={**p["acdc"]["a"], "dt": "x"})),
     "exactly those"),
    (lambda r, c, p: c.update(acdc=rebuilt(p, a={**p["acdc"]["a"], "name": "Bob"})),
     "value"),
    (lambda r, c, p: c.update(acdc=rebuilt(p, a={**p["acdc"]["a"], "i": "E" + "A" * 43})),
     "issuee"),
    (lambda r, c, p: c.update(acdc=rebuilt(p, a={**p["acdc"]["a"], "u": "x"})), "salt"),
    (lambda r, c, p: c.update(acdc=rebuilt(p, e={"d": "x"})), "none was asked"),
    (lambda r, c, p: c.update(acdc=rebuilt(p, rd="E" + "A" * 43)), "rd"),
    (lambda r, c, p: c.pop("acdc"), "no ACDC"),
])
def test_acdc_failures(change, words):
    problems = acdc_problems(change)
    assert any(words in p for p in problems), problems


def test_an_untargeted_credential_must_name_no_issuee():
    problems = acdc_problems(lambda r, c, p: c.update(
        acdc=rebuilt(p, a={**p["acdc"]["a"], "i": "E" + "A" * 43})), issuee=False)
    assert any("issuee" in x for x in problems)


def test_a_version_string_that_does_not_size_its_body():
    request, result, _parts = w.issuance()
    raw = bytes.fromhex(result["credentials"]["c"]["acdc"])
    spaced = raw.replace(b',"t"', b', "t"', 1)
    size = len(spaced) - len(iss.GENUS)
    spaced = spaced.replace(raw[8 + 20:8 + 24], iss.int_b64(size, 4).encode(), 1)
    result["credentials"]["c"]["acdc"] = spaced.hex()
    assert any("does not size" in p for p in iss.grade(request, result))


def test_an_acdc_said_that_cannot_be_computed():
    request, result, parts = w.issuance()
    body = iss.sized({**parts["acdc"], "A": ["x", 7]}, "ACDC")
    result["credentials"]["c"]["acdc"] = (iss.GENUS + iss.serialize(body)).hex()
    assert any("cannot be computed" in p for p in iss.grade(request, result))


def test_acdc_compaction_covers_schemas_aggregates_and_nested_blocks():
    nested = {"d": "", "inner": {"d": "", "x": 1}, "list": [1]}
    body = {"v": "", "d": "", "s": {"$id": "", "type": "object"},
            "A": ["agid", {"d": "", "x": 1}, "Ecompact"], "a": nested}
    assert iss.acdc_said(body).startswith("E")
    said, raw = w.schema()
    assert iss.schema_said(bytes.fromhex(raw)) == said
    assert iss.schema_said(iss.serialize({"$id": "x", "type": "object"})) == ""
    assert iss.schema_said(b"[1]") == "" and iss.schema_said(b'{"type": "object"}') == ""


# -- edges ------------------------------------------------------------------------------------

FAR = "far"  # in an issued edge section, stands for the far credential's SAID


def edged(edges, far_edges=None, near_issuer="holder", far_issuee=True):
    """A request for C, issued by the issuer to the holder, then N, whose edges are as asked,
    and the result an issuer would return."""
    request, result, parts = w.issuance(issuee=far_issuee)
    kels = {"issuer": parts["issuer"], "holder": parts["holder"]}
    signer = kels[near_issuer]
    far = parts["acdc"]
    if far_edges is not None:
        far_edges = json.loads(json.dumps(far_edges).replace(f'"{FAR}"', json.dumps(far["d"])))
    e = {"d": "", **(far_edges if far_edges is not None else {
        "le": {"d": "", "n": far["d"], "o": "I2I"}})}
    e = _saided(e)
    r = w.rip(signer.prefix, u=w.salt("rip2"))
    a = {"d": "", "i": parts["holder"].prefix, "name": "N"}
    a["d"] = iss.block_said(a)
    near = w.acdc(signer.prefix, parts["schema"], r["d"], a, e)
    disclosure = w.block(near["d"])
    update = w.bup(r["d"], 1, r["d"], disclosure[:44])
    signer.ixn([{"s": "0", "d": r["d"]}])
    signer.ixn([{"s": "1", "d": update["d"]}])
    result["kels"][near_issuer] = signer.stream().hex()
    request["credentials"].insert(0, {"name": "n", "issuer": near_issuer, "issuee": "holder",
                                      "schema": parts["schema"], "attributes": {"name": "N"},
                                      "registry": "bup", "edges": edges})
    result["credentials"]["n"] = {"acdc": (iss.GENUS + iss.serialize(near)).hex(),
                                  "registry": w.chain(r, update), "disclosure": disclosure}
    return iss.grade(request, result)


def _saided(block):
    """Every map with a d in it given its own SAID, innermost first."""
    if not isinstance(block, dict):
        return block
    out = {k: _saided(v) for k, v in block.items()}
    if out.get("d") == "":
        out["d"] = iss.block_said(out)
    return out


def test_edges_as_asked_verify():
    assert edged({"le": {"credential": "c", "o": "I2I"}}) == []
    assert edged({"le": {"credential": "c", "o": ["I2I"]}}) == []
    assert edged({"le": {"credential": "c"}}, {"le": {"d": "", "n": ""}}) != []
    # The default operator: I2I to a targeted credential, NI2I to an untargeted one.
    assert edged({"le": {"credential": "c"}}, {"le": {"d": "", "n": FAR}}) == []
    assert edged({"le": {"credential": "c"}}, {"le": {"d": "", "n": FAR, "o": "I2I"}}) == []
    assert edged({"le": {"credential": "c", "o": "NI2I"}},
                 {"le": {"d": "", "n": FAR, "o": "NI2I"}}, near_issuer="issuer") == []
    assert edged({"le": {"credential": "c", "o": "E1E"}},
                 {"le": {"d": "", "n": FAR, "o": "E1E"}}, near_issuer="issuer") == []
    assert edged({"o": "OR", "g": {"le": {"credential": "c"}}},
                 {"o": "OR", "g": {"d": "", "le": {"d": "", "n": FAR}}}) == []


@pytest.mark.parametrize("asked,issued,words,kwargs", [
    ({"le": {"credential": "c", "o": "NI2I"}}, None, "operators are not", {}),
    ({"le": {"credential": "c"}}, {"le": {"d": "", "n": FAR, "o": "NI2I"}}, "operators are not",
     {}),
    ({"le": {"credential": "nope"}}, None, "does not name", {}),
    ({"other": {"credential": "c"}}, None, "labels", {}),
    ({"o": "OR", "le": {"credential": "c"}}, None, "operator is not", {}),
    ({"le": {"credential": "c"}}, {"le": "Ecompact"}, "not a map", {}),
    ({"g": {"le": {"credential": "c"}}}, {"g": {"d": "", "le": {"d": "", "n": "Ewrong"}}},
     "does not name", {}),
    ({"le": {"credential": "c"}}, {"le": {"n": FAR}}, "no SAID of its own", {}),
    ({"le": {"credential": "c", "o": "I2I"}}, None, "do not hold", {"near_issuer": "issuer"}),
    ({"le": {"credential": "c", "o": "DI2I"}}, {"le": {"d": "", "n": FAR, "o": "DI2I"}},
     "do not hold", {"near_issuer": "issuer"}),
    ({"le": {"credential": "c", "o": "E1E"}}, {"le": {"d": "", "n": FAR, "o": "E1E"}},
     "do not hold", {"far_issuee": False}),
    ({"le": {"credential": "c", "o": "I2I"}}, {"le": {"d": "", "n": FAR, "o": "I2I"}},
     "do not hold", {"far_issuee": False}),
])
def test_edges_not_as_asked_fail(asked, issued, words, kwargs):
    assert any(words in p for p in edged(asked, issued, **kwargs))


def test_an_edge_section_that_is_not_a_map():
    assert iss._edges({"le": {}}, "Ecompact", {}, {}) == ["the edge section is not a map"]


def test_credentials_are_checked_far_first_whatever_the_order():
    order = iss._ordered([{"name": "n", "edges": {"g": {"le": {"credential": "f"}}, "o": "OR"}},
                          {"name": "f"}, {"name": "x", "edges": {"le": {"credential": "x"}}},
                          {"name": "y", "edges": {"le": {"credential": "missing"}}}])
    assert [c["name"] for c in order] == ["f", "n", "x", "y"]


# -- the whole result -------------------------------------------------------------------------

def test_missing_and_broken_kels_are_reported():
    request, result, _ = w.issuance()
    result["kels"] = {"issuer": "00"}
    problems = iss.grade(request, result)
    assert any("no KEL was returned for holder" in p for p in problems)
    assert any("issuer's KEL" in p for p in problems)
    request["schemas"].append("7b")
    assert iss.grade(request, copy.deepcopy(result))


def test_an_acdc_must_be_genus_pinned_and_of_type_acm():
    problems = acdc_problems(lambda r, c, p: c.update(acdc=c["acdc"][16:]))
    assert any("genus/version code" in x for x in problems)
    problems = acdc_problems(lambda r, c, p: c.update(acdc=rebuilt(p, t="zzz")))
    assert any("type is not acm" in x for x in problems)


def test_a_nested_block_whose_said_is_false_fails():
    def change(r, c, p):
        c.update(acdc=rebuilt(p, a={**p["acdc"]["a"], "d": "E" + "A" * 43}))
    assert any("does not verify against its own SAID" in x for x in acdc_problems(change))

    def in_a_list(r, c, p):
        c.update(acdc=rebuilt(p, r=[{"d": "E" + "A" * 43, "x": 1}]))
    assert any("does not verify against its own SAID" in x for x in acdc_problems(in_a_list))


def test_an_issuance_whose_schema_the_request_does_not_carry_fails():
    request, result, _ = w.issuance()
    request["schemas"] = ["7b7d", "zz"]
    assert any("no schema in the request" in p for p in iss.grade(request, result))


def test_an_identifier_that_cannot_rotate_is_not_transferable():
    assert "not transferable" in failed(w.Kel("i", nxt=()).stream())[0]


def test_a_signature_index_that_is_not_base64_is_unreadable():
    sig = w.sig_group(b"x", [(0, "a")])
    with pytest.raises(iss.Unread, match="not Base64"):
        iss.signatures(w.outer(sig[:5] + "!" + sig[6:]).encode())


@pytest.mark.parametrize("asked,issued,kwargs,words", [
    ({"le": {"credential": "c"}}, {"le": {"d": "", "n": FAR, "o": []}}, {}, None),
    ({"le": {"credential": "c"}}, {"le": {"d": "", "n": FAR, "o": []}},
     {"near_issuer": "issuer"}, "do not hold"),
    ({"le": {"credential": "c", "o": ["I2I", "XYZ"]}},
     {"le": {"d": "", "n": FAR, "o": ["I2I", "XYZ"]}}, {}, "operator outside"),
    ({"le": {"credential": "c", "o": "I2I"}}, {"le": {"d": "", "n": FAR}}, {},
     "not the ones asked"),
])
def test_empty_unknown_and_omitted_operators(asked, issued, kwargs, words):
    problems = edged(asked, issued, **kwargs)
    assert (problems == []) if words is None else any(words in p for p in problems), problems


def test_a_said_field_that_is_not_a_string_and_a_false_aggregate_block_fail():
    def number(r, c, p):
        c.update(acdc=rebuilt(p, a={**p["acdc"]["a"], "inner": {"d": 123, "x": 1}}))
    assert any("does not verify against its own SAID" in x for x in acdc_problems(number))

    def aggregate(r, c, p):
        c.update(acdc=rebuilt(p, A=["x", {"d": "E" + "A" * 43, "y": 1}]))
    assert any("does not verify against its own SAID" in x for x in acdc_problems(aggregate))


@pytest.mark.parametrize("fields", [{"n": ["not-a-digest"]}, {"nt": "2"}, {"nt": "0"}])
def test_a_next_key_commitment_that_cannot_be_used_fails(fields):
    problems = failed(icp_with(**fields))
    assert "not digests" in problems[0] or "not transferable" in problems[0]


def test_an_aggregate_must_verify_against_its_agid():
    member = {"d": "", "y": 1}
    member["d"] = iss.block_said(member)
    good = [iss.digest(iss.serialize([iss.DUMMY, member["d"]])), member]
    assert iss._aggregate_verifies(good)
    assert iss._aggregate_verifies([good[0], member["d"]])
    unsaided = {"label": "x"}
    unsaided_agid = iss.digest(iss.serialize([iss.DUMMY, iss.block_said(unsaided)]))
    for bad in ([("E" + "A" * 43), member], [good[0], "not-a-digest"], ["x"], "x",
                [unsaided_agid, unsaided]):
        assert not iss._aggregate_verifies(bad)

    def forged(r, c, p):
        c.update(acdc=rebuilt(p, A=["E" + "A" * 43, member]))
    assert any("AGID" in x for x in acdc_problems(forged))


def test_an_edge_operator_of_the_wrong_shape_fails():
    for o in (None, 7, ["I2I", 7]):
        problems = edged({"le": {"credential": "c"}}, {"le": {"d": "", "n": FAR, "o": o}})
        assert any("neither an operator" in p for p in problems), o


def test_a_primitive_must_be_canonically_encoded():
    with pytest.raises(iss.Unread, match="canonical"):
        iss.raw_of("EZ" + "A" * 42, "E", 32)


def test_a_body_nested_beyond_the_bound_is_unreadable():
    deep = b'{"v":"KERICAACAAJSONAAAA.","x":' + b"[" * 70 + b"]" * 70 + b"}"
    deep = deep.replace(b"AAAA.", iss.int_b64(len(deep), 4).encode() + b".", 1)
    with pytest.raises(iss.Unread, match="nests deeper"):
        iss.frame(deep, b"KERI")
    assert iss._nesting(b'{"s":"[[[\\"[[","x":[1]}') == 2


def test_a_seal_list_that_is_not_a_list_is_no_seal():
    assert "not anchored" in iss.sealed([{"a": 123}], "Erd", "0", "Erd")


# -- the PR review's findings -------------------------------------------------------------------

def test_an_acdc_that_breaks_its_schema_fails():
    request, result, _ = w.issuance()
    strict = {**w.SCHEMA, "$id": iss.DUMMY, "required": ["zz"]}
    strict["$id"] = iss.digest(iss.serialize(strict))
    request["schemas"].append(iss.serialize(strict).hex())
    request["credentials"][0]["schema"] = strict["$id"]
    problems = iss.grade(request, result)
    assert any("schema is not the one asked for" in p for p in problems)
    assert any("does not validate against its schema" in p for p in problems)


def test_a_schema_outside_the_runners_subset_cannot_be_evaluated():
    assert "cannot be evaluated" in iss._fits({}, {"type": "object", "minLength": 1})[0]
    assert iss._fits({}, None) == []


def test_an_edge_schema_must_be_carried_and_satisfied():
    said, _ = w.schema()
    assert edged({"le": {"credential": "c"}}, {"le": {"d": "", "n": FAR, "s": said}}) == []
    problems = edged({"le": {"credential": "c"}},
                     {"le": {"d": "", "n": FAR, "s": "E" + "A" * 43}})
    assert any("which the request does not carry" in p for p in problems)
    strict = {"$id": "", "type": "object", "required": ["zz"]}
    bodies = {"c": {"d": "Efar", "a": {}}}
    assert "far credential" in iss._edge_schemas({"le": {"n": "Efar", "s": "Es"}}, bodies,
                                                 {"Es": strict})[0]
    assert iss._edge_blocks("Ecompact") == []
    # A far node the issuance does not hold is reported by the edge check, not here.
    assert iss._edge_schemas({"le": {"n": "Eunknown", "s": "Es"}}, {}, {"Es": strict}) == []


@pytest.mark.parametrize("fields,words", [
    ({"kt": "-1"}, "not lowercase hex"),
    ({"kt": ""}, "not lowercase hex"),
    ({"kt": "0"}, "between 1 and"),
])
def test_signing_thresholds_must_be_usable(fields, words):
    assert words in failed(icp_with(**fields))[0]


def test_salts_and_stamps_must_have_their_forms():
    assert iss._is_stamp("2026-10-15T16:52:06.408727+00:00")
    assert iss._is_stamp("2026-10-15T16:52:06.408727Z")
    assert not iss._is_stamp("2026-10-15T16:52:06+00:00") and not iss._is_stamp(7)
    problems = registry_problems(lambda c, p: c.update(registry=w.chain(
        w.saidify({**p["rip"], "u": "x", "d": ""}, "ACDC"), p["bup"])))
    assert any("salt or stamp" in x for x in problems)
    problems = registry_problems(lambda c, p: c.update(registry=w.chain(
        p["rip"], w.saidify({**p["bup"], "dt": "not-a-stamp", "d": ""}, "ACDC"))))
    assert any("stamp is not of the form" in x for x in problems)
    problems = acdc_problems(lambda r, c, p: c.update(acdc=rebuilt(p, u="x")))
    assert any("top-level salt" in x for x in problems)


def test_an_attachments_count_must_measure_what_follows():
    sig = w.sig_group(b"x", [(0, "a")])
    with pytest.raises(iss.Unread, match="count"):
        iss.groups(("-CAA" + sig).encode())
    with pytest.raises(iss.Unread, match="count"):
        iss.groups(("--CAAAAA" + sig).encode())


def test_a_registry_must_be_genus_pinned_bodies_only():
    problems = registry_problems(lambda c, p: c.update(registry=c["registry"][16:]))
    assert any("genus/version code" in x for x in problems)
    problems = registry_problems(lambda c, p: c.update(registry=c["registry"] + b"junk".hex()))
    assert any("bytes follow" in x for x in problems)


def test_an_or_group_holds_when_one_member_does():
    asked = {"o": "OR", "a": {"credential": "c"}, "b": {"credential": "nope"}}
    issued_e = {"o": "OR", "a": {"d": "", "n": FAR}, "b": {"d": "", "n": "Ewrong"}}
    assert edged(asked, issued_e) == []
    asked["a"] = {"credential": "nope"}
    issued_e["a"] = {"d": "", "n": "Ewrong"}
    assert any("does not name" in p for p in edged(asked, issued_e))
