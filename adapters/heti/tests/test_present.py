"""acdc.present through heti's disclose, and acdc.verify's presentation context judged with heti's
parts (this.i 9fg9ufsm), over the inputs of the suite's sedi-1 holder and presenter cases."""

import json
import pathlib

import pytest

from kcs_adapter_heti import present, presentation, verify

FIXTURE = json.loads((pathlib.Path(__file__).parent / "fixtures" / "present.json").read_text())


def given(case_id, **over):
    return {**FIXTURE["cases"][case_id]["input"], **over}


def body(result):
    stream = bytes.fromhex(result["presented"]["stream"])
    return verify.split(stream)[0]


# -- acdc.present

def test_compact_conceals_the_attribute_section():
    sad = body(present.present(given("ACDC-0160")))
    assert isinstance(sad["a"], str)


def test_expanded_answers_the_held_body():
    request = given("ACDC-0161")
    held = verify.split(bytes.fromhex(request["held"]["stream"]))
    result = present.present(request)
    assert bytes.fromhex(result["presented"]["stream"]) == verify.GENUS + held[1]


def test_a_partial_form_that_hides_nothing_is_the_held_body():
    assert isinstance(body(present.present(given("ACDC-0162")))["a"], dict)


def test_a_partial_form_conceals_what_it_does_not_expand():
    sad = body(present.present(given("ACDC-0163")))
    assert isinstance(sad["a"], str) and isinstance(sad["e"], dict)


def test_heti_cannot_compact_an_edge_section():
    result = present.present(given("ACDC-0163", disclosure={"form": "compact"}))
    assert result == {"refused": {"reason": "heti's disclose cannot compact e"}}


def test_selective_reveals_the_named_blocks_and_heti_reveals_the_issuee():
    sad = body(present.present(given("ACDC-0165")))
    revealed = [b for b in sad["A"][1:] if isinstance(b, dict)]
    assert {k for b in revealed for k in b} >= {"i", "name"}


@pytest.mark.parametrize("case_id,words", [
    ("ACDC-0166", "heti does not find the held ACDC valid"),
    ("ACDC-0169", "x names no block"),
    ("ACDC-0170", "names a block twice"),
    ("ACDC-0171", "must name at least one block"),
    ("ACDC-0173", "heti refused the disclosure"),
    ("ACDC-0174", "nickname names no attribute block"),
    ("ACDC-0175", "names an attribute twice"),
    ("ACDC-0176", "must name at least one attribute"),
    ("ACDC-0177", "a is held only compact"),
])
def test_what_a_holder_must_refuse_is_refused(case_id, words):
    result = present.present(given(case_id))
    assert words in result["refused"]["reason"]


@pytest.mark.parametrize("change", [
    {"disclosure": "compact"},
    {"disclosure": {"form": "shown"}},
    {"disclosure": {"form": "partial", "expand": "a"}},
    {"disclosure": {"form": "selective", "disclose": [1]}},
    {"held": {"stream": "zz"}},
    {"held": "x"},
])
def test_a_request_the_adapter_cannot_read_is_an_error(change):
    with pytest.raises(verify.Malformed):
        present.present(given("ACDC-0160", **change))


# -- the presentation context

def judged(case_id, **over):
    return verify.verify(given(case_id, **over))


@pytest.mark.parametrize("case_id,verdict", [
    ("ACDC-0118", "valid"),  # the issuee
    ("ACDC-0119", "invalid"),  # a stranger
    ("ACDC-0120", "valid"),  # the issuer: heti's own rule admits it, unlike sedi-1's
    ("ACDC-0121", "valid"),  # untargeted
    ("ACDC-0128", "valid"),  # an aggregate presented by its issuee
    ("ACDC-0130", "invalid"),  # an aggregate presented by a stranger
])
def test_the_presenter_is_bound_by_hetis_own_rule(case_id, verdict):
    result = judged(case_id)
    assert result["verdict"] == verdict
    if verdict == "invalid":
        assert result["reason"].startswith(presentation.E_PRESENTER)


def grant(case_id):
    return bytes.fromhex(given(case_id)["presentation"]["messages"][-1]["stream"])


def with_grant(case_id, stream: bytes, **over):
    context = {**given(case_id)["presentation"], "messages": [{"stream": stream.hex()}], **over}
    return judged(case_id, presentation=context)


def rewritten(stream: bytes, old: bytes, new: bytes) -> bytes:
    assert old in stream
    return stream.replace(old, new, 1)


@pytest.mark.parametrize("edit,words", [
    (lambda s: b"not a message", "does not frame"),
    (lambda s: rewritten(s, b'"r":"/ipex/grant"', b'"r":"/ipex/apply"'), "not an exn"),
    (lambda s: rewritten(s, b'"o":["E', b'"o":["X'), "does not name exactly"),
    (lambda s: s.split(b"-CA")[0], "no signature group"),
])
def test_a_grant_that_does_not_hold_is_invalid(edit, words):
    result = with_grant("ACDC-0118", edit(grant("ACDC-0118")))
    assert result["verdict"] == "invalid" and words in result["reason"]


def test_a_grant_to_another_verifier_is_invalid():
    result = with_grant("ACDC-0118", grant("ACDC-0118"), verifier="E" + "A" * 43)
    assert (result["verdict"], result["reason"]) == (
        "invalid", "the grant is addressed to another verifier")


def test_a_forged_signature_is_refused_by_heti():
    stream = grant("ACDC-0118")
    forged = stream[:-10] + (b"A" if stream[-10:-9] != b"A" else b"B") + stream[-9:]
    result = with_grant("ACDC-0118", forged)
    assert result["verdict"] in ("invalid", "incomplete") and result["reason"].startswith("e.")


def test_an_error_heti_does_not_code_is_not_swallowed(monkeypatch):
    def broken(**kwargs):
        raise RuntimeError("not a heti refusal")

    monkeypatch.setattr(presentation, "verify_signature", broken)
    with pytest.raises(RuntimeError):
        judged("ACDC-0118")


@pytest.mark.parametrize("attachments,ok", [
    (b"", False),  # no signature group
    (b"-CAB-SAA", False),  # a group, but not a transferable signature group
])
def test_only_one_transferable_signature_group_for_the_sender_counts(attachments, ok):
    assert (presentation._signatures(attachments, "E" * 44) is not None) is ok


def wrapped(code: bytes, contents: bytes) -> bytes:
    """A group of quadlet-counted contents under a two-character code, small count."""
    quadlets = len(contents) // 4
    return code + (verify.B64[quadlets // 64] + verify.B64[quadlets % 64]).encode() + contents


def test_a_signature_group_for_another_signer_or_without_signatures_counts_for_nothing():
    _sad, _raw, attachments = verify.split(grant("ACDC-0118"))
    sender = _sad["i"]
    assert presentation._signatures(attachments, sender) is not None
    assert presentation._signatures(attachments, "E" + "B" * 43) is None
    group = next(b for c, b in verify.groups(attachments) if c == b"-X")
    head = group[:112]  # the signer's prefix, its establishment event's sequence number and SAID
    for contents in (group[:-4],  # a signature cut short
                     head + b"-KAA",  # a signature group holding none
                     head):  # no signature group at all
        assert presentation._signatures(wrapped(b"-C", wrapped(b"-X", contents)), sender) is None


@pytest.mark.parametrize("context", [
    "x",
    {"messages": [], "verifier": "E"},
    {"messages": [{"stream": "00"}]},
    {"messages": [{"stream": "00"}], "verifier": ""},
])
def test_a_context_that_names_no_message_or_no_verifier_cannot_be_read(context):
    with pytest.raises(verify.Malformed):
        presentation.context({"presentation": context})


def test_without_a_context_nothing_is_composed():
    assert presentation.context({}) is None


def test_a_block_held_only_as_its_said_carries_no_label():
    sad = {"A": ["Eagid", "Eblinded", {"d": "Eb", "u": "0A", "name": "Zoe"}]}
    assert present._selected(sad, {"disclose": ["name"]}) == ([2], None)


@pytest.mark.parametrize("disclosure", [{"form": "compact"},
                                        {"form": "selective", "disclose": ["name"]}])
def test_a_form_that_hides_the_issuee_block_heti_always_reveals_is_refused(disclosure):
    result = present.present(given("ACDC-0164", disclosure=disclosure))
    assert result == {"refused": {"reason": present.ALWAYS_ISSUEE}}


def test_the_issuee_block_is_one_held_disclosed():
    assert present._issuee_block({"A": ["Eagid", {"d": "E", "i": "E"}]}) is True
    assert present._issuee_block({"A": ["Eagid", "Eblinded"]}) is False
    assert present._issuee_block({"a": {"d": "E"}}) is False


def test_siblings_are_hidden_at_every_level_a_partial_form_names():
    sad = {"a": {"d": "Ea", "x": {"d": "Ex", "y": {"d": "Ey"}, "z": {"d": "Ez"}}}}
    assert present._hidden(sad, {"form": "partial", "expand": ["a.x.y"]}) == (["a.x.z"], None)


def test_a_partial_form_hides_every_sub_block_it_does_not_name():
    sad = {"a": {"d": "Ea", "x": {"d": "Ex", "v": 1}, "y": {"d": "Ey", "v": 2}},
           "e": {"d": "Ee", "le": {"n": "E1"}, "private": {"n": "E2"}, "o": "AND"}}
    assert present._hidden(sad, {"form": "partial", "expand": ["a.x", "e.le"]}) == (
        ["a.y", "e.private"], None)
    assert present._hidden(sad, {"form": "partial", "expand": ["a", "e"]}) == ([], None)
    assert present._hidden(sad, {"form": "compact"}) == (["a", "e"], None)


def test_a_sub_block_of_the_edges_heti_must_hide_is_refused():
    request = given("ACDC-0163")
    assert present.present(request)["presented"]  # e has only le, so naming it hides nothing
    sad = verify.split(bytes.fromhex(request["held"]["stream"]))[0]
    hidden, _ = present._hidden({**sad, "e": {**sad["e"], "extra": {"n": "E"}}},
                                request["disclosure"])
    assert "e.extra" in hidden


@pytest.mark.parametrize("sad,found", [
    ({"a": "Ea"}, "a"),
    ({"A": ["Eagid", {"d": "E1"}, "Eblinded"]}, "A"),
    ({"e": {"d": "Ee", "o": "AND", "le": "Ecompact"}}, "e.le"),
    ({"a": {"d": "Ea"}, "e": {"d": "Ee", "le": {"n": "E"}}}, None),
])
def test_a_block_held_only_compact_is_found(sad, found):
    assert present._compact_inside(sad) == found


def test_a_signature_counter_must_count_the_signatures_it_heads():
    _sad, _raw, attachments = verify.split(grant("ACDC-0118"))
    group = next(b for c, b in verify.groups(attachments) if c == b"-X")
    head, sigs = group[:116], group[116:]
    for counter in (b"-KAA", b"-K!!"):
        contents = head[:112] + counter + sigs
        assert presentation._signatures(wrapped(b"-C", wrapped(b"-X", contents)),
                                        _sad["i"]) is None


def test_partial_paths_are_matched_in_one_pass_per_level():
    import time

    blocks = {f"b{n}": {"d": "E", "x": {"d": "E"}, "y": {"d": "E"}} for n in range(20_000)}
    sad = {"a": {"d": "Ea", **blocks}}
    expand = [f"a.b{n}.x" for n in range(20_000)]
    start = time.monotonic()
    hidden, why = present._hidden(sad, {"form": "partial", "expand": expand})
    assert time.monotonic() - start < 5 and why is None
    assert len(hidden) == 20_000 and hidden[0] == "a.b0.y"
