"""acdc.issue cases: the case contract, the runner's framing of an anchoring event and its search
for the signatures the case's own seeds make, and the three issuance checks
(docs/adapter-protocol.md, acdc.issue; this.i 4xw8k0hg)."""

import base64
import copy
import json
import os
import shlex

import pytest
from conftest import ROOT, assertion, make_case

from keri_conformance import cli, ed25519, issuance
from keri_conformance.assertions import evaluate
from keri_conformance.cases import case_problem

B64 = issuance.B64
SEED_A, SEED_B = bytes(range(32)), bytes(range(1, 33))
SEEDS = {"DKeyA": SEED_A.hex(), "DKeyB": SEED_B.hex()}


def body(fields: str = '"t":"ixn","i":"EIss","s":"1"') -> bytes:
    """A KERI 2.00 JSON body whose version string declares its own size."""
    template = '{"v":"KERICAACAAJSONAAAA.",' + fields + "}"
    size = len(template)
    text = "".join(B64[(size >> shift) & 63] for shift in (18, 12, 6, 0))
    return template.replace("AAAA.", text + ".", 1).encode()


BODY = body()


def signed(*signers, binary=False, genus=True, body_=BODY):
    """An anchoring stream with an indexed signature by each (index, seed)."""
    text = "-KAB" + "".join(issuance.indexed_signature(i, ed25519.sign(seed, body_))
                            for i, seed in signers)
    attachments = base64.urlsafe_b64decode(text) if binary else text.encode()
    return (issuance.GENUS if genus else b"") + body_ + attachments


# --- framing ----------------------------------------------------------------------------------

@pytest.mark.parametrize("genus", [True, False])
def test_an_anchoring_event_frames_by_its_version_string(genus):
    framed, attachments = issuance.frame(signed((0, SEED_A), genus=genus))
    assert framed == BODY and attachments.startswith(b"-KAB")


@pytest.mark.parametrize(("stream", "words"), [
    (b"-_AAACAA" + b'{"v":"ACDCCAACAAJSONAAAA."}', "does not begin with a KERI JSON body"),
    (b'{"v":"KERICAA', "not a KERI 2.00 JSON"),
    (b'{"v":"KERICAACAACBORAAAA.xx"}', "not a KERI 2.00 JSON"),
    (b'{"v":"KERICAACAAJSONAAAAx"}', "not a KERI 2.00 JSON"),
    (b'{"v":"KERICAACAAJSONA*AA."}', "not Base64"),
    (b'{"v":"KERICAACAAJSON\xffAAA."}', "not Base64"),
    (b'{"v":"KERICAACAAJSON____."}', "more than the"),
    (b'{"v":"KERICAACAAJSONAAEA."}', "only"),
])
def test_an_unframeable_anchoring_event_is_refused(stream, words):
    with pytest.raises(issuance.Unframed, match=words):
        issuance.frame(stream)


# --- signatures -------------------------------------------------------------------------------

def test_the_indexed_signature_encoding_is_cesr_s():
    from generators.spec_tables import encoding, spec_source, tables
    try:
        t = tables.load(spec_source.load_spec())
    except spec_source.SpecUnavailable:
        if os.environ.get("KCS_REQUIRE_SPEC") == "1":
            raise
        pytest.skip("the pinned CESR specification text is unavailable")
    signature = ed25519.sign(SEED_A, BODY)
    for index in (0, 1, 63):
        assert issuance.indexed_signature(index, signature) == \
            encoding.indexed(t, "A", signature, index)


@pytest.mark.parametrize(("index", "size"), [(-1, 64), (64, 64), (0, 63)])
def test_an_impossible_indexed_signature_is_refused(index, size):
    with pytest.raises(ValueError):
        issuance.indexed_signature(index, bytes(size))


@pytest.mark.parametrize("binary", [False, True])
def test_signatures_are_found_in_either_domain(binary):
    framed, attachments = issuance.frame(signed((0, SEED_A), (1, SEED_B), binary=binary))
    assert issuance.missing_signatures(framed, attachments, ["DKeyA", "DKeyB"], SEEDS) == []


@pytest.mark.parametrize(("signers", "missing"), [
    ([(1, SEED_A), (1, SEED_B)], ["DKeyA"]),  # the right key at the wrong index
    ([(0, SEED_B), (1, SEED_B)], ["DKeyA"]),  # another key at the right index
    ([(0, SEED_A)], ["DKeyB"]),  # one signer absent
])
def test_a_signature_counts_only_by_its_key_at_its_index(signers, missing):
    framed, attachments = issuance.frame(signed(*signers))
    assert issuance.missing_signatures(framed, attachments, ["DKeyA", "DKeyB"], SEEDS) == missing


def test_a_signature_over_another_body_does_not_count():
    other = body('"t":"ixn","i":"EIss","s":"2"')
    framed, _ = issuance.frame(signed((0, SEED_A)))
    _, attachments = issuance.frame(signed((0, SEED_A), body_=other))
    assert issuance.missing_signatures(framed, attachments, ["DKeyA"], SEEDS) == ["DKeyA"]


# --- the case contract ------------------------------------------------------------------------

REQUEST = {
    "kels": [{"stream": "2d5f4141414341417b7d", "source": "issuer"}],
    "seeds": SEEDS,
    "acdc": {"v": "", "t": "acm", "d": ""},
    "registry": [{"event": {"v": "", "t": "upd", "d": ""}},
                 {"event": {"v": "", "t": "bup", "d": "", "b": ""},
                  "blind": {"salt": "0ABz", "state": {"d": "", "u": "", "td": "", "ts": "issued"}}}],
    "anchor": {"event": {"v": "", "t": "ixn", "d": ""}},
}
EXPECTED = {"acdc": "7b7d", "registry": [{"event": "7b01", "blind": None},
                                         {"event": "7b02", "blind": "7b03"}],
            "anchor_body": BODY.hex()}
BASIS = "Hand-built for the runner's tests."


def issue_case(request=REQUEST, assertions=None, **kwargs):
    assertions = assertions or [
        assertion("issued", level="INTEROP", basis=BASIS, expected=EXPECTED),
        assertion("anchor_signed", name="a2", level="INTEROP", basis=BASIS,
                  expected=["DKeyA", "DKeyB"])]
    return make_case("ACDC-0901", "acdc.issue", request, assertions, profile="sedi-1", **kwargs)


def test_an_issuance_case_is_valid():
    assert case_problem(issue_case()) is None
    refused = assertion("issue_refused", level="INTEROP", basis=BASIS)
    assert case_problem(issue_case(assertions=[refused])) is None


def _without(doc, *path):
    doc = copy.deepcopy(doc)
    target = doc
    for key in path[:-1]:
        target = target[key]
    del target[path[-1]]
    return doc


@pytest.mark.parametrize(("case", "words"), [
    (issue_case(assertions=[assertion("issued", level="INTEROP", basis=BASIS,
                                      expected={**EXPECTED, "registry": EXPECTED["registry"][:1]})]),
     "registry events that do not match"),
    (issue_case(assertions=[assertion("issued", level="INTEROP", basis=BASIS, expected={
        **EXPECTED, "registry": [{"event": "7b01", "blind": "7b03"},
                                 {"event": "7b02", "blind": "7b03"}]})]),
     "registry events that do not match"),
    (issue_case(assertions=[assertion("issued", level="INTEROP", basis=BASIS,
                                      expected=_without(EXPECTED, "anchor_body"))]),
     "anchoring body exactly when"),
    (issue_case(request=_without(REQUEST, "anchor"),
                assertions=[assertion("anchor_signed", level="INTEROP", basis=BASIS,
                                      expected=["DKeyA"])]),
     "does not ask for"),
    (issue_case(assertions=[assertion("anchor_signed", level="INTEROP", basis=BASIS,
                                      expected=["DKeyC"])]),
     "no seed in its input: DKeyC"),
])
def test_an_issuance_case_must_agree_with_its_input(case, words):
    problem = case_problem(case)
    assert problem is not None and words in problem


def test_an_issuance_case_belongs_to_the_acdc_layer():
    case = issue_case()
    case["id"] = "KERI-0901"
    assert "ACDC-" in case_problem(case)


# --- the checks -------------------------------------------------------------------------------

def issued_result(**changes):
    return {"acdc": "7b7d", "registry": copy.deepcopy(EXPECTED["registry"]),
            "anchor": signed((0, SEED_A), (1, SEED_B)).hex(), **changes}


def check(name, result, expected=None):
    a = {"id": "a1", "check": name, "level": "INTEROP", "basis": BASIS}
    if expected is not None:
        a["expected"] = expected
    return evaluate(a, result, REQUEST)


def test_an_issuance_matching_the_case_passes_every_check():
    assert check("issued", issued_result(), EXPECTED).outcome == "pass"
    assert check("anchor_signed", issued_result(), ["DKeyA", "DKeyB"]).outcome == "pass"
    assert check("issue_refused", issued_result()).outcome == "fail"


@pytest.mark.parametrize(("result", "words"), [
    ({"refused": {"reason": "x"}}, "refused to issue"),
    (issued_result(acdc="7b7e"), "acdc"),
    (issued_result(registry=[]), "registry"),
    (issued_result(anchor=signed((0, SEED_A), body_=body('"t":"ixn"')).hex()), "anchor_body"),
    (issued_result(anchor="00"), "cannot be framed"),
])
def test_issued_bytes_must_be_the_case_s(result, words):
    evaluation = check("issued", result, EXPECTED)
    assert evaluation.outcome == "fail" and words in evaluation.detail


def test_without_an_expected_anchor_the_anchor_is_not_compared():
    expected = _without(EXPECTED, "anchor_body")
    assert check("issued", issued_result(anchor="00"), expected).outcome == "pass"


@pytest.mark.parametrize(("result", "words"), [
    ({"refused": {}}, "no anchoring event"),
    ({"acdc": "7b7d", "registry": []}, "no anchoring event"),
    (issued_result(anchor="00"), "cannot be framed"),
    (issued_result(anchor=signed((0, SEED_A)).hex()), "by DKeyB"),
])
def test_the_anchor_must_carry_each_signer_s_signature(result, words):
    evaluation = check("anchor_signed", result, ["DKeyA", "DKeyB"])
    assert evaluation.outcome == "fail" and words in evaluation.detail


def test_a_refusal_passes_a_case_that_must_be_refused():
    assert check("issue_refused", {"refused": {}}).outcome == "pass"


# --- end to end -------------------------------------------------------------------------------

def test_kcs_run_grades_an_issuance(cases_dir, tmp_path, write_json):
    hello = {"protocol": 1, "adapter": {"name": "a", "version": "1"},
             "implementation": {"name": "i", "version": "1", "commit": "c"},
             "operations": ["acdc.issue"], "features": []}
    table = [{"match": {"op": "acdc.issue"}, "result": issued_result()}]
    from conftest import good
    argv = good("--table", write_json("t.json", table), "--hello", write_json("h.json", hello))
    report_path = tmp_path / "report.json"
    code = cli.main(["run", "--adapter", shlex.join(argv), "--suite", str(ROOT), "--cases",
                     str(cases_dir(issue_case())), "--report", str(report_path)])
    report = json.loads(report_path.read_text())
    assert [r["outcome"] for r in report["cases"][0]["assertions"]] == ["pass", "pass"]
    assert code == 0
