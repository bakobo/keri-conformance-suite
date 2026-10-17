"""`kcs agree`, the cross-role agreement matrix (this.i 3ptj8hu9): what an issuer or holder
produced becomes acdc.verify bundles, and each verifier's verdict is held to what the case
implies."""

import copy
import json
import os
import pathlib
import sys

import pytest

from keri_conformance import agree, cli, issued
from keri_conformance.session import Failure, Reply

ROOT = pathlib.Path(__file__).resolve().parent.parent
HETI = json.loads((ROOT / "tests/fixtures/heti-issuance.json").read_text())
GOOD = str(ROOT / "tests/fakes/good.py")


def issue_case(assertion="issued", **over):
    case = {"id": "ACDC-9001", "operation": "acdc.issue", "status": "draft",
            "profile": "sedi-1", "targets": {"features": ["acdc.registry.bup"]},
            "input": copy.deepcopy(HETI["request"]),
            "assertions": [{"id": "a1", "check": assertion, "level": "INTEROP"}]}
    return {**case, **over}


def present_case(assertion="present_refused"):
    return {"id": "ACDC-9002", "operation": "acdc.present", "status": "draft",
            "profile": "sedi-1", "targets": {"features": []},
            "input": {"perspective": {"role": "holder"}, "kels": [], "registry": [],
                      "schemas": [], "acdcs": [], "held": {"stream": "2d5f"},
                      "disclosure": {"form": "compact"}},
            "assertions": [{"id": "a1", "check": assertion, "level": "INTEROP"}]}


class Fake:
    """An opened session: answers by operation from a table, and records what it was sent."""

    def __init__(self, answers, operations=("acdc.issue", "acdc.verify"),
                 features=("acdc.registry.bup",)):
        self.answers = answers
        self.hello = {"operations": list(operations), "features": list(features),
                      "implementation": {"name": "fake", "version": "0", "commit": "0"}}
        self.sent = []
        self.opened = self.closed = False

    def open(self):
        self.opened = True

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.closed = True

    def request(self, op, fields):
        self.sent.append((op, fields))
        answer = self.answers[op]
        return answer(fields) if callable(answer) else answer

    def take_stderr(self):
        return ""


ISSUED = Reply(HETI["result"])
VALID = Reply({"verdict": "valid", "registry": None, "edges": []})
INVALID = Reply({"verdict": "invalid", "registry": None, "edges": []})


def test_the_disclosure_is_wrapped_with_or_without_its_group_code():
    state = HETI["result"]["credentials"]["c"]["disclosure"]
    bare = agree.disclosure_group(state)
    assert bare == "-CAk-aAj" + state
    assert agree.disclosure_group("-aAj" + state) == bare
    big = "A" * 4 * 64 ** 2
    assert agree.disclosure_group(big).startswith("--CAABAC--aAABAA")


def test_an_issuance_becomes_one_bundle_per_credential_built_from_what_was_returned():
    bundle = agree.issue_bundles(HETI["request"], HETI["result"])["c"]
    out = HETI["result"]["credentials"]["c"]
    assert bundle["presented"] == {"stream": out["acdc"]}
    assert bundle["schemas"] == HETI["request"]["schemas"] and bundle["acdcs"] == []
    assert [k["source"] for k in bundle["kels"]] == ["issuer", "issuer", "holder"]
    joined = b"".join(bytes.fromhex(k["stream"]).removeprefix(issued.GENUS)
                      for k in bundle["kels"][:2])
    assert issued.GENUS + joined == bytes.fromhex(HETI["result"]["kels"]["issuer"])
    head = bytes.fromhex(bundle["registry"][-1]["stream"])
    assert head.endswith(agree.disclosure_group(out["disclosure"]).encode())
    assert all(bytes.fromhex(e["stream"]).startswith(issued.GENUS) for e in bundle["registry"])


def test_a_converted_issuance_is_valid_under_the_reference_model():
    from generators.spec_tables import sedi_model as sm
    from generators.spec_tables import spec_source, tables
    try:
        text = spec_source.load_spec()
    except spec_source.SpecUnavailable as e:
        if os.environ.get("KCS_REQUIRE_SPEC") == "1":
            raise
        pytest.skip(f"a pinned specification text is unavailable: {e}")
    bundle = agree.issue_bundles(HETI["request"], HETI["result"])["c"]
    result = sm.evaluate(tables.load(text), bundle)
    assert result.verdict == sm.VALID and result.head.facts()["ts"] == "issued"


def test_a_credential_bundle_carries_its_far_credentials_and_their_registries():
    request = {"roles": [], "schemas": [], "credentials": [
        {"name": "a", "edges": {"g": {"o": "OR", "x": {"credential": "b"}}}},
        {"name": "b", "edges": {"y": {"credential": "c"}, "z": "not an edge"}},
        {"name": "c", "edges": {"w": {"credential": "a"}}}]}
    result = {"kels": {}, "credentials": {
        n: {"acdc": n.encode().hex(), "registry": "", "disclosure": None} for n in "abc"}}
    bundles = agree.issue_bundles(request, result)
    assert bundles["a"]["acdcs"] == [{"stream": b"b".hex()},
                                     {"stream": b"c".hex()}]
    assert bundles["c"]["acdcs"] == [{"stream": b"a".hex()},
                                     {"stream": b"b".hex()}]
    assert bundles["b"]["registry"] == []


def test_a_presentation_replaces_what_was_held():
    case = present_case()
    bundle = agree.present_bundle(case["input"], {"presented": {"stream": "2d5f00"}})
    assert "held" not in bundle and "disclosure" not in bundle
    assert bundle["presented"] == {"stream": "2d5f00"}
    assert bundle["perspective"] == {"role": "validator"}


def test_a_clean_issuance_must_be_valid_to_every_verifier(monkeypatch):
    monkeypatch.setattr(agree, "evaluate", lambda a, r, i: type("E", (), {"outcome": "pass"}))
    issuer = Fake({"acdc.issue": ISSUED, "acdc.verify": VALID})
    other = Fake({"acdc.verify": INVALID}, operations=("acdc.verify",))
    cells = agree.matrix({"a": issuer, "b": other}, {"a": issuer, "b": other}, [issue_case()])
    assert [(c["verifier"], c["expected"], c["verdict"], c["agrees"]) for c in cells] == [
        ("a", "valid", "valid", True), ("b", "valid", "invalid", False)]
    assert other.sent[0][0] == "acdc.verify" and "presented" in other.sent[0][1]


def test_an_issuance_that_fails_its_own_case_is_recorded_without_an_expectation():
    issuer = Fake({"acdc.issue": Reply({**HETI["result"], "kels": {
        "issuer": HETI["result"]["kels"]["holder"], "holder": HETI["result"]["kels"]["holder"]}}),
        "acdc.verify": VALID})
    [cell] = agree.matrix({"a": issuer}, {"a": issuer}, [issue_case()])
    assert cell["producer_passed"] is False and cell["expected"] is None
    assert cell["agrees"] is None


def test_an_issuer_negative_issued_anyway_must_be_refused_by_every_verifier():
    issuer = Fake({"acdc.issue": ISSUED, "acdc.verify": VALID})
    [cell] = agree.matrix({"a": issuer}, {"a": issuer}, [issue_case("issue_refused")])
    assert (cell["expected"], cell["verdict"], cell["agrees"]) == ("not-valid", "valid", False)
    issuer.answers["acdc.verify"] = Failure("harness", "boom")
    [cell] = agree.matrix({"a": issuer}, {"a": issuer}, [issue_case("issue_refused")])
    assert (cell["verdict"], cell["agrees"], cell["detail"]) == (None, False, "harness: boom")


def test_a_refusal_or_an_error_is_one_cell_with_no_verifier():
    refused = Fake({"acdc.issue": Reply({"refused": {"reason": "no"}})})
    broken = Fake({"acdc.issue": Failure("crash", "it died")})
    cells = agree.matrix({"r": refused, "e": broken}, {"r": refused, "e": broken}, [issue_case("issue_refused")])
    assert [(c["producer"], c["produced"], c["producer_passed"], c["verifier"], c["detail"])
            for c in cells] == [("r", "refused", True, None, "no"),
                                ("e", "error", False, None, "crash: it died")]


def test_an_answer_no_bundle_can_be_built_from_disagrees_only_when_something_was_expected():
    bad = Reply({"kels": {"issuer": "2d5f414141434141", "holder": ""},
                    "credentials": {"c": {"acdc": "", "registry": ""}}})
    issuer = Fake({"acdc.issue": bad, "acdc.verify": VALID})
    [cell] = agree.matrix({"a": issuer}, {"a": issuer}, [issue_case("issue_refused")])
    assert cell["agrees"] is False and cell["detail"].startswith("no bundle could be built")
    [cell] = agree.matrix({"a": issuer}, {"a": issuer}, [issue_case()])
    assert cell["agrees"] is None


def test_a_presentation_is_verified_and_a_refusal_case_presented_carries_no_expectation():
    holder = Fake({"acdc.present": Reply({"presented": {"stream": "2d5f"}}),
                   "acdc.verify": INVALID}, operations=("acdc.present", "acdc.verify"))
    [cell] = agree.matrix({"h": holder}, {"h": holder}, [present_case()])
    assert (cell["credential"], cell["produced"], cell["expected"], cell["verdict"],
            cell["agrees"]) == ("presented", "presented", None, "invalid", None)


def test_what_a_party_does_not_declare_is_never_sent():
    case = issue_case()
    verifier = Fake({"acdc.verify": VALID}, operations=("acdc.verify",), features=())
    issuer = Fake({"acdc.issue": ISSUED}, operations=("acdc.issue",))
    cells = agree.matrix({"i": issuer, "v": verifier}, {"i": issuer, "v": verifier}, [case, {**case, "status": "deprecated"},
                          {**case, "operation": "acdc.verify"}])
    assert [(c["verifier"], c["detail"], c["agrees"]) for c in cells] == [
        ("v", "the verifier does not declare the case's features", None),
        (None, "no adapter that declares acdc.verify and the case's features verified it", False)]
    assert verifier.sent == [] and len(issuer.sent) == 1


def test_an_expectation_no_adapter_can_verify_disagrees():
    issuer = Fake({"acdc.issue": ISSUED}, operations=("acdc.issue",))
    [cell] = agree.matrix({"i": issuer}, {"i": issuer}, [issue_case()])
    assert (cell["verifier"], cell["expected"], cell["agrees"]) == (None, "valid", False)
    [cell] = agree.matrix({"i": issuer}, {"i": issuer}, [issue_case("issue_refused")])
    assert (cell["expected"], cell["agrees"]) == ("not-valid", False)


def test_the_report_opens_every_adapter_and_counts_disagreements(monkeypatch):
    monkeypatch.setattr(agree, "evaluate", lambda a, r, i: type("E", (), {"outcome": "pass"}))
    opened = []

    def start(command):
        opened.append(Fake({"acdc.issue": ISSUED, "acdc.verify": INVALID}))
        return opened[-1]

    report = agree.run_agreement(start, {"a": "x"}, [issue_case()], "2026.10")
    producing, verifying = opened
    assert all(f.opened and f.closed for f in opened)
    # The verdict comes from a session that issued nothing.
    assert [op for op, _ in producing.sent] == ["acdc.issue"]
    assert [op for op, _ in verifying.sent] == ["acdc.verify"]
    assert report["summary"] == {"cells": 1, "judged": 1, "disagree": 1}
    assert report["adapters"] == {"a": producing.hello["implementation"]}
    text = agree.human_summary(report)
    assert "1 disagreeing" in text and "ACDC-9001 c: a issued, a said invalid" in text
    report["cells"][0]["detail"] = None
    assert agree.human_summary(report).endswith("where valid was expected")


def _suite(tmp_path, verdict):
    cases = tmp_path / "cases"
    cases.mkdir()
    source = next(p for p in sorted((ROOT / "cases/sedi").glob("*.json"))
                  if json.loads(p.read_text())["operation"] == "acdc.present")
    case = json.loads(source.read_text())
    (cases / source.name).write_text(json.dumps(case))
    hello = {"protocol": 1, "adapter": {"name": "f", "version": "0"},
             "implementation": {"name": "f", "version": "0", "commit": "0"},
             "operations": ["acdc.present", "acdc.verify"],
             "features": case["targets"]["features"], "composes": []}
    table = [{"match": {"op": "acdc.present"},
              "result": {"presented": {"stream": issued.GENUS.hex() + case["assertions"][0][
                  "expected"]["body"]}}},
             {"match": {"op": "acdc.verify"},
              "result": {"verdict": verdict, "registry": None, "edges": []}}]
    (tmp_path / "hello.json").write_text(json.dumps(hello))
    (tmp_path / "table.json").write_text(json.dumps(table))
    command = (f"{sys.executable} {GOOD} --hello {tmp_path / 'hello.json'} "
               f"--table {tmp_path / 'table.json'}")
    return ["--adapter", f"f={command}",
            "--suite", str(ROOT), "--cases", str(cases)]


@pytest.mark.parametrize("verdict,code", [("valid", 0), ("invalid", 1)])
def test_kcs_agree_exits_on_disagreement_and_writes_the_matrix(tmp_path, capsys, verdict, code):
    args = _suite(tmp_path, verdict)
    report = tmp_path / "agree.json"
    assert cli.main(["agree", *args, "--profile", "sedi-1", "--report", str(report)]) == code
    cells = json.loads(report.read_text())["cells"]
    assert [c["verdict"] for c in cells] == [verdict]
    assert "Agreement: 1 cells" in capsys.readouterr().out
    assert cli.main(["agree", *args]) == code


def test_kcs_agree_refuses_a_bad_adapter_list(tmp_path, capsys):
    args = _suite(tmp_path, "valid")
    assert cli.main(["agree", *args, *args[:2]]) == 2
    assert "share a name" in capsys.readouterr().err
    assert cli.main(["agree", "--adapter", "nocommand"]) == 2
    assert cli.main(["agree", "--adapter", "x= "]) == 2
