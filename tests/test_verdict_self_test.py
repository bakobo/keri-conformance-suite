"""The always-X self-test (docs/profiles/sedi-test-plan.md, item 8): a verifier that answers one
verdict to every acdc.verify case, whatever the bundle, fails sedi-1, while acdc-v1.0 passes the
two that never answer valid at MUST. The difference is the point of sedi-1's grading: acdc-v1.0
grades accepting a valid ACDC only as an inferred SHOULD, so refusing everything conforms there,
and sedi-1 grades valid, invalid and incomplete apart at INTEROP (choices valid-is-interop and
unresolved-grading, this.i 8fh68wt6).

Every ACDC case is still draft, and a draft decides no verdict, so the committed cases are read
here as if active. Each constant verifier goes through run_case, the runner's own path from a
response to an outcome, with a stand-in session in place of an adapter process."""

import pathlib

import pytest

from keri_conformance import run
from keri_conformance.cases import load_cases
from keri_conformance.session import Reply

ROOT = pathlib.Path(__file__).resolve().parent.parent
CASES = [c for c in load_cases(ROOT / "cases")
         if c["operation"] == "acdc.verify" and c["profile"] in ("sedi-1", "acdc-v1.0")]


class Always:
    """A session whose adapter verifies every bundle as ``verdict``, reporting no edge and no
    registry, and declares every feature a case can ask for."""

    def __init__(self, verdict: str):
        features = sorted({f for c in CASES for f in c["targets"]["features"]})
        self.hello = {"operations": ["acdc.verify"], "features": features,
                      "implementation": {"name": f"always-{verdict}"}}
        self.verdict = verdict

    def request(self, operation, fields):
        assert operation == "acdc.verify"
        return Reply({"verdict": self.verdict})

    def take_stderr(self):
        return ""


def entries(verdict: str) -> list[dict]:
    session = Always(verdict)
    return [run.run_case(session, {**case, "status": "active"}) for case in CASES]


def test_both_profiles_have_verify_cases_of_every_expected_verdict():
    expected = {(c["profile"], a["expected"]) for c in CASES for a in c["assertions"]
                if a["check"] == "verdict"}
    assert {("sedi-1", v) for v in ("valid", "invalid", "incomplete")} <= expected
    assert ("acdc-v1.0", "not-valid") in expected


@pytest.mark.parametrize("verdict,acdc", [("valid", "not-conformant"),
                                          ("invalid", "conformant"),
                                          ("incomplete", "conformant")])
def test_a_verifier_that_always_answers_one_verdict_fails_sedi_1(verdict, acdc):
    found = entries(verdict)
    assert run._member_verdict(found, "sedi-1", own=True) == "not-interoperable"
    assert run._member_verdict(found, "acdc-v1.0", own=False) == acdc
    # Each fails sedi-1 on cases expecting each verdict but its own.
    failed = {a["expected"] for e, c in zip(found, CASES) if c["profile"] == "sedi-1"
              for a, r in zip(c["assertions"], e["assertions"])
              if a["check"] == "verdict" and r["outcome"] == "fail"}
    assert failed >= {"valid", "invalid", "incomplete"} - {verdict}
    assert verdict not in failed
