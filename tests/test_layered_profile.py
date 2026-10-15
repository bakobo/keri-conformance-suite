"""Layered profiles: reading a profile file, and the claim a layered profile makes over its own
cases and its prerequisites' in one run (docs/design.md, Targets and profiles; this.i 47yreej2)."""

import json
import shlex
import shutil

import pytest
from conftest import ROOT, assertion, good, make_case

from keri_conformance import cli, errors
from keri_conformance.profiles import Profile, claim_verdict, load_profile, manifest_problem

INTEROP_VERDICTS = ("interoperable", "not-interoperable", "incomplete", "no-evidence")
BASIS = "Hand-built for the runner's tests."
LAYERED = {"name": "lay", "version": "1", "status": "draft", "prerequisites": ["base"],
           "requires": {"operations": ["cesr.parse"], "features": ["cesr.genus-2.00"]},
           "cases": []}


@pytest.fixture
def suite(tmp_path):
    root = tmp_path / "suite"
    (root / "profiles").mkdir(parents=True)
    shutil.copy(ROOT / "pyproject.toml", root / "pyproject.toml")
    shutil.copy(ROOT / "profiles" / "features.json", root / "profiles" / "features.json")

    write(root, "base", {"name": "base", "normative": True, "cases": []})
    write(root, "other", {"name": "other", "normative": True, "cases": []})
    write(root, "lay", LAYERED)
    return root


def write(root, name, doc):
    (root / "profiles" / f"{name}.json").write_text(json.dumps(doc), encoding="utf-8")


# --- reading a profile ----------------------------------------------------------------------------

def test_a_flat_profile_is_read_from_the_suite():
    profile = load_profile(ROOT, "cesr-1.0")
    assert profile == Profile("cesr-1.0")
    assert not profile.layered and profile.members == ("cesr-1.0",)


def test_a_layered_profile_names_its_prerequisites_and_requirements(suite):
    profile = load_profile(suite, "lay")
    assert profile.layered and profile.version == "1"
    assert profile.members == ("lay", "base")
    assert profile.operations == ("cesr.parse",) and profile.features == ("cesr.genus-2.00",)


@pytest.mark.parametrize("name", ["no-such-profile", "../profiles/base", "Upper", "", "a" * 65])
def test_a_profile_the_suite_does_not_define_is_refused_as_usage(suite, name):
    with pytest.raises(errors.RunnerError) as info:
        load_profile(suite, name)
    assert info.value.code == errors.E_PROFILE_UNKNOWN
    assert info.value.exit_code == errors.EXIT_USAGE


@pytest.mark.parametrize(("doc", "words"), [
    ({**LAYERED, "name": "other-name"}, '"name" is lay'),
    ([], '"name" is lay'),
    ({**LAYERED, "version": ""}, "must not be empty"),
    ({**LAYERED, "prerequisites": []}, "at least 1 item"),
    ({**LAYERED, "requires": {"operations": []}}, "features"),
    ({**LAYERED, "surprise": 1}, "surprise"),
    ({**LAYERED, "prerequisites": ["lay"]}, "layers do not nest"),
    ({**LAYERED, "prerequisites": ["nested"]}, "layers do not nest"),
])
def test_a_malformed_layered_profile_is_a_runner_fault(suite, doc, words):
    write(suite, "nested", {**LAYERED, "name": "nested"})
    write(suite, "lay", doc)
    with pytest.raises(errors.RunnerError) as info:
        load_profile(suite, "lay")
    assert info.value.code == errors.E_PROFILE_FORMAT
    assert info.value.exit_code == errors.EXIT_FAULT
    assert words in info.value.message


def test_a_prerequisite_the_suite_does_not_define_is_refused(suite):
    write(suite, "lay", {**LAYERED, "prerequisites": ["missing"]})
    with pytest.raises(errors.RunnerError) as info:
        load_profile(suite, "lay")
    assert info.value.code == errors.E_PROFILE_UNKNOWN


def test_an_unreadable_profile_file_is_a_runner_fault(suite):
    (suite / "profiles" / "lay.json").write_text("{", encoding="utf-8")
    with pytest.raises(errors.RunnerError) as info:
        load_profile(suite, "lay")
    assert info.value.code == errors.E_PROFILE_FORMAT


# --- the claim ------------------------------------------------------------------------------------

PREREQUISITE = ("conformant", "not-conformant", "incomplete", "no-evidence")
OWN = INTEROP_VERDICTS


def expected_claim(own, prerequisite, missing):
    if missing or own == "not-interoperable" or prerequisite == "not-conformant":
        return "not-interoperable"
    if own != "interoperable" or prerequisite != "conformant":
        return "incomplete"
    return "interoperable"


@pytest.mark.parametrize("missing", [False, True])
@pytest.mark.parametrize("prerequisite", PREREQUISITE)
@pytest.mark.parametrize("own", OWN)
def test_the_claim_takes_definite_failures_first(own, prerequisite, missing):
    assert claim_verdict(own, {"base": prerequisite, "other": "conformant"}, missing) == \
        expected_claim(own, prerequisite, missing)


def test_every_prerequisite_must_be_conformant():
    assert claim_verdict("interoperable", {"a": "conformant", "b": "no-evidence"}, False) == \
        "incomplete"
    assert claim_verdict("interoperable", {"a": "conformant", "b": "conformant"}, False) == \
        "interoperable"


# --- a layered run, end to end --------------------------------------------------------------------

# Prerequisite cases that make the base profile's verdict each value. The fake adapter rejects the
# stream 2d4b and decodes every other stream, and answers keri.emit, whose signatures_verify check
# this runner cannot evaluate.
BASE_CASES = {
    "conformant": [make_case("CESR-0001", "cesr.parse", {"stream": "2d4b"},
                             [assertion("rejected")], profile="base")],
    "not-conformant": [make_case("CESR-0001", "cesr.parse", {"stream": "00"},
                                 [assertion("rejected")], profile="base")],
    "incomplete": [make_case("KERI-0001", "keri.emit",
                             {"event": {"t": "icp"}, "seeds": {"DAbc": "00"}},
                             [assertion("signatures_verify")], profile="base")],
    "no-evidence": [],
}
OWN_CASES = {
    "interoperable": [make_case("CESR-0101", "cesr.parse", {"stream": "2d4b"},
                                [assertion("rejected", level="INTEROP", basis=BASIS)],
                                profile="lay")],
    "not-interoperable": [make_case("CESR-0101", "cesr.parse", {"stream": "00"},
                                    [assertion("rejected", level="INTEROP", basis=BASIS)],
                                    profile="lay")],
    "no-evidence": [],
}
# A case in neither profile, which a layered run must not send.
STRAY = make_case("CESR-0201", "cesr.parse", {"stream": "00"}, [assertion("rejected")],
                  profile="other")


def manifest(suite, *cases):
    """List each case in its profile's file, as the generator would."""
    for name in ("base", "other", "lay"):
        path = suite / "profiles" / f"{name}.json"
        doc = json.loads(path.read_text())
        doc["cases"] = sorted(c["id"] for c in cases if c["profile"] == name)
        path.write_text(json.dumps(doc), encoding="utf-8")


def run(suite, cases, tmp_path, profile="lay"):
    report = tmp_path / "report.json"
    code = cli.main(["run", "--adapter", shlex.join(good()), "--suite", str(suite),
                     "--cases", str(cases), "--report", str(report), "--profile", profile])
    return code, (json.loads(report.read_text()) if report.exists() else None)


@pytest.mark.parametrize("missing", [False, True])
@pytest.mark.parametrize("prerequisite", PREREQUISITE)
@pytest.mark.parametrize("own", list(OWN_CASES))
def test_a_layered_run_reports_its_claim(suite, cases_dir, tmp_path, capsys, own, prerequisite,
                                         missing):
    if missing:
        write(suite, "lay", {**LAYERED, "requires": {"operations": ["cesr.parse", "acdc.issue"],
                                                    "features": ["kel.delegation"]}})
    chosen = [*BASE_CASES[prerequisite], *OWN_CASES[own], STRAY]
    manifest(suite, *chosen)
    code, report = run(suite, cases_dir(*chosen), tmp_path)
    claim = report["claim"]
    want = expected_claim(own, prerequisite, missing)
    assert claim["verdict"] == report["verdict"] == want
    assert claim["profile"] == "lay" and claim["version"] == "1"
    assert claim["prerequisites"] == {"base": prerequisite}
    assert claim["own_verdict"] == own
    assert claim["missing"] == ({"operations": ["acdc.issue"], "features": ["kel.delegation"]}
                                if missing else {"operations": [], "features": []})
    assert code == {"interoperable": 0, "not-interoperable": 1, "incomplete": 4}[want]
    assert "CESR-0201" not in {c["id"] for c in report["cases"]}
    out = capsys.readouterr().out
    assert f"verdict: {want}" in out
    assert f"base ({prerequisite})" in out and "lay version 1" in out
    assert ("not declared, and required to claim lay: acdc.issue, kel.delegation" in out) == missing


def test_a_layered_claim_is_never_worded_as_conformance(suite, cases_dir, tmp_path, capsys):
    chosen = [*BASE_CASES["conformant"], *OWN_CASES["interoperable"]]
    manifest(suite, *chosen)
    _code, report = run(suite, cases_dir(*chosen), tmp_path)
    assert report["verdict"] in INTEROP_VERDICTS
    verdict_line = next(line for line in capsys.readouterr().out.splitlines()
                        if line.startswith("verdict:"))
    assert "conform" not in verdict_line


def test_a_flat_profile_run_has_no_claim(suite, cases_dir, tmp_path):
    _code, report = run(suite, cases_dir(*BASE_CASES["conformant"]), tmp_path, profile="base")
    assert "claim" not in report and report["verdict"] == "conformant"


def test_an_unknown_profile_is_refused_before_any_case_runs(suite, cases_dir, tmp_path, capsys):
    code, report = run(suite, cases_dir(*BASE_CASES["conformant"]), tmp_path, profile="sedi-9")
    assert code == errors.EXIT_USAGE and report is None
    assert errors.E_PROFILE_UNKNOWN in capsys.readouterr().err


@pytest.mark.parametrize("change", ["missing", "extra"])
def test_a_layered_run_refuses_cases_its_profiles_do_not_name(suite, cases_dir, tmp_path,
                                                               capsys, change):
    chosen = [*BASE_CASES["conformant"], *OWN_CASES["interoperable"]]
    manifest(suite, *chosen)
    if change == "missing":
        chosen = chosen[:1]
    else:
        chosen.append(make_case("CESR-0102", "cesr.parse", {"stream": "2d4b"},
                                [assertion("rejected", level="INTEROP", basis=BASIS)],
                                profile="lay"))
    code, report = run(suite, cases_dir(*chosen), tmp_path)
    assert code == errors.EXIT_FAULT and report is None
    err = capsys.readouterr().err
    assert errors.E_PROFILE_CASES in err
    assert ("missing CESR-0101" if change == "missing" else "not listed CESR-0102") in err


@pytest.mark.parametrize("member", ["base", "lay"])
def test_an_unsent_case_leaves_its_profile_incomplete(suite, cases_dir, tmp_path, member):
    unsent = make_case("KERI-0009", "keri.process",
                       {"perspective": {"role": "validator"},
                        "messages": [{"stream": "7b7d", "source": "controller"}]},
                       [assertion("disposition", message=0, phase="final", expected="seen",
                                  **({} if member == "base" else
                                     {"level": "INTEROP", "basis": BASIS}))],
                       features=["kel.delegation"], profile=member)
    chosen = [*BASE_CASES["conformant"], *OWN_CASES["interoperable"], unsent]
    manifest(suite, *chosen)
    _code, report = run(suite, cases_dir(*chosen), tmp_path)
    claim = report["claim"]
    if member == "base":
        assert claim["prerequisites"] == {"base": "incomplete"}
    else:
        assert claim["own_verdict"] == "incomplete"
    assert claim["verdict"] == "incomplete"


def test_a_prerequisite_whose_case_list_is_malformed_is_a_runner_fault(suite):
    write(suite, "base", {"name": "base", "cases": "CESR-0001"})
    with pytest.raises(errors.RunnerError) as info:
        load_profile(suite, "lay")
    assert info.value.code == errors.E_PROFILE_FORMAT


def test_the_manifest_check_names_what_differs():
    profile = Profile("lay", "1", ("base",), manifests={"lay": ("A",), "base": ("B", "C")})
    assert manifest_problem(profile, {"lay": {"A"}, "base": {"B", "C"}}) is None
    problem = manifest_problem(profile, {"lay": {"A", "D"}, "base": {"B"}})
    assert problem is not None and "not listed D" in problem
    assert "missing C" in manifest_problem(profile, {"lay": {"A"}, "base": {"B"}})


def test_an_aborted_layered_run_claims_no_more_than_incomplete(suite, cases_dir, tmp_path,
                                                                monkeypatch):
    from keri_conformance import run as run_module
    chosen = [*BASE_CASES["conformant"], *OWN_CASES["interoperable"]]
    manifest(suite, *chosen)
    monkeypatch.setattr(run_module, "MAX_RETAINED_BYTES", 0)
    code, report = run(suite, cases_dir(*chosen), tmp_path)
    assert report["verdict"] == "aborted" and report["claim"]["verdict"] == "incomplete"
    assert code == errors.EXIT_FAULT


def test_an_aborted_run_never_softens_a_definite_failure(suite, cases_dir, tmp_path,
                                                         monkeypatch):
    from keri_conformance import run as run_module
    write(suite, "lay", {**LAYERED, "requires": {"operations": ["acdc.issue"], "features": []}})
    chosen = [*BASE_CASES["conformant"], *OWN_CASES["interoperable"]]
    manifest(suite, *chosen)
    monkeypatch.setattr(run_module, "MAX_RETAINED_BYTES", 0)
    _code, report = run(suite, cases_dir(*chosen), tmp_path)
    assert report["verdict"] == "aborted"
    assert report["claim"]["verdict"] == "not-interoperable"
