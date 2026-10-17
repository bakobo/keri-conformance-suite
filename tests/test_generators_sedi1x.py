"""The sedi-1x-interop companion (test-plan item 11; this.i 9sgwng6m): keripy 1.x issuances the
suite builds, and the cases made from them. generators/keripy1x_check/check_acdc.py checks the
committed cases against keripy 1.2.14 itself; these tests hold the builder to the 1.x wire it
transcribes, so a change cannot drift from it unnoticed."""

import json
import os
import pathlib

import pytest

from generators.spec_tables import keri_events as ke
from generators.spec_tables import keripy1x_issue as k1
from generators.spec_tables import regenerate, sedi1x_cases, spec_source, tables
from generators.spec_tables.errors import ScenarioError

ROOT = pathlib.Path(__file__).resolve().parent.parent
try:
    CESR_TEXT = spec_source.load_spec()
except spec_source.SpecUnavailable as e:
    if os.environ.get("KCS_REQUIRE_SPEC") == "1":
        raise
    pytest.skip(f"a pinned specification text is unavailable: {e}", allow_module_level=True)

T = tables.load(CESR_TEXT)
SCHEMA = {"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object"}


def spec(*credentials, **over):
    return {"issuer": "I", "roles": ["I", "H"], "schemas": {"S": SCHEMA},
            "credentials": list(credentials) or [{"name": "c", "schema": "S", "issuee": "H",
                                                  "attributes": {"name": "Zoe"}}], **over}


def issuance_of_spec():
    return k1.Issuance(T, spec())


def frames(stream_hex: str) -> tuple[dict, str]:
    raw = bytes.fromhex(stream_hex)
    size = int(raw[16:22], 16)
    return json.loads(raw[:size]), raw[size:].decode()


def test_a_1x_issuance_is_a_kel_a_vcp_iss_registry_and_an_acdc_each_anchored():
    request = k1.Issuance(T, spec()).request("c")
    kel = [frames(k["stream"]) for k in request["kels"]]
    assert [(b["t"], k["source"]) for (b, _), k in zip(kel, request["kels"])] == [
        ("icp", "I"), ("icp", "H"), ("ixn", "I"), ("ixn", "I")]
    for body, attached in kel:
        assert body["v"].startswith("KERI10JSON") and body["v"].endswith("_")
        assert attached.startswith("-AAB") and len(attached) == 4 + 88
    vcp, iss = (frames(r["stream"]) for r in request["registry"])
    assert vcp[0]["t"] == "vcp" and vcp[0]["d"] == vcp[0]["i"] and vcp[0]["c"] == ["NB"]
    assert iss[0]["t"] == "iss" and iss[0]["ri"] == vcp[0]["i"] and iss[0]["dt"] == k1.STAMP
    # Each registry event names the interaction that seals it, and that interaction seals it.
    for (event, couple), (ixn, _) in zip((vcp, iss), kel[2:]):
        assert couple == "-GAB" + k1._seqner(T, int(ixn["s"], 16)) + ixn["d"]
        assert ixn["a"] == [{"i": event["i"], "s": event["s"], "d": event["d"]}]
    acdc, triple = frames(request["presented"]["stream"])
    assert list(acdc) == ["v", "d", "i", "ri", "s", "a"] and acdc["v"].startswith("ACDC10JSON")
    assert triple == "-IAB" + acdc["d"] + k1._seqner(T, 0) + iss[0]["d"]
    assert acdc["a"]["i"] == kel[1][0]["i"] and "dt" not in acdc["a"]
    # The SAID is over the expanded form, with the attribute block's own SAID inside it.
    dummied = {**acdc, "d": k1.DUMMY}
    assert acdc["d"] == ke.digest(T, k1._json(dummied))
    assert acdc["a"]["d"] == ke.digest(T, k1._json({**acdc["a"], "d": k1.DUMMY}))
    assert request["acdcs"] == [] and request["perspective"] == {"role": "validator"}
    # Cut at the last event of each: the issuer at its second interaction, the holder at its
    # inception, the registry at its inception and the credential at its issuance.
    assert sorted(issuance_of_spec().as_of.values()) == [0, 0, 0, 2]


def test_edges_nested_blocks_dt_revocation_and_the_registry_nonce_are_written_as_asked():
    far = {"name": "far", "schema": "S", "attributes": {"name": "A"}}
    near = {"name": "near", "schema": "S", "issuee": "H", "dt": k1.STAMP, "revoked": True,
            "attributes": {"given": {"u": "0A" + "A" * 22, "value": "Zoe"}},
            "edges": {"agent": {"credential": "far", "u": "0A" + "B" * 22, "o": "NI2I"},
                      "plain": {"credential": "far"}},
            "edges_u": "0A" + "C" * 22}
    issuance = k1.Issuance(T, spec(far, near, registry="other"))
    request = issuance.request("near")
    acdc, _ = frames(request["presented"]["stream"])
    assert acdc["a"]["dt"] == k1.STAMP
    assert list(acdc["a"]["given"]) == ["d", "u", "value"]
    edges = acdc["e"]
    assert list(edges) == ["d", "u", "agent", "plain"]
    assert list(edges["agent"]) == ["d", "u", "n", "s", "o"]
    assert edges["plain"] == {"n": issuance.saids["far"], "s": issuance.saids["far.schema"]}
    assert [frames(r["stream"])[0]["t"] for r in request["registry"]] == [
        "vcp", "iss", "iss", "rev"]
    assert request["acdcs"] == [{"stream": issuance.acdcs["far"].hex()}]
    plain = k1.Issuance(T, spec(far, near))
    assert plain.saids["registry"] != issuance.saids["registry"]


@pytest.mark.parametrize("credentials,presented,words", [
    ([{"name": "c", "schema": "X"}], "c", "does not define"),
    ([{"name": "c", "schema": "S", "edges": {"e": {"credential": "d"}}},
      {"name": "d", "schema": "S"}], "c", "not issued before it"),
    ([{"name": "c", "schema": "S"}], "x", "does not issue"),
])
def test_a_spec_the_builder_cannot_follow_is_refused(credentials, presented, words):
    with pytest.raises(ScenarioError, match=words):
        k1.Issuance(T, spec(*credentials)).request(presented)


# -- the cases

CORE = json.loads((ROOT / "interop/two-wallets/schemas/sedi-core-1x.schema.json").read_text())


def test_the_2x_shape_runs_the_1x_profile_mapping_backwards():
    shaped = sedi1x_cases.two_x(CORE)
    assert shaped["required"] == ["v", "d", "i", "rd", "s", "a", "e", "r"]
    assert list(shaped["properties"])[:6] == ["v", "t", "d", "u", "i", "rd"]
    assert "ri" not in shaped["properties"]
    assert shaped["properties"]["rd"] == CORE["properties"]["ri"]
    assert CORE["required"] == ["v", "d", "i", "ri", "s", "a"]  # the original is untouched


LIBRARY = {"core": {"copy_of": "x", "schema": CORE}}


def test_schema_options_name_dt_and_drop_the_section_u():
    out = sedi1x_cases._schemas(LIBRARY, {"a": {"from": "core", "allow_dt": True,
                                                "edge_section_u": False}, "b": SCHEMA})
    assert "$id" not in out["a"] and out["b"] is SCHEMA
    assert "dt" in out["a"]["properties"]["a"]["oneOf"][1]["properties"]
    assert "u" not in out["a"]["properties"]["e"]["oneOf"][1]["required"]
    assert "$id" in CORE and "dt" not in CORE["properties"]["a"]["oneOf"][1]["properties"]
    with pytest.raises(ScenarioError, match="schemas table does not hold"):
        sedi1x_cases._schemas(LIBRARY, {"a": {"from": "nope"}})


def test_each_shared_schema_is_the_committed_file_it_copies():
    for path in sorted((ROOT / "scenarios/sedi1x").glob("*.json")):
        for entry in json.loads(path.read_text()).get("schemas", {}).values():
            assert entry["schema"] == json.loads((ROOT / entry["copy_of"]).read_text())


CASE = {"id": "ACDC-0901", "key": "SX-01", "title": "t", "description": "d.", "fixture": "f",
        "presented": "c", "expected": "valid", "basis": "it saves it.", "triage": "None."}


def test_a_case_is_an_interop_verdict_with_keripys_basis():
    out = sedi1x_cases.build_case(T, "scenarios/sedi1x/x.json", {"f": spec()},
                                  {**CASE, "expected": "invalid", "pair": "SX-00"},
                                  {"SX-00": "ACDC-0900"})
    assert out["profile"] == "sedi-1x-interop" and out["operation"] == "acdc.verify"
    [a] = out["assertions"]
    assert (a["check"], a["expected"], a["level"]) == ("verdict", "invalid", "INTEROP")
    assert a["basis"].startswith("keripy 1.2.14 (commit bab95c16") and "it saves it." in a["basis"]
    assert out["description"].endswith("Its positive pair is SX-00 (ACDC-0900), which differs "
                                       "from it only in the defect.")
    assert out["provenance"]["scenario"] == "scenarios/sedi1x/x.json#SX-01"
    assert "acdc.keripy-1x" in out["targets"]["features"]
    assert out["dag"] == {"root": json.loads(bytes.fromhex(out["input"]["presented"]["stream"])
                                             .split(b"-IAB")[0])["d"], "edges": []}


def test_the_dag_holds_every_edge_reachable_from_the_presented_credential_once():
    far = {"name": "far", "schema": "S"}
    mid = {"name": "mid", "schema": "S", "edges": {"a": {"credential": "far"}}}
    near = {"name": "near", "schema": "S",
            "edges": {"b": {"credential": "mid"}, "c": {"credential": "far"}}}
    issuance = k1.Issuance(T, spec(far, mid, near))
    s = issuance.saids
    assert issuance.dag("near") == {"root": s["near"], "edges": [
        {"near": s["near"], "path": "e.b", "n": s["mid"]},
        {"near": s["near"], "path": "e.c", "n": s["far"]},
        {"near": s["mid"], "path": "e.a", "n": s["far"]}]}


@pytest.mark.parametrize("change,words", [
    (lambda c: c.pop("basis"), "needs"),
    (lambda c: c.update(extra=1), "unknown fields"),
    (lambda c: c.update(expected="revoked"), "not a verdict"),
    (lambda c: c.update(fixture="nope"), "not defined"),
    (lambda c: c.update(pair="SX-09"), "its pair"),
])
def test_a_malformed_case_is_refused(change, words):
    case = dict(CASE)
    change(case)
    with pytest.raises(ScenarioError, match=words):
        sedi1x_cases.build_case(T, "x", {"f": spec()}, case, {})


@pytest.fixture
def tree(tmp_path):
    (tmp_path / "scenarios/sedi1x").mkdir(parents=True)
    return tmp_path


def write(tree, cases, profile="sedi-1x-interop"):
    (tree / "scenarios/sedi1x/t.json").write_text(json.dumps(
        {"profile": profile, "fixtures": {"f": spec()}, "cases": cases}))


def test_the_companions_cases_are_generated_into_their_profile(tree):
    write(tree, [CASE, {**CASE, "id": "ACDC-0902", "key": "SX-02", "expected": "invalid",
                        "pair": "SX-01"}])
    files, members = {}, {"sedi-1x-interop": []}
    regenerate._generate_sedi1x(tree, files, members, T)
    assert sorted(files) == ["cases/sedi1x/ACDC-0901.json", "cases/sedi1x/ACDC-0902.json"]
    assert members["sedi-1x-interop"] == ["ACDC-0901", "ACDC-0902"]


@pytest.mark.parametrize("cases,profile,existing,words", [
    ([CASE], "sedi-1", {}, "unknown profile"),
    ([{**CASE, "id": "X-1"}], "sedi-1x-interop", {}, "ACDC-NNNN"),
    ([CASE], "sedi-1x-interop", {"cases/acdc/ACDC-0901.json": b""}, "used twice"),
    ([{**CASE, "expected": "maybe"}], "sedi-1x-interop", {}, "not a verdict"),
    ([{**CASE, "fixture": "nope"}], "sedi-1x-interop", {}, "not defined"),
    ([{**CASE, "presented": "nope"}], "sedi-1x-interop", {}, "does not issue"),
])
def test_a_bad_companion_scenario_is_refused(tree, cases, profile, existing, words):
    write(tree, cases, profile)
    with pytest.raises(ScenarioError, match=words):
        regenerate._generate_sedi1x(tree, dict(existing), {"sedi-1x-interop": []}, T)


def test_a_case_whose_spec_breaks_the_builder_is_named(tree):
    (tree / "scenarios/sedi1x/t.json").write_text(json.dumps(
        {"profile": "sedi-1x-interop", "fixtures": {"f": {"issuer": "I", "schemas": {}}},
         "cases": [CASE]}))
    with pytest.raises(ScenarioError, match="ACDC-0901: KeyError"):
        regenerate._generate_sedi1x(tree, {}, {"sedi-1x-interop": []}, T)


def test_the_committed_companion_is_what_its_scenario_generates():
    files, members = {}, {"sedi-1x-interop": []}
    regenerate._generate_sedi1x(ROOT, files, members, T)
    for path, data in files.items():
        assert (ROOT / path).read_bytes() == data
    profile = json.loads((ROOT / "profiles/sedi-1x-interop.json").read_text())
    assert profile["cases"] == members["sedi-1x-interop"] and not profile["normative"]
