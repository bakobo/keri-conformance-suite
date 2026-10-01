"""Loading cases: every *.json under the cases directory, lightly checked at runtime, sorted by id.
A malformed case is a runner fault naming its file, never an adapter failure."""

import copy
import json

import pytest
from conftest import ROOT, assertion, make_case
from jsonschema import Draft202012Validator

from keri_conformance import errors
from keri_conformance.cases import case_problem, load_cases

SCHEMA = Draft202012Validator(
    json.loads((ROOT / "schema" / "case.schema.json").read_text(encoding="utf-8")))

STATE = {"sn": 0, "said": "EAbc", "keys": ["DAbc"], "kt": "1", "ndigs": ["EGhi"], "nt": "1",
         "wits": [], "bt": "0", "delegator": None}

GOOD = [
    make_case("CESR-0001", "cesr.parse", {"stream": "2d4b"}, [assertion("rejected")]),
    make_case("CESR-0002", "cesr.parse", {"stream": "00"}, [assertion("decoded", expected=[])]),
    make_case("CESR-0003", "cesr.encode", {"code": "E", "raw": "00", "domain": "text"},
              [assertion("encoded", expected="10")]),
    make_case("KERI-0001", "keri.process",
              {"perspective": {"role": "validator"},
               "messages": [{"stream": "7b7d", "source": "controller"}]},
              [assertion("disposition", message=0, phase="initial", expected="accepted"),
               assertion("key_state", name="a2", level="SHOULD", aid="EAbc", expected=STATE)],
              reference={"implementation": "keripy", "commit": "9a8b7aa"}),
    make_case("KERI-0002", "keri.emit", {"event": {"t": "icp"}, "seeds": {"DAbc": "00"}},
              [assertion("emitted_body", expected="7b7d"),
               assertion("signatures_verify", name="a2"),
               assertion("attachments_equivalent", name="a3", expected=[])]),
    make_case("CESR-0004", "cesr.parse", {"stream": ""}, [assertion("rejected")],
              status="deprecated"),
    make_case("CESR-0005", "cesr.parse", {"stream": ""},
              [{"id": "a1", "check": "rejected", "level": "INTEROP", "basis": "keripy 1.x"}],
              status="disputed"),
]


@pytest.mark.parametrize("case", GOOD, ids=[c["id"] for c in GOOD])
def test_hand_built_cases_satisfy_the_schema_and_the_runtime_check(case):
    assert list(SCHEMA.iter_errors(case)) == []
    assert case_problem(case) is None


def broken(mutate):
    case = copy.deepcopy(GOOD[3])
    mutate(case)
    return case


def set_(path, value):
    def mutate(case):
        target = case
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
    return mutate


def delete(path):
    def mutate(case):
        target = case
        for key in path[:-1]:
            target = target[key]
        del target[path[-1]]
    return mutate


BROKEN = {
    "not an object": lambda case: case.clear(),
    "missing id": delete(["id"]),
    "schema version": set_(["schema_version"], 2),
    "schema version bool": set_(["schema_version"], True),
    "bad id": set_(["id"], "KERI-1"),
    "bad status": set_(["status"], "retired"),
    "bad profile": set_(["profile"], 3),
    "targets not object": set_(["targets"], []),
    "features not list": set_(["targets", "features"], "kel.basic"),
    "feature not string": set_(["targets", "features"], [1]),
    "bad operation": set_(["operation"], "keri.fly"),
    "input not object": set_(["input"], []),
    "input carries id": set_(["input", "id"], 5),
    "input carries op": set_(["input", "op"], "hello"),
    "assertions empty": set_(["assertions"], []),
    "assertions not list": set_(["assertions"], {}),
    "assertion not object": set_(["assertions", 0], "a1"),
    "assertion id": set_(["assertions", 0, "id"], 1),
    "assertion check": set_(["assertions", 0, "check"], "vibes"),
    "assertion level": set_(["assertions", 0, "level"], "MIGHT"),
    "assertion missing field": delete(["assertions", 0, "phase"]),
    "message not int": set_(["assertions", 0, "message"], "0"),
    "message negative": set_(["assertions", 0, "message"], -1),
    "message bool": set_(["assertions", 0, "message"], True),
    "phase": set_(["assertions", 0, "phase"], "middle"),
    "key state not object": set_(["assertions", 1, "expected"], []),
    "key state missing field": delete(["assertions", 1, "expected", "bt"]),
    "aid not string": set_(["assertions", 1, "aid"], 3),
    "duplicate assertion id": set_(["assertions", 1, "id"], "a1"),
    "provenance not object": set_(["provenance"], None),
    "reference not object": set_(["provenance", "reference"], "keripy"),
    "reference implementation": set_(["provenance", "reference", "implementation"], 3),
}


@pytest.mark.parametrize("name", list(BROKEN))
def test_each_malformation_is_described(name):
    case = broken(BROKEN[name])
    problem = case_problem(case)
    assert isinstance(problem, str) and problem.endswith("."), name


def test_every_check_the_runner_knows_is_loadable():
    from keri_conformance.assertions import CHECKS, CRYPTO_CHECKS
    from keri_conformance.cases import CHECK_FORMS

    assert set(CHECK_FORMS) == set(CHECKS) | set(CRYPTO_CHECKS)


def test_an_unhashable_check_is_described():
    case = broken(set_(["assertions", 0, "check"], ["decoded"]))
    assert "check" in case_problem(case)


def test_a_case_that_is_not_an_object_is_described():
    assert case_problem(["x"]) == "It is not a JSON object."


def test_load_cases_reads_recursively_and_sorts_by_id(cases_dir):
    directory = cases_dir(*reversed(GOOD))
    (directory / "README.txt").write_text("not a case")
    loaded = load_cases(directory)
    assert [c["id"] for c in loaded] == sorted(c["id"] for c in GOOD)


def test_a_missing_cases_directory_is_a_fault(tmp_path):
    with pytest.raises(errors.RunnerError) as info:
        load_cases(tmp_path / "nope")
    assert info.value.code == errors.E_CASES_MISSING
    assert info.value.exit_code == errors.EXIT_FAULT


def test_a_malformed_case_names_its_file(cases_dir):
    directory = cases_dir(GOOD[0], broken(set_(["status"], "retired")))
    with pytest.raises(errors.RunnerError) as info:
        load_cases(directory)
    assert info.value.code == errors.E_CASE_FORMAT
    assert "KERI-0001.json" in str(info.value)
    assert "status" in str(info.value)


@pytest.mark.parametrize("content", [b"{not json", b"\xff\xfe", b"[" * 100000])
def test_unparseable_case_files_are_faults(cases_dir, content):
    directory = cases_dir()
    (directory / "bad.json").write_bytes(content)
    with pytest.raises(errors.RunnerError) as info:
        load_cases(directory)
    assert info.value.code == errors.E_CASE_FORMAT
    assert "bad.json" in str(info.value)


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_non_finite_numbers_in_a_case_file_are_faults(cases_dir, constant):
    directory = cases_dir()
    text = json.dumps(GOOD[0]).replace('"schema_version": 1', f'"schema_version": {constant}')
    (directory / "nan.json").write_text(text)
    with pytest.raises(errors.RunnerError) as info:
        load_cases(directory)
    assert info.value.code == errors.E_CASE_FORMAT
    assert constant in str(info.value)


def test_an_oversized_case_file_is_a_fault(cases_dir):
    directory = cases_dir(GOOD[0])
    with pytest.raises(errors.RunnerError) as info:
        load_cases(directory, max_bytes=100)
    assert "100 bytes" in str(info.value)


def test_an_unreadable_case_file_is_a_final_fault(cases_dir):
    directory = cases_dir(GOOD[0])
    path = next(directory.rglob("*.json"))
    path.chmod(0)
    try:
        with pytest.raises(errors.RunnerError) as info:
            load_cases(directory)
    finally:
        path.chmod(0o644)
    assert info.value.code == errors.E_CASE_READ
    assert info.value.code.endswith(".f")
    assert path.name in str(info.value)


def test_a_transient_read_error_is_retryable(cases_dir, monkeypatch):
    import errno
    import pathlib

    directory = cases_dir(GOOD[0])

    def broken_open(self, *args, **kwargs):
        raise OSError(errno.EIO, "Input/output error")

    monkeypatch.setattr(pathlib.Path, "open", broken_open)
    with pytest.raises(errors.RunnerError) as info:
        load_cases(directory)
    assert info.value.code == errors.E_CASE_READ_TRANSIENT
    assert info.value.code.endswith(".r")
    assert "Input/output error" in str(info.value)


def test_duplicate_case_ids_are_a_fault(cases_dir):
    directory = cases_dir(GOOD[0])
    (directory / "copy.json").write_text(json.dumps(GOOD[0]))
    with pytest.raises(errors.RunnerError) as info:
        load_cases(directory)
    assert "CESR-0001" in str(info.value)
    assert "copy.json" in str(info.value)


# --- bounded discovery ----------------------------------------------------------------------------


def test_case_discovery_stops_at_the_file_count_limit(cases_dir):
    directory = cases_dir(GOOD[0], GOOD[1], GOOD[2])
    assert len(load_cases(directory, max_files=3)) == 3
    with pytest.raises(errors.RunnerError) as info:
        load_cases(directory, max_files=2)
    assert info.value.code == errors.E_CASES_COUNT
    assert "2" in str(info.value)


def test_case_discovery_stops_at_the_byte_limit_before_reading(cases_dir):
    directory = cases_dir(GOOD[0], GOOD[1])
    (directory / "zz-broken.json").write_text("{not json")  # never read: the limit trips first
    total = sum(p.stat().st_size for p in directory.rglob("*.json"))
    with pytest.raises(errors.RunnerError) as info:
        load_cases(directory, max_total_bytes=total - 1)
    assert info.value.code == errors.E_CASES_BYTES
    assert str(total - 1) in str(info.value)


def test_the_count_limit_also_trips_before_reading(cases_dir):
    directory = cases_dir(GOOD[0])
    (directory / "a-broken.json").write_text("{not json")
    with pytest.raises(errors.RunnerError) as info:
        load_cases(directory, max_files=1)
    assert info.value.code == errors.E_CASES_COUNT


@pytest.mark.parametrize(("number", "code"), [(5, "E_CASE_READ_TRANSIENT"), (13, "E_CASE_READ")])
def test_a_failure_to_size_a_case_file_is_coded(cases_dir, monkeypatch, number, code):
    from keri_conformance import cases as cases_module

    directory = cases_dir(GOOD[0])

    def broken(_path):
        raise OSError(number, "cannot stat")

    monkeypatch.setattr(cases_module.os.path, "getsize", broken)
    with pytest.raises(errors.RunnerError) as info:
        load_cases(directory)
    assert info.value.code == getattr(errors, code)


def test_duplicate_assertion_ids_are_found_wherever_they_are():
    case = copy.deepcopy(GOOD[4])
    case["assertions"][2]["id"] = "a1"
    assert case_problem(case) == 'Its assertion id "a1" is used twice.'
