"""Install-and-invoke smoke: the installed `kcs` entry point runs `run` and `check-adapter` against
the good fake adapter and a temporary directory of hand-built cases that satisfy the case schema."""

import json
import pathlib
import shlex
import subprocess
import sys

from conftest import ROOT, assertion, good, make_case
from jsonschema import Draft202012Validator

KCS = pathlib.Path(sys.executable).parent / "kcs"
SCHEMA = Draft202012Validator(
    json.loads((ROOT / "schema" / "case.schema.json").read_text(encoding="utf-8")))

CASES = [
    make_case("CESR-0001", "cesr.parse", {"stream": "2d4b"}, [assertion("rejected")],
              features=["cesr.genus-2.00"]),
    make_case("CESR-0002", "cesr.encode", {"code": "E", "raw": "00", "domain": "text"},
              [assertion("encoded", expected="10")]),
    make_case("KERI-0001", "keri.process",
              {"perspective": {"role": "validator"},
               "messages": [{"stream": "7b7d", "source": "controller"}]},
              [assertion("disposition", message=0, phase="initial", expected="seen")],
              features=["kel.basic"]),
]


def test_the_smoke_cases_satisfy_the_case_schema():
    for case in CASES:
        assert list(SCHEMA.iter_errors(case)) == [], case["id"]


def test_installed_kcs_run(cases_dir, tmp_path):
    assert KCS.exists(), "kcs is not installed in this environment; run via `uv run pytest`"
    cases = cases_dir(*CASES)
    report = tmp_path / "report.json"
    out = subprocess.run([str(KCS), "run", "--adapter", shlex.join(good()), "--suite", str(ROOT),
                          "--cases", str(cases), "--report", str(report)],
                         capture_output=True, text=True, timeout=60, check=False)
    assert out.returncode == 0, out.stderr
    assert "verdict: conformant" in out.stdout
    data = json.loads(report.read_text())
    assert [c["outcome"] for c in data["cases"]] == ["pass", "pass", "pass"]


def test_installed_kcs_check_adapter():
    out = subprocess.run([str(KCS), "check-adapter", shlex.join(good()), "--suite", str(ROOT)],
                         capture_output=True, text=True, timeout=60, check=False)
    assert out.returncode == 0, out.stderr
    assert "pass  id-echo" in out.stdout
