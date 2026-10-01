"""Every error code the adapter emits follows the Bakobo grammar
<sorter>.<descriptor>[.<sub>...].<disposition> (bakobo/dev standards/error-codes.md)."""

import re
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src" / "kcs_adapter_keripy"
CANDIDATE = re.compile(r"\b[ew]\.[a-z0-9-]+(?:\.[a-z0-9-]+)+\b")
GRAMMAR = re.compile(r"[ew]\.(input|id|grant|feature|proof|party|state|env|self|rule)"
                     r"(\.[a-z0-9]+(?:-[a-z0-9]+)*)+\.[fr]")


def codes():
    found = set()
    for path in SRC.glob("*.py"):
        found.update(CANDIDATE.findall(path.read_text()))
    return found


def test_the_adapter_has_error_codes_to_check():
    assert len(codes()) >= 10


def test_every_code_follows_the_grammar():
    bad = sorted(c for c in codes() if not GRAMMAR.fullmatch(c) or c.split(".")[-2] in "fr")
    assert bad == []
