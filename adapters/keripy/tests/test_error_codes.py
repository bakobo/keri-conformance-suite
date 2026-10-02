"""Every error code the adapter emits follows the Bakobo grammar
<sorter>.<descriptor>[.<sub>...].<disposition> (bakobo/dev standards/error-codes.md)."""

import ast
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


def _code_strings(tree):
    """Every string constant in tree that contains an error code, with its parent node."""
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    for node in ast.walk(tree):
        if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                and CANDIDATE.search(node.value)):
            yield node, parents.get(node)


def test_codes_appear_only_as_module_scope_constant_assignments():
    offenders = []
    for path in sorted(SRC.glob("*.py")):
        tree = ast.parse(path.read_text())
        for node, parent in _code_strings(tree):
            ok = (isinstance(parent, ast.Assign) and parent in tree.body
                  and parent.value is node and len(parent.targets) == 1
                  and isinstance(parent.targets[0], ast.Name)
                  and parent.targets[0].id.isupper()
                  and GRAMMAR.fullmatch(node.value))
            if not ok:
                offenders.append(f"{path.name}:{node.lineno}")
    assert offenders == []
