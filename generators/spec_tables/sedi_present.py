"""sedi-1's holder: what a holder must present for a disclosure, or why it must refuse
(choice holder-presents; docs/adapter-protocol.md, acdc.present).

A disclosure is read against the held ACDC as the bundle gives it:

- ``compact`` needs nothing more, and ``expanded`` needs every block held expanded;
- ``partial`` names label paths from the top level (``a``, ``e``, ``e.le``); each names a SAIDed
  block of the held ACDC, and is expanded with the blocks that contain it, while every other
  block is compacted to its SAID. A path that names nothing or a block held only compact, a path
  named twice and an empty list are refused;
- ``selective`` names attribute labels of the aggregate ``A``; each names exactly one blinded
  attribute block, which is disclosed, while every other block is left as its blinded SAID. A
  label that names no block, one named twice, an empty list and an ACDC with no aggregate are
  refused.

The answer is a form acdc_build can present (so the expected body comes from the same builder
that made the held one), or the reason for a refusal. The secrets a presentation must not carry
are the strings of the held ACDC, other than its version string, that the expected presentation
does not carry, at least eight characters long so that a search for them cannot match by chance.
"""

import json

from . import acdc_saids as sa

MIN_SECRET = 8
BLOCK_FIELDS = ("d", "u")


def _paths(node, prefix: str = "") -> dict[str, object]:
    """Every map value of ``node`` by its label path, with nested maps' values below it."""
    out = {}
    for key, value in node.items():
        path = f"{prefix}{key}"
        out[path] = value
        if isinstance(value, dict):
            out.update(_paths(value, f"{path}."))
    return out


def _labels(block) -> list[str]:
    return [k for k in block if k not in BLOCK_FIELDS] if isinstance(block, dict) else []


def form(held: dict, expanded: dict, disclosure: dict) -> tuple[object, str | None]:
    """The acdc_build form that presents ``held`` as ``disclosure`` asks, or None and why a
    holder refuses; ``expanded`` is the ACDC with every block expanded, which a holder can
    present only if it holds every block so."""
    kind = disclosure["form"]
    if kind == "compact":
        return kind, None
    if kind == "expanded":
        if {k: v for k, v in held.items() if k != "v"} != {
                k: v for k, v in expanded.items() if k != "v"}:
            return None, "the expanded form of an ACDC with a block held only compact"
        return kind, None
    if kind == "partial":
        named = disclosure["expand"]
        if not named:
            return None, "an empty choice"
        if len(set(named)) != len(named):
            return None, "a path named twice"
        paths = _paths({k: v for k, v in held.items() if k not in ("v", "d")})
        for path in named:
            if path not in paths:
                return None, f"{path} names nothing"
            if not sa.is_saided(paths[path]):
                return None, f"{path} names a block held only compact"
        keep = {p for path in named for p in _ancestors(path)}
        compact = [p for p, value in paths.items()
                   if sa.is_saided(value) and p not in keep and _parent_kept(p, keep)]
        return {"compact": sorted(compact)}, None
    named = disclosure["disclose"]
    blocks = held.get("A")
    if not isinstance(blocks, list):
        return None, "a selective form of an ACDC with no aggregate"
    if not named:
        return None, "an empty choice"
    if len(set(named)) != len(named):
        return None, "a label named twice"
    index = {}
    for i, block in enumerate(blocks[1:]):
        for label in _labels(block):
            index.setdefault(label, []).append(i)
    disclose = []
    for label in named:
        if len(index.get(label, [])) != 1:
            return None, f"{label} names no single block"
        disclose.append(index[label][0])
    return {"disclose": sorted(disclose)}, None


def _ancestors(path: str) -> list[str]:
    parts = path.split(".")
    return [".".join(parts[:n]) for n in range(1, len(parts) + 1)]


def _parent_kept(path: str, keep: set[str]) -> bool:
    """A block is compacted where it stands, so only one whose parent is shown expanded."""
    parent = path.rpartition(".")[0]
    return not parent or parent in keep


def secrets(held: dict, presented: dict) -> list[str]:
    """The held ACDC's strings that the presentation must not carry."""
    shown = json.dumps(presented)
    found = []

    def walk(value):
        if isinstance(value, dict):
            for v in value.values():
                walk(v)
        elif isinstance(value, list):
            for v in value:
                walk(v)
        elif isinstance(value, str) and len(value) >= MIN_SECRET and value not in shown:
            found.append(value)

    # The version string sizes the held form, so it differs from the presented one's and
    # discloses nothing.
    walk({k: v for k, v in held.items() if k != "v"})
    return sorted(set(found))
