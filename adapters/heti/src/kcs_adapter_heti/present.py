"""acdc.present through heti's public disclose (heti.anchored.produce.disclosing; this.i 9fg9ufsm).

The held ACDC is first judged by heti's own verifier, through this adapter's acdc.verify path with
the held ACDC as the one presented, and whatever heti does not find valid is refused: a holder
refuses to present what a verifier would refuse (adapter protocol, acdc.present). The form then
goes to heti's ``disclose``:

- **compact** and **partial** hide what the form hides, at every level a partial form names: the
  attribute section or one level of its sub-blocks (``conceal=("a",)`` or ``("a/<label>",)``).
  heti cannot compact an edge or rules section or any block inside one, or a block deeper in the
  attribute section, so a form that would is refused with that reason rather than compacted by
  the adapter; naming one edge of a section whose other edges must stay hidden is such a form.
- **selective** reveals the aggregate's blocks by their indices in ``A``, each label mapped to the
  block that carries it, and an ACDC with no aggregate is refused by heti.
- heti's disclose always reveals an aggregate's issuee block (its tick 4gnp), so a compact form of
  an aggregate, and a selective form that does not name the issuee, are refused: the adapter never
  answers with a presentation other than the one asked for.
- **expanded**, and a partial form that hides nothing, answer the held body unchanged: the held
  ACDC is already fully expanded, and heti's disclose refuses a reduction that reduces nothing.
  A block held only as its SAID (a section, an aggregate block or an edge) cannot be expanded by
  its holder, so an expanded form of an ACDC holding one is refused.

The protocol's own rules about the disclosure are applied before heti is asked: a partial path or
selective label that names no block, one named twice, and an empty selective list are refused. A
presentation carries no attachments, which the protocol allows. A form the protocol does not
define cannot be read, and is an error rather than a refusal.
"""

from heti.anchored.produce.disclosing import disclose

from kcs_adapter_heti import verify as v

FORMS = ("compact", "expanded", "partial", "selective")
ISSUEE_INDEX = 1  # the aggregate's issuee block, which heti's disclose always reveals
ALWAYS_ISSUEE = ("heti's disclose always reveals the aggregate's issuee block, so it cannot "
                 "present a form that hides it")
SECTIONS = ("a", "A", "e", "r")  # the top-level sections a form compacts or expands
FIELDS = ("d", "u", "o")  # a block's own fields, never a sub-block

def _disclosure(request) -> dict:
    given = request.get("disclosure")
    if not isinstance(given, dict) or given.get("form") not in FORMS:
        raise v.Malformed(f'{v.E_MALFORMED}: "disclosure" must be an object whose "form" is one '
                          f"of {', '.join(FORMS)}.")
    for key in ("expand", "disclose"):
        if key in given and not (isinstance(given[key], list)
                                 and all(isinstance(x, str) for x in given[key])):
            raise v.Malformed(f'{v.E_MALFORMED}: "disclosure.{key}" must be a list of strings.')
    return given


def _held(request) -> bytes:
    held = request.get("held")
    stream = held.get("stream") if isinstance(held, dict) else None
    if not isinstance(stream, str) or not v.HEX.fullmatch(stream):
        raise v.Malformed(f'{v.E_MALFORMED}: "held" must be an object whose "stream" is a '
                          "lowercase hex string.")
    return bytes.fromhex(stream)


def _refused(reason: str) -> dict:
    return {"refused": {"reason": reason}}


def _sections(sad: dict) -> list[str]:
    return [b for b in SECTIONS if isinstance(sad.get(b), (dict, list))]


def _hide_beneath(node: dict, prefix: str, expand: list[str]) -> list[str]:
    """Every sub-block of ``node`` (at ``prefix``) a partial form hides: one no expand path names
    is hidden whole, one a path names exactly stays whole, and one only deeper paths name is
    descended into, so a sibling is hidden at every level. The paths are grouped by the child they
    run through once per level, so each is read once at each depth however many blocks there are."""
    depth = prefix.count(".") + 1
    through: dict[str, list[str]] = {}
    exact = set()
    for path in expand:
        parts = path.split(".")
        through.setdefault(parts[depth], []).append(path)
        if len(parts) == depth + 1:
            exact.add(parts[depth])
    hidden = []
    for label, block in node.items():
        if label in FIELDS or not isinstance(block, dict):
            continue
        if label not in through:
            hidden.append(f"{prefix}.{label}")
        elif label not in exact:
            hidden += _hide_beneath(block, f"{prefix}.{label}", through[label])
    return hidden


def _hidden(sad: dict, given: dict) -> tuple[list[str], str | None]:
    """Every block a compact or partial form hides, by its path (``a``, ``a.name``, ``A``,
    ``e``, ``e.le``), or a refusal. A section a partial form names whole stays whole; one it
    names only parts of has every other block, at every level, hidden."""
    sections = _sections(sad)
    if given["form"] == "compact":
        return sections, None
    expand = given.get("expand", [])
    if not expand:
        return [], "a partial form must name at least one block to expand"
    if len(set(expand)) != len(expand):
        return [], "a partial form names a block twice"
    for path in expand:
        node = sad
        for part in path.split("."):
            node = node.get(part) if isinstance(node, dict) else None
        if not isinstance(node, dict):
            return [], f"{path} names no block"
    hidden = []
    for section in sections:
        named = [p for p in expand if p == section or p.startswith(section + ".")]
        if not named:
            hidden.append(section)
        elif section not in named and isinstance(sad[section], dict):
            hidden += _hide_beneath(sad[section], section, named)
    return hidden, None


def _compact_inside(sad: dict) -> str | None:
    """The first block a holder holds only as its SAID, which it cannot expand: a whole section,
    an aggregate block, or an edge block."""
    for section in SECTIONS:
        if isinstance(sad.get(section), str):
            return section
    blocks = sad.get("A")
    if isinstance(blocks, list) and any(isinstance(b, str) for b in blocks[1:]):
        return "A"
    edges = sad.get("e")
    if isinstance(edges, dict):
        for label, block in edges.items():
            if label not in FIELDS and isinstance(block, str):
                return f"e.{label}"
    return None


def _issuee_block(sad: dict) -> bool:
    """Whether the aggregate's issuee block, A[1], is held disclosed: heti always reveals it."""
    blocks = sad.get("A")
    return isinstance(blocks, list) and len(blocks) > 1 and isinstance(blocks[1], dict)


def _selected(sad: dict, given: dict) -> tuple[list[int], str | None]:
    """The aggregate indices a selective form reveals, or a refusal."""
    labels = given.get("disclose", [])
    if not labels:
        return [], "a selective form must name at least one attribute"
    if len(set(labels)) != len(labels):
        return [], "a selective form names an attribute twice"
    section = sad.get("A")
    blocks = section[1:] if isinstance(section, list) else []
    index = {}
    for n, block in enumerate(blocks, start=1):
        if isinstance(block, dict):
            for label in block:
                if label not in ("d", "u"):
                    index.setdefault(label, n)
    missing = [label for label in labels if label not in index]
    if section is not None and missing:
        return [], f"{missing[0]} names no attribute block"
    return [index[label] for label in labels if label in index], None


def present(request) -> dict:
    given = _disclosure(request)
    held = _held(request)
    judged = v.verify({**{k: x for k, x in request.items() if k not in ("held", "disclosure")},
                       "presented": {"stream": held.hex()}})
    if judged["verdict"] != "valid":
        return _refused(f"heti does not find the held ACDC valid: {judged['reason']}")
    sad, raw, _attachments = v.split(held)
    body = v.GENUS + raw
    if given["form"] == "expanded":
        compact = _compact_inside(sad)
        if compact:  # a block held only as its SAID cannot be expanded by its holder
            return _refused(f"{compact} is held only compact")
        return {"presented": {"stream": body.hex()}}
    if given["form"] == "selective":
        reveal, why = _selected(sad, given)
        if why:
            return _refused(why)
        if ISSUEE_INDEX not in reveal and _issuee_block(sad):
            return _refused(ALWAYS_ISSUEE)
        conceal = []
    else:
        hidden, why = _hidden(sad, given)
        if why:
            return _refused(why)
        # heti conceals the attribute section or one level of its sub-blocks; it reduces an
        # aggregate only by revealing none of its blocks but the issuee's, which is not the form
        # asked for when the issuee block is hidden; and it cannot compact e or r.
        if "A" in hidden and _issuee_block(sad):
            return _refused(ALWAYS_ISSUEE)
        beyond = [h for h in hidden
                  if h not in ("A", "a") and not (h.startswith("a.") and h.count(".") == 1)]
        if beyond:
            return _refused(f"heti's disclose cannot compact {beyond[0]}")
        if not hidden:
            return {"presented": {"stream": body.hex()}}
        conceal = [h.replace(".", "/", 1) for h in hidden if h != "A"]
        reveal = []
    try:
        out = disclose(acdc=body, reveal=reveal, conceal=conceal)
    except Exception as exc:  # noqa: BLE001 - heti refuses a reduction it cannot make
        return _refused(f"heti refused the disclosure: {exc}")
    return {"presented": {"stream": bytes(out).hex()}}
