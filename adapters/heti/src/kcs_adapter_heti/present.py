"""acdc.present through heti's public disclose (heti.anchored.produce.disclosing; this.i 9fg9ufsm).

The held ACDC is first judged by heti's own verifier, through this adapter's acdc.verify path with
the held ACDC as the one presented, and whatever heti does not find valid is refused: a holder
refuses to present what a verifier would refuse (adapter protocol, acdc.present). The form then
goes to heti's ``disclose``:

- **compact** and **partial** conceal the top-level blocks the form hides. heti conceals only the
  attribute section (``conceal=("a",)``), so a form that would compact an edge or rules section is
  refused with that reason rather than compacted by the adapter.
- **selective** reveals the aggregate's blocks by their indices in ``A``, each label mapped to the
  block that carries it. heti always reveals the issuee block (index 1) as well (its tick 4gnp),
  and an ACDC with no aggregate is refused by heti.
- **expanded**, and a partial form that hides nothing, answer the held body unchanged: the held
  ACDC is already fully expanded, and heti's disclose refuses a reduction that reduces nothing.
  A block held only as its SAID cannot be expanded by its holder, so an expanded form of an ACDC
  holding one is refused.

The protocol's own rules about the disclosure are applied before heti is asked: a partial path or
selective label that names no block, one named twice, and an empty selective list are refused. A
presentation carries no attachments, which the protocol allows. A form the protocol does not
define cannot be read, and is an error rather than a refusal.
"""

from heti.anchored.produce.disclosing import disclose

from kcs_adapter_heti import verify as v

FORMS = ("compact", "expanded", "partial", "selective")
BLOCKS = ("a", "e", "r")  # the top-level blocks a form compacts or expands
HETI_CONCEALS = ("a",)  # what heti's disclose can compact


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


def _hidden(sad: dict, given: dict) -> tuple[list[str], str | None]:
    """The top-level blocks a compact or partial form compacts, or a refusal."""
    present = [b for b in BLOCKS if isinstance(sad.get(b), dict)]
    if given["form"] == "compact":
        return present, None
    expand = given.get("expand", [])
    if not expand:
        return [], "a partial form must name at least one block to expand"
    if len(set(expand)) != len(expand):
        return [], "a partial form names a block twice"
    for path in expand:
        node, parts = sad, path.split(".")
        for part in parts:
            node = node.get(part) if isinstance(node, dict) else None
        if not isinstance(node, dict):
            return [], f"{path} names no block"
    kept = {path.split(".")[0] for path in expand}
    return [b for b in present if b not in kept], None


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
        compact = [b for b in BLOCKS if isinstance(sad.get(b), str)]
        if compact:  # a block held only as its SAID cannot be expanded by its holder
            return _refused(f"{compact[0]} is held only compact")
        return {"presented": {"stream": body.hex()}}
    if given["form"] == "selective":
        reveal, why = _selected(sad, given)
        if why:
            return _refused(why)
        conceal = []
    else:
        conceal, why = _hidden(sad, given)
        if why:
            return _refused(why)
        beyond = [b for b in conceal if b not in HETI_CONCEALS]
        if beyond:
            return _refused(f"heti's disclose cannot compact {beyond[0]}")
        if not conceal:
            return {"presented": {"stream": body.hex()}}
        reveal = []
    try:
        out = disclose(acdc=body, reveal=reveal, conceal=conceal)
    except Exception as exc:  # noqa: BLE001 - heti refuses a reduction it cannot make
        return _refused(f"heti refused the disclosure: {exc}")
    return {"presented": {"stream": bytes(out).hex()}}
