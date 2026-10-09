"""Cross-check the ACDC generator's primitives against keripy main, at a pinned commit.

Run from this directory, in its own pinned environment:

    uv run python check.py [--report PATH]

keripy is never the authority here (docs/design.md, ACDC, "Construction properties"). Every
fixture is computed twice, once by the generator (``generators/spec_tables``, standard library
only) under the readings docs/design.md fixes, and once by keripy, and the two are compared. A
disagreement is reported, with the generator's value under every candidate reading of the bytes
the text leaves open (``acdc_saids.CANDIDATES``: A-B1, A-B2, A-B3 and A-C1), so the report says
which choice explains it, if one does. It never changes an expected value; a maintainer records
it in ``generators/DISAGREEMENTS.md``.

Primitives and the keripy computation each is compared with:

- ``registry-said``: rip and bup SAIDs, against ``SerderACDC(sad=..., makify=True)``, and the
  generator's bytes must verify through ``SerderACDC(raw=..., verify=True)``;
- ``most-compact``: an ACDC's top-level SAID from each presented form (compact, expanded,
  partially disclosed, selectively disclosed), against ``SerderACDC(sad=..., makify=True)``, and
  the presented bytes must verify through ``SerderACDC(raw=..., verify=True)``;
- ``block-said``: every nested SAIDed block, against ``Compactor(mad=..., makify=True)`` compacted;
- ``schema-said``: against ``Schemer(sed=...)``, and the delivered bytes must load through
  ``Schemer(raw=...)``; a schema printed with whitespace probes A-B2;
- ``agid``: against ``Aggor(ael=..., makify=True, kind="JSON")``;
- ``blid``: the BLID and the block's text, against ``Blinder(crew=BlindState(...), makify=True)``;
- ``schema-validation``: the subset evaluator's verdict against ``Schemer.verify``, which runs the
  ``jsonschema`` library under the schema's declared dialect.

The fixtures are the pinned ACDC text's own worked examples and bundles the generator builds from
the fragments below.
"""

import argparse
import copy
import json
import pathlib
import sys
import warnings

warnings.filterwarnings("ignore")

from keri.core import mapping, scheming, serdering, structing
from keri.core.structing import BlindState

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from generators.spec_tables import acdc_build as ab
from generators.spec_tables import acdc_saids as sa
from generators.spec_tables import json_schema_subset as js
from generators.spec_tables import spec_source, tables
from generators.spec_tables.b64 import b64_to_int

KERIPY_COMMIT = "9a8b7aa70960f16fe7acffd8cf7901941ac912a1"
GENUS = b"-_AAACAA"
T = tables.load()
SPEC = spec_source.load_spec(pin=spec_source.ACDC).splitlines()

# -- fixtures -------------------------------------------------------------------------------------

DIALECT = js.DIALECT
S1 = {"$id": "", "$schema": DIALECT, "title": "S1", "version": "1.0.0", "type": "object",
      "required": ["v", "d", "i", "s", "a"],
      "properties": {
          "v": {"type": "string"}, "d": {"type": "string"}, "i": {"type": "string"},
          "s": {"type": "string"},
          "a": {"oneOf": [{"type": "string"},
                          {"type": "object", "required": ["d", "i", "name", "lei"],
                           "properties": {"name": {"type": "string"},
                                          "lei": {"type": "string"}}}]},
          "e": {"oneOf": [{"type": "string"}, {"type": "object"}]},
          "r": {"oneOf": [{"type": "string"}, {"$ref": "#/$defs/rules"}]}},
      "$defs": {"rules": {"type": "object", "required": ["d"],
                          "properties": {"d": {"type": "string"}}}}}


def _icp(aid, key):
    return {"name": f"{aid}icp", "aid": aid, "t": "icp", "keys": [key], "next": [key + "n"]}


def _base(acdcs, presented, seals, registries=()):
    events = [_icp("I", "i0"), _icp("H", "h0"), _icp("Q", "q0")]
    events += [{"name": f"ixn{n}", "aid": "I", "t": "ixn", "a": [s]}
               for n, s in enumerate(seals, start=1)]
    kels = [{"event": "Iicp", "sigs": ["i0"]}, {"event": "Hicp", "sigs": ["h0"]},
            {"event": "Qicp", "sigs": ["q0"]}]
    kels += [{"event": f"ixn{n}", "sigs": ["i0"]} for n in range(1, len(seals) + 1)]
    return {"events": events, "kels": kels, "schemas": [{"name": "S1", "schema": S1}],
            "registries": list(registries), "acdcs": acdcs, "presented": presented}


def _attrs(name, issuee="H", **extra):
    return {"d": "", "i": {"aid": issuee}, "name": name, "lei": "5493001KJTIIGC8Y1R12", **extra}


def fragments() -> dict[str, dict]:
    a1 = {"name": "A1", "issuer": "I", "schema": "S1", "a": _attrs("Zoe"), "source_seal": "ixn1"}
    frags = {}
    for form in ("compact", "expanded"):
        frags[f"direct-{form}"] = _base([{**a1, "form": form}], "A1", [{"acdc": "A1"}])
    nested = {**a1, "u": "private", "form": {"compact": ["a.inner"]},
              "a": _attrs("Zoe", inner={"d": "", "u": {"nonce": "n1"}, "role": "x"},
                          plain={"note": "kept expanded",
                                 "deep": {"d": "", "u": {"nonce": "n2"}, "k": 1}}),
              "r": {"d": "", "usage": {"d": "", "l": "Not for resale."}}}
    frags["nested-partial"] = _base([nested], "A1", [{"acdc": "A1"}])
    frags["nested-expanded"] = _base([{**nested, "form": "expanded"}], "A1", [{"acdc": "A1"}])
    frags["non-ascii"] = _base([{**a1, "a": _attrs("Zoë Doe"), "form": "expanded"}], "A1",
                               [{"acdc": "A1"}])
    chain = [
        {"name": "N", "issuer": "I", "schema": "S1", "a": _attrs("N"), "form": "expanded",
         "e": {"d": "", "le": {"d": "", "n": {"acdc": "F"}, "s": {"schema": "S1"}},
               "grp": {"o": "AND", "m": [{"d": "", "n": {"acdc": "F"}, "o": "NI2I"}]}}},
        {"name": "F", "issuer": "Q", "schema": "S1", "a": _attrs("F", issuee="I")},
    ]
    frags["edges"] = _base(chain, "N", [{"acdc": "N"}])
    sd = {**a1, "A": [{"d": "", "u": {"nonce": f"b{i}"}, "x": i} for i in range(3)],
          "form": {"disclose": [1]}}
    del sd["a"]
    frags["selective"] = _base([sd], "A1", [{"acdc": "A1"}])
    regs = [
        {"name": "rip1", "t": "rip", "issuer": "I", "u": "r1", "source_seal": "ixn1"},
        {"name": "bup1", "t": "bup", "registry": "rip1", "source_seal": "ixn2", "disclose": True,
         "state": {"u": "s1", "td": {"acdc": "A1"}, "ts": "issued"}},
        {"name": "bup2", "t": "bup", "registry": "rip1", "source_seal": "ixn3", "disclose": True,
         "state": {"u": "s2", "td": {"acdc": "A1"}, "ts": "revoked"}},
    ]
    reg_acdc = {k: v for k, v in a1.items() if k != "source_seal"}
    frags["registry"] = _base([{**reg_acdc, "registry": "rip1"}], "A1",
                              [{"registry": "rip1"}, {"registry": "bup1"}, {"registry": "bup2"}],
                              regs)
    return frags


def _json_at(line: int):
    depth, out = 0, []
    for text in SPEC[line - 1:]:
        out.append(text)
        depth += text.count("{") + text.count("[") - text.count("}") - text.count("]")
        if depth == 0:
            return json.loads("\n".join(out))
    raise ValueError(f"no JSON value opens on line {line}")


def _body(stream_hex: str) -> tuple[dict, bytes]:
    """A stream's body, framed by its version string's size field."""
    data = bytes.fromhex(stream_hex).removeprefix(GENUS)
    size = b64_to_int(data[20:24].decode())  # {"v":"ACDCCAACAAJSON then KKKK
    raw = data[:size]
    return json.loads(raw), raw


# -- comparison ------------------------------------------------------------------------------------

def _alternatives() -> list[tuple[str, sa.Readings]]:
    out = []
    for field, values in sa.CANDIDATES.items():
        for value in values[1:]:
            out.append((f"{field}={value}", sa.Readings(**{field: value})))
    return out


ALTERNATIVES = _alternatives()


class Report:
    def __init__(self):
        self.rows: list[dict] = []

    def compare(self, primitive, fixture, ours, keripy_value, mine_under=None, note=None):
        """Record one comparison. ``mine_under(readings)`` recomputes the generator's value under
        another reading, to explain a disagreement."""
        row = {"primitive": primitive, "fixture": fixture, "generator": ours,
               "keripy": keripy_value, "agree": ours == keripy_value}
        if mine_under is not None:
            # The generator's value under each other reading that changes it: the fixtures
            # that discriminate between readings, and which side keripy takes.
            alts = {name: _safe(mine_under, r) for name, r in ALTERNATIVES}
            row["alternatives"] = {n: v for n, v in alts.items() if v != ours}
            if not row["agree"]:
                row["explained_by"] = [n for n, v in alts.items() if v == keripy_value]
        if note:
            row["note"] = note
        self.rows.append(row)

    def keripy(self, primitive, fixture, thunk, ours=None, mine_under=None):
        try:
            value = thunk()
        except Exception as e:  # noqa: BLE001 - keripy refusing is itself a result to record
            value = f"keripy raised {type(e).__name__}: {e}"[:300]
        self.compare(primitive, fixture, ours, value, mine_under)


def _safe(fn, readings):
    try:
        return fn(readings)
    except Exception:  # noqa: BLE001 - a reading that cannot apply gives no value to compare
        return None


def _keripy_acdc_said(sad):
    work = copy.deepcopy(sad)
    return serdering.SerderACDC(sad=work, makify=True).said


def _keripy_verifies(raw):
    serdering.SerderACDC(raw=bytearray(raw), verify=True)
    return "verifies"


def _keripy_block(block):
    c = mapping.Compactor(mad=copy.deepcopy(block), makify=True, kind="JSON")
    c.compact()
    return c.said


def _blocks(value, path):
    """Every SAIDed block below a section, with its path, innermost first."""
    found = []
    if isinstance(value, dict):
        for k, v in value.items():
            found += _blocks(v, f"{path}.{k}")
        if sa.is_saided(value):
            found.append((path, value))
    elif isinstance(value, list):
        for i, v in enumerate(value):
            found += _blocks(v, f"{path}.{i}")
    return found


def spec_examples(rep: Report):
    for line in (2239, 2257, 2295, 2331, 2375, 3538, 3553):
        event = _json_at(line)
        rep.keripy("registry-said", f"spec line {line}",
                   lambda e=event: _keripy_acdc_said({**e, "d": ""}),
                   sa.said(T, event), lambda r, e=event: sa.said(T, e, readings=r))
    for line in (3679, 3707):
        acdc = _json_at(line)
        rep.keripy("most-compact", f"spec line {line}", lambda a=acdc: _keripy_acdc_said(a),
                   sa.acdc_said(T, acdc), lambda r, a=acdc: sa.acdc_said(T, a, r))
    preimage = _json_at(954)
    rep.keripy("agid", "spec line 954",
               lambda: mapping.Aggor(ael=list(preimage), makify=True, kind="JSON").agid,
               sa.agid(T, preimage[1:]), lambda r: sa.agid(T, preimage[1:], r))
    for line, u, td, ts in (
            (2167, "aG1lSjdJSNl7TiroPl67Uqzd5eFvzmr6bPlL7Lh4ukv8", "", ""),
            (2210, "aLfCdNAnc-0P2SiruarZSajXiUWu5iU2VfQahvpNCyzB",
             "EMLjZLIMlfUOoKox_sDwQaJO-0wdoGW0uNbmI28Wwc4M", "issued"),
            (2347, "aGx7b16vGHVPT56tX30kYOEzTwiVY4aabc4k9AawYyZG",
             "EMLjZLIMlfUOoKox_sDwQaJO-0wdoGW0uNbmI28Wwc4M", "revoked")):
        _blid(rep, f"spec line {line}", u, td, ts)
    schema = _json_at(3725)
    printed = "\n".join(SPEC[3724:3803]).encode()
    rep.keripy("schema-said", "spec line 3725", lambda: scheming.Schemer(sed=dict(schema)).said,
               sa.schema_said(T, schema), lambda r: sa.schema_said(T, schema, r, raw=printed))
    rep.keripy("schema-said", "spec line 3725, printed bytes",
               lambda: scheming.Schemer(raw=printed).said,
               sa.schema_said(T, schema, raw=printed),
               lambda r: sa.schema_said(T, schema, r, raw=printed))


def _blid(rep, fixture, u, td, ts):
    def keripy():
        b = structing.Blinder(crew=BlindState(d="", u=u, td=td, ts=ts), makify=True)
        return [b.blid, b.qb64]
    rep.keripy("blid", fixture, keripy,
               [sa.blid(T, u, td, ts), sa.blinded_block(T, u, td, ts)],
               lambda r: [sa.blid(T, u, td, ts, r), sa.blinded_block(T, u, td, ts, r)])


def generated(rep: Report):
    for fname, frag in fragments().items():
        b = ab.build_bundle(T, frag)
        req = b.request
        for name, form in b.forms.items():
            entry = req["presented"] if name == frag["presented"] else None
            fixture = f"{fname}/{name} ({_form_name(frag, name)})"
            rep.keripy("most-compact", fixture, lambda f=form: _keripy_acdc_said(f),
                       sa.acdc_said(T, form), lambda r, f=form: sa.acdc_said(T, f, r))
            if entry is not None:
                _, raw = _body(entry["stream"])
                rep.keripy("most-compact", f"{fixture}, presented bytes verify",
                           lambda r=raw: _keripy_verifies(r), "verifies")
            for section in ("a", "e", "r"):
                for path, block in _blocks(b.expanded[name].get(section), section):
                    rep.keripy("block-said", f"{fname}/{name} {path}",
                               lambda bl=block: _keripy_block(bl), sa.block_said(T, block),
                               lambda r, bl=block: sa.block_said(T, bl, r))
            if isinstance(b.expanded[name].get("A"), list):
                full = b.expanded[name]["A"]
                saids = [blk["d"] for blk in full[1:]]
                rep.keripy("agid", f"{fname}/{name}",
                           lambda s=saids: mapping.Aggor(ael=[sa.DUMMY] + s, makify=True,
                                                         kind="JSON").agid,
                           full[0], lambda r, s=saids: sa.agid(T, s, r))
        for entry in req["registry"]:
            body, raw = _body(entry["stream"])
            fixture = f"{fname}/{body['t']} n={body['n']}"
            rep.keripy("registry-said", fixture,
                       lambda bd=body: _keripy_acdc_said({**bd, "d": ""}), body["d"],
                       lambda r, bd=body: sa.said(T, bd, readings=r))
            rep.keripy("registry-said", f"{fixture}, bytes verify",
                       lambda rw=raw: _keripy_verifies(rw), "verifies")
        for spec in frag.get("registries", []):
            if spec["t"] == "bup":
                st = spec["state"]
                td = b.saids[st["td"]["acdc"]] if isinstance(st["td"], dict) else st["td"]
                _blid(rep, f"{fname}/{spec['name']}", ab.blind(T, st["u"]), td, st["ts"])
        for hexed in req["schemas"]:
            raw = bytes.fromhex(hexed)
            schema = json.loads(raw)
            rep.keripy("schema-said", f"{fname}/schema", lambda rw=raw: scheming.Schemer(raw=rw).said,
                       sa.schema_said(T, schema), lambda r, s=schema, rw=raw:
                       sa.schema_said(T, s, r, raw=rw))
    _validation(rep)


def _form_name(frag, name):
    spec = next(a for a in frag["acdcs"] if a["name"] == name)
    form = spec.get("form", "compact")
    return form if isinstance(form, str) else json.dumps(form, separators=(",", ":"))


def _validation(rep: Report):
    """The subset evaluator against keripy's Schemer.verify on valid and invalid instances."""
    frag = fragments()["direct-expanded"]
    b = ab.build_bundle(T, frag)
    schema = json.loads(bytes.fromhex(b.request["schemas"][0]))
    schemer = scheming.Schemer(sed=copy.deepcopy(schema))
    good = b.forms["A1"]
    a = good["a"]
    instances = {
        "expanded, valid": good,
        "compact, valid": b.forms["A1"] | {"a": sa.block_said(T, a)},
        "missing lei": good | {"a": {k: v for k, v in a.items() if k != "lei"}},
        "lei a number": good | {"a": a | {"lei": 5493001}},
        "missing s": {k: v for k, v in good.items() if k != "s"},
        "rules via local $ref, valid": good | {"r": {"d": "Exyz"}},
        "rules via local $ref, missing d": good | {"r": {"l": "x"}},
        "a is a number": good | {"a": 7},
        "both oneOf branches (a SAID string is a string only)": good | {"a": "Eabc"},
    }
    for label, inst in instances.items():
        def keripy(i=inst):
            try:
                return schemer.verify(raw=json.dumps(i).encode())
            except Exception:  # noqa: BLE001 - keripy raises its ValidationError for any refusal
                return False
        rep.compare("schema-validation", label, js.validate(schema, inst), keripy())


def summarize(rep: Report) -> list[str]:
    lines = [f"keripy {KERIPY_COMMIT}", "",
             "| primitive | fixtures | agree | disagree | explained by |",
             "|---|---|---|---|---|"]
    prims = list(dict.fromkeys(r["primitive"] for r in rep.rows))
    for p in prims:
        rows = [r for r in rep.rows if r["primitive"] == p]
        bad = [r for r in rows if not r["agree"]]
        why = sorted({e for r in bad for e in (r.get("explained_by") or ["unexplained"])})
        lines.append(f"| {p} | {len(rows)} | {len(rows) - len(bad)} | {len(bad)} | "
                     f"{', '.join(why) or '-'} |")
    lines += ["", ("Per open byte choice, over the fixtures where the reading changes the "
                   "generator's value:"), "",
              ("| reading | fixtures it changes | keripy matches the design's reading | "
               "keripy matches this reading |"), "|---|---|---|---|"]
    for name, _ in ALTERNATIVES:
        rows = [r for r in rep.rows if name in r.get("alternatives", {})]
        default = sum(r["keripy"] == r["generator"] for r in rows)
        alt = sum(r["keripy"] == r["alternatives"][name] for r in rows)
        lines.append(f"| {name} | {len(rows)} | {default} | {alt} |")
    lines.append("")
    for r in rep.rows:
        if not r["agree"]:
            lines.append(f"DISAGREES {r['primitive']} {r['fixture']}: generator "
                         f"{r['generator']!r}, keripy {r['keripy']!r}, explained by "
                         f"{r.get('explained_by') or 'nothing'}")
    return lines


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--report", type=pathlib.Path)
    args = ap.parse_args()
    rep = Report()
    spec_examples(rep)
    generated(rep)
    print("\n".join(summarize(rep)))
    if args.report:
        args.report.write_text(json.dumps({"keripy": KERIPY_COMMIT, "results": rep.rows},
                                          indent=2, ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
