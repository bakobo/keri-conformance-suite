"""Cross-check the CESR cases against keripy main's own Parser, at a pinned commit.

Run from this directory, in its own pinned environment:

    uv run python check.py [--report PATH]

keripy is never the authority here. A disagreement is reported for a maintainer to record in
``generators/DISAGREEMENTS.md``; it never changes an expected value.

Each stream goes through ``Parser.msgParsator`` (``src/keri/core/parsing.py``), framed, once per
message, exactly as keripy parses a stream: it handles a leading genus/version code, reaps and
verifies each body with ``Serdery`` (SAID, field set and version string, so an invalid body is
rejected), and extracts the attachments into ``MsgParseDom`` lists (``sigers``, ``wigers``,
``cigars``, ``tsgs``, ``frcs``). Nothing is reconstructed. What keripy reports is compared with
the same projection of the case's expected items: per message, its protocol, version,
serialization and size, then each attachment list in order with codes, index fields and raw
values. keripy's Parser reports no offsets, no count codes, no group ends and no genus items, so
those parts of a case are not cross-checked here at all; DISAGREEMENTS.md says so.

A case expected to be rejected agrees when ``msgParsator`` raises. If it yields (waits for more
bytes) on a framed stream, that is reported as ``keripy-waits``.
"""

import argparse
import json
import pathlib
import signal
import sys

from keri.core.coring import Matter
from keri.core.indexing import Indexer
from keri.core.parsing import Parser
from keri.kering import Vrsn_2_0

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from generators.spec_tables import tables

KERIPY_COMMIT = "9a8b7aa70960f16fe7acffd8cf7901941ac912a1"
TIMEOUT_SECONDS = 10
PROFILES = ("cesr-1.0", "cesr-strict", "keripy-1x-interop")


class Hang(Exception):
    pass


class Waits(Exception):
    pass


def _alarm(signum, frame):
    raise Hang(f"no result within {TIMEOUT_SECONDS} seconds")


def _matter(m):
    return {"code": m.code, "raw": m.raw.hex()}


def _siger(s):
    """An indexed signature as keripy holds it. ``ondex`` is included only when keripy's own
    table gives the code an ondex field on the wire; for a both-same code keripy fills ondex
    from index, which is inference, not wire content, so it is left out."""
    out = {"code": s.code, "index": s.index}
    if Indexer.Sizes[s.code].os:
        out["ondex"] = s.ondex
    out["raw"] = s.raw.hex()
    return out


def keripy_view(stream: bytes) -> list[dict]:
    """Every message keripy's Parser extracts from ``stream``, with its attachments."""
    parser = Parser(version=Vrsn_2_0)
    ims = bytearray(stream)
    out = []
    while ims:
        gen = parser.msgParsator(ims=ims, framed=True, piped=False)
        try:
            next(gen)
        except StopIteration as done:
            exts = done.value
        else:
            raise Waits("msgParsator yielded for more bytes on a framed stream")
        s = exts.serder
        out.append({
            "message": {"proto": s.proto, "version": f"{s.pvrsn.major}.{s.pvrsn.minor}",
                        "serialization": s.kind, "size": s.size},
            "sigers": [_siger(x) for x in exts.sigers],
            "wigers": [_siger(x) for x in exts.wigers],
            "cigars": [{"pre": _matter(c.verfer), "sig": _matter(c)} for c in exts.cigars],
            "tsgs": [{"pre": _matter(t[0]), "sn": _matter(t[1]), "dig": _matter(t[2]),
                      "sigers": [_siger(x) for x in t[3]]} for t in exts.tsgs],
            "frcs": [{"fn": _matter(f[0]), "dt": _matter(f[1])} for f in exts.frcs],
        })
    return out


def expected_view(items: list[dict]) -> list[dict]:
    """The same projection of a case's expected items: what keripy's Parser could report."""
    out, stack, pending = [], [], []
    for it in items:
        while stack and stack[-1]["group_end"] <= it["start"]:
            stack.pop()
        if it["kind"] == "message":
            out.append({"message": {k: it[k] for k in ("proto", "version", "serialization", "size")},
                        "sigers": [], "wigers": [], "cigars": [], "tsgs": [], "frcs": []})
            continue
        if it["kind"] == "genus":
            continue
        if it["kind"] == "counter":
            stack.append(it)
            continue
        cur = out[-1]
        letters = [c["code"].lstrip("-") for c in stack]
        inner = letters[-1]
        value = ({k: it[k] for k in ("code", "index", "ondex", "raw") if k in it}
                 if it["kind"] == "indexed" else {"code": it["code"], "raw": it["raw"]})
        if inner == "K" and "X" in letters:
            cur["tsgs"][-1]["sigers"].append(value)
        elif inner in ("K", "A"):
            cur["sigers"].append(value)
        elif inner == "L":
            cur["wigers"].append(value)
        elif inner in ("M", "O", "X"):
            pending.append(value)
            want = 3 if inner == "X" else 2
            if len(pending) == want:
                if inner == "M":
                    cur["cigars"].append({"pre": pending[0], "sig": pending[1]})
                elif inner == "O":
                    cur["frcs"].append({"fn": pending[0], "dt": pending[1]})
                else:
                    cur["tsgs"].append({"pre": pending[0], "sn": pending[1], "dig": pending[2],
                                        "sigers": []})
                pending = []
        else:
            raise ValueError(f"no keripy projection for a primitive in a {inner} group")
    return out


def run_case(case):
    signal.signal(signal.SIGALRM, _alarm)
    signal.alarm(TIMEOUT_SECONDS)
    try:
        if case["operation"] == "cesr.encode":  # keripy's own encoder, Matter
            inp = case["input"]
            m = Matter(raw=bytes.fromhex(inp["raw"]), code=inp["code"])
            return {"encoded": (m.qb64b if inp["domain"] == "text" else m.qb2).hex()}
        return {"parsed": keripy_view(bytes.fromhex(case["input"]["stream"]))}
    except Hang as e:
        return {"hang": str(e)}
    except Waits as e:
        return {"waits": str(e)}
    except Exception as e:  # noqa: BLE001 - any exception is keripy refusing the stream
        return {"rejected": f"{type(e).__name__}: {e}"}
    finally:
        signal.alarm(0)


def _ondex_only_difference(got, want):
    """True when the only difference is an ondex keripy reports as None where the wire carries 0
    (keripy checks a current-only code's ondex is zero, then discards it)."""
    def strip(view):
        text = json.dumps(view, sort_keys=True)
        return text.replace('"ondex": null', '"ondex": 0')
    return strip(got) == strip(want)


def compare(case, got):
    out = []
    for a in case["assertions"]:
        if a["check"] == "rejected":
            verdict = ("agree" if "rejected" in got else
                       "keripy-hangs" if "hang" in got else
                       "keripy-waits" if "waits" in got else "keripy-accepts")
        elif a["check"] == "encoded":
            verdict = "agree" if got.get("encoded") == a["expected"] else "keripy-differs"
        elif "parsed" not in got:
            verdict = "keripy-rejects" if "rejected" in got else "keripy-hangs-or-waits"
        else:
            want = expected_view(a["expected"])
            if got["parsed"] == want:
                verdict = "agree"
            elif _ondex_only_difference(got["parsed"], want):
                verdict = "agree-except-ondex-not-reported"
            else:
                verdict = "keripy-differs"
        out.append({"assertion": a["id"], "verdict": verdict})
    return out


def table_differences():
    """Codes and sizes where keripy main's genus 2.00 tables and the specification's differ.
    This compares tables, not parsing, and feeds the table section of DISAGREEMENTS.md."""
    from keri.core.counting import CtrDex_2_0

    t = tables.load()
    notes = []
    for code, prim in sorted(t.primitives.items()):
        if code not in Matter.Sizes:
            notes.append(f"primitive {code}: in the spec master table, not in keripy")
        elif prim.fs is not None and Matter.Sizes[code].fs != prim.fs:
            notes.append(f"primitive {code}: spec full size {prim.fs}, keripy {Matter.Sizes[code].fs}")
    notes += [f"primitive {c}: in keripy, not in the spec" for c in sorted(set(Matter.Sizes) - set(t.primitives))]
    for code, ent in sorted(t.indexed.items()):
        k = Indexer.Sizes.get(code)
        if k is None or (k.hs + k.ss, k.os, k.fs) != (ent.cs, ent.os, ent.fs):
            notes.append(f"indexed {code}: spec {(ent.cs, ent.os, ent.fs)}, keripy {k}")
    notes += [f"indexed {c}: in keripy, not in the spec" for c in sorted(set(Indexer.Sizes) - set(t.indexed))]
    keripy_ctr = {v: k for k, v in vars(CtrDex_2_0).items()}
    for code, desc in sorted(t.count_codes.items()):
        notes.append(f"count {code}: spec '{desc}'; keripy {keripy_ctr.get(code)}")
    notes += [f"count {c}: in keripy ({keripy_ctr[c]}), not in the spec master table"
              for c in sorted(set(keripy_ctr) - set(t.count_codes) - {"-_AAA"})]
    return notes


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--report", type=pathlib.Path, default=None)
    args = parser.parse_args(argv)
    results = []
    for path in sorted((ROOT / "cases" / "cesr").glob("*.json")):
        case = json.loads(path.read_text(encoding="utf-8"))
        if case["profile"] not in PROFILES:
            continue
        got = run_case(case)
        results.append({"id": case["id"], "profile": case["profile"], "status": case["status"],
                        "keripy": got, "verdicts": compare(case, got)})
    report = {"keripy_commit": KERIPY_COMMIT, "path": "Parser.msgParsator; Matter for encodings",
              "cases": results, "tables": table_differences()}
    if args.report:
        args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                               encoding="utf-8")
    for r in results:
        flags = ",".join(v["verdict"] for v in r["verdicts"])
        detail = r["keripy"].get("rejected", "")[:90]
        print(f"{r['id']} {r['profile']:17} {r['status']:9} {flags} {detail}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
