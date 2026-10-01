"""Cross-check the spec-table CESR cases against keripy main at a pinned commit.

Run from this directory, in its own pinned environment:

    uv run python check.py [--report PATH]

keripy is never the authority here. A disagreement is reported for a maintainer to record in
``generators/DISAGREEMENTS.md``; it never changes an expected value.

keripy's ``Parser`` routes messages to its event handlers and does not report decoded items with
offsets, so the walk below uses keripy's own classes for every decision a parser makes: ``sniff``
for the domain of each top-level frame, ``smell`` for each version string, ``Counter`` for each
count code and the byte length of its group, and ``Matter`` and ``Indexer`` for each primitive and
indexed signature, their codes, index fields and raw values, and their pad and lead-byte checks.
What the walk supplies itself is only which kind of element a group holds: indexed signatures in
-K and -L, frames in the universal groups -A, -B and -C, and primitives or nested groups
elsewhere. Two normalisations bring keripy's object model to the wire report the suite asks for:
an ondex that keripy sets to ``None`` for a code whose table row has an ondex field (a current-only
code, whose ondex keripy requires to be zero) is reported as 0, and the genus/version code, whose
version keripy stores as a count, is reported with size 0.
"""

import argparse
import json
import pathlib
import signal
import sys
import traceback

from keri.core.coring import Matter
from keri.core.counting import Counter
from keri.core.indexing import Indexer
from keri.kering import Colds, Vrsn_2_0, smell, sniff

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from generators.spec_tables import tables

KERIPY_COMMIT = "9a8b7aa70960f16fe7acffd8cf7901941ac912a1"
TIMEOUT_SECONDS = 10


class Hang(Exception):
    pass


class WalkReject(ValueError):
    """A rejection the walk decided from keripy's own sizes, where keripy's Parser would raise
    in the same place (a group or body longer than the stream, or a cold start keripy cannot
    parse); reported separately from exceptions keripy itself raised."""


def _alarm(signum, frame):
    raise Hang(f"no result within {TIMEOUT_SECONDS} seconds")


class Walker:
    def __init__(self, s: bytes):
        self.s = s

    def _cold(self, i):
        return sniff(bytearray(self.s[i:]))

    def counter(self, i, cold, top):
        ims = bytearray(self.s[i:])
        ctr = (Counter(qb64b=ims, version=Vrsn_2_0) if cold == Colds.txt
               else Counter(qb2=ims, version=Vrsn_2_0))
        width = ctr.byteSize(cold)
        after = i + width
        if ctr.code == "-_AAA":
            vrsn = Counter.b64ToVer(ctr.countToB64(l=3))
            return [{"kind": "counter", "start": i, "end": after, "code": ctr.code, "size": 0,
                     "group_end": after, "genus": "AAA",
                     "gvrsn": f"{vrsn.major}.{vrsn.minor:02d}"}], after
        end = after + ctr.byteCount(cold)
        if end > len(self.s):
            raise WalkReject(f"{ctr.code} counts {ctr.count} past the end of the stream")
        item = {"kind": "counter", "start": i, "end": after, "code": ctr.code, "size": ctr.count,
                "group_end": end}
        items = []
        pos = after
        bare = ctr.code.lstrip("-")
        while pos < end:
            if bare in ("A", "B", "C"):
                got, pos = self.frame(pos, end, top=False)
            elif bare in ("K", "L"):
                one, pos = self.indexed(pos, cold, end)
                got = [one]
            elif self._starts_counter(pos, cold):
                got, pos = self.counter(pos, cold, top=False)
            else:
                one, pos = self.primitive(pos, cold, end)
                got = [one]
            items.extend(got)
        if pos != end:
            raise WalkReject(f"an element of {ctr.code} crosses the group end")
        return [item, *items], end

    def _starts_counter(self, i, cold):
        return self.s[i] >= 0xF8 if cold == Colds.bny else self.s[i:i + 1] == b"-"

    def primitive(self, i, cold, end):
        ims = bytearray(self.s[i:end])
        m = Matter(qb64b=ims) if cold == Colds.txt else Matter(qb2=ims)
        width = len(m.qb64b) if cold == Colds.txt else len(m.qb2)
        return {"kind": "primitive", "start": i, "end": i + width, "code": m.code,
                "raw": m.raw.hex()}, i + width

    def indexed(self, i, cold, end):
        ims = bytearray(self.s[i:end])
        x = Indexer(qb64b=ims) if cold == Colds.txt else Indexer(qb2=ims)
        width = len(x.qb64b) if cold == Colds.txt else len(x.qb2)
        item = {"kind": "indexed", "start": i, "code": x.code, "index": x.index}
        os_ = Indexer.Sizes[x.code].os
        if os_:
            item["ondex"] = 0 if x.ondex is None else x.ondex
        item["raw"] = x.raw.hex()
        item["end"] = i + width
        return item, i + width

    def message(self, i, limit):
        sm = smell(bytearray(self.s[i:]))
        end = i + sm.size
        if end > len(self.s):
            raise WalkReject(f"the message at {i} declares {sm.size} bytes")
        json.loads(self.s[i:end])
        return [{"kind": "message", "start": i, "end": end, "proto": sm.proto,
                 "version": f"{sm.pvrsn.major}.{sm.pvrsn.minor}", "serialization": sm.kind,
                 "size": sm.size}], end

    def frame(self, i, limit, top):
        cold = self._cold(i)
        if cold == Colds.msg:
            return self.message(i, limit)
        if cold in (Colds.txt, Colds.bny):
            return self.counter(i, cold, top)
        raise WalkReject(f"keripy sniff reports cold start {cold!r} at offset {i}")

    def walk(self):
        items, i = [], 0
        while i < len(self.s):
            got, i = self.frame(i, len(self.s), top=True)
            items.extend(got)
        return items


def encode(case):
    inp = case["input"]
    m = Matter(raw=bytes.fromhex(inp["raw"]), code=inp["code"])
    return (m.qb64b if inp["domain"] == "text" else m.qb2).hex()


def run_case(case):
    signal.signal(signal.SIGALRM, _alarm)
    signal.alarm(TIMEOUT_SECONDS)
    try:
        if case["operation"] == "cesr.encode":
            return {"encoded": encode(case)}
        return {"decoded": Walker(bytes.fromhex(case["input"]["stream"])).walk()}
    except Hang as e:
        return {"hang": str(e)}
    except WalkReject as e:
        return {"rejected": f"walk: {e}", "by": "walk"}
    except Exception as e:  # noqa: BLE001 - any exception is keripy refusing the stream
        return {"rejected": f"{type(e).__name__}: {e}", "by": "keripy",
                "trace": traceback.format_exc(limit=3).splitlines()[-1]}
    finally:
        signal.alarm(0)


def compare(case, got):
    """Agreement or the nature of a disagreement, for every assertion."""
    out = []
    for a in case["assertions"]:
        want = a["check"]
        if want == "rejected":
            if "rejected" in got:
                verdict = "agree"
            elif "hang" in got:
                verdict = "keripy-hangs"
            else:
                verdict = "keripy-accepts"
        elif "hang" in got:
            verdict = "keripy-hangs"
        elif "rejected" in got:
            verdict = "keripy-rejects"
        else:
            verdict = "agree" if got.get(want) == a["expected"] else "keripy-differs"
        out.append({"assertion": a["id"], "verdict": verdict})
    return out


def table_differences():
    """Codes and sizes where keripy main's genus 2.00 tables and the spec's differ."""
    t = tables.load()
    notes = []
    for code, prim in sorted(t.primitives.items()):
        if code not in Matter.Sizes:
            notes.append(f"primitive {code}: in the spec master table, not in keripy")
        elif prim.fs is not None and Matter.Sizes[code].fs != prim.fs:
            notes.append(f"primitive {code}: spec full size {prim.fs}, keripy {Matter.Sizes[code].fs}")
    for code in sorted(set(Matter.Sizes) - set(t.primitives)):
        notes.append(f"primitive {code}: in keripy, not in the spec master table")
    for code, ent in sorted(t.indexed.items()):
        k = Indexer.Sizes.get(code)
        if k is None:
            notes.append(f"indexed {code}: in the spec, not in keripy")
        elif (k.hs + k.ss, k.os, k.fs) != (ent.cs, ent.os, ent.fs):
            notes.append(f"indexed {code}: spec (cs, os, fs) = {(ent.cs, ent.os, ent.fs)}, "
                         f"keripy {(k.hs + k.ss, k.os, k.fs)}")
    for code in sorted(set(Indexer.Sizes) - set(t.indexed)):
        notes.append(f"indexed {code}: in keripy, not in the spec indexed table")
    from keri.core.counting import CtrDex_2_0
    keripy_ctr = {getattr(CtrDex_2_0, f): f for f in CtrDex_2_0._asdict()} \
        if hasattr(CtrDex_2_0, "_asdict") else {v: k for k, v in vars(CtrDex_2_0).items()}
    for code, desc in sorted(t.count_codes.items()):
        if code not in keripy_ctr:
            notes.append(f"count {code}: in the spec ({desc}), not in keripy")
        else:
            notes.append(f"count {code}: spec '{desc}'; keripy {keripy_ctr[code]}")
    for code in sorted(set(keripy_ctr) - set(t.count_codes) - {"-_AAA"}):
        notes.append(f"count {code}: in keripy ({keripy_ctr[code]}), not in the spec master table")
    return notes


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--report", type=pathlib.Path, default=None)
    args = parser.parse_args(argv)
    results = []
    for path in sorted((ROOT / "cases" / "cesr").glob("*.json")):
        case = json.loads(path.read_text(encoding="utf-8"))
        if case["profile"] != "cesr-1.0":
            continue
        got = run_case(case)
        verdicts = compare(case, got)
        results.append({"id": case["id"], "status": case["status"], "keripy": got,
                        "verdicts": verdicts})
    report = {"keripy_commit": KERIPY_COMMIT, "cases": results, "tables": table_differences()}
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.report:
        args.report.write_text(text + "\n", encoding="utf-8")
    disagreements = [r for r in results if any(v["verdict"] != "agree" for v in r["verdicts"])]
    for r in results:
        flags = ",".join(v["verdict"] for v in r["verdicts"])
        print(f"{r['id']} {r['status']:9} {flags}")
    print(f"{len(results)} cases, {len(disagreements)} with a disagreement")
    return 0


if __name__ == "__main__":
    sys.exit(main())
