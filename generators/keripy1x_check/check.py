"""Cross-check the keripy-1x-interop CESR cases against keripy 1.2.14 itself.

Run from this directory, in its own pinned environment:

    uv run python check.py [--report PATH]

The interop cases' expected values come from the 1.00 count-code table transcribed in
``generators/spec_tables/keripy1x.py``. This script checks that transcription two ways, using
keripy 1.2.14 for every decision:

- it walks each stream with keripy 1.2.14's ``sniff``, ``smell``, ``Counter`` (genus/version
  1.00), ``Matter`` and ``Indexer``, reading each group the way keripy 1.2.14's ``Parser`` does
  (``src/keri/core/parsing.py``: ``-V`` takes ``count * 4`` characters, lines 759-764; ``-A``
  extracts ``count`` signatures, lines 781-784; ``-C`` extracts ``count`` couples, lines 261-269);
- it re-emits every count code with keripy's own ``Counter(code=..., count=..., gvrsn=1.0)`` and
  checks the bytes are the case's bytes.
"""

import argparse
import json
import pathlib
import sys

import keri
from keri.core.coring import Matter
from keri.core.counting import Counter
from keri.core.indexing import Indexer
from keri.kering import Colds, Vrsn_1_0, smell, sniff

ROOT = pathlib.Path(__file__).resolve().parents[2]
KERIPY_COMMIT = "bab95c16e949b61398129a3e41a8f68bad84c94f"
ITEMS = {"-A": ("indexed", 1), "-B": ("indexed", 1), "-C": ("primitive", 2)}
QUADLETS = ("-V", "-0V")


class Walker:
    def __init__(self, s: bytes):
        self.s = s
        self.reemitted = []

    def counter(self, i):
        ctr = Counter(qb64b=bytearray(self.s[i:]), gvrsn=Vrsn_1_0)
        after = i + len(ctr.qb64b)
        again = Counter(code=ctr.code, count=ctr.count, gvrsn=Vrsn_1_0).qb64b
        self.reemitted.append(again == bytes(self.s[i:after]))
        item = {"kind": "counter", "start": i, "end": after, "code": ctr.code, "size": ctr.count}
        items, pos = [], after
        if ctr.code in QUADLETS:
            end = after + ctr.count * 4
            while pos < end:
                got, pos = self.element(pos, end)
                items.extend(got)
        else:
            kind, per = ITEMS[ctr.code]
            for _ in range(ctr.count * per):
                got, pos = (self.indexed if kind == "indexed" else self.primitive)(pos)
                items.append(got)
            end = pos
        item["group_end"] = end
        return [item, *items], end

    def element(self, i, end):
        if self.s[i:i + 1] == b"-":
            return self.counter(i)
        got, pos = self.primitive(i)
        return [got], pos

    def primitive(self, i):
        m = Matter(qb64b=bytearray(self.s[i:]))
        return {"kind": "primitive", "start": i, "end": i + len(m.qb64b), "code": m.code,
                "raw": m.raw.hex()}, i + len(m.qb64b)

    def indexed(self, i):
        x = Indexer(qb64b=bytearray(self.s[i:]))
        end = i + len(x.qb64b)
        return {"kind": "indexed", "start": i, "end": end, "code": x.code, "index": x.index,
                "raw": x.raw.hex()}, end

    def walk(self):
        items, i = [], 0
        while i < len(self.s):
            cold = sniff(bytearray(self.s[i:]))
            if cold == Colds.msg:
                sm = smell(bytearray(self.s[i:]))
                items.append({"kind": "message", "start": i, "end": i + sm.size,
                              "proto": sm.proto,
                              "version": f"{sm.vrsn.major}.{sm.vrsn.minor}",
                              "serialization": sm.kind, "size": sm.size})
                i += sm.size
            elif cold == Colds.txt:
                got, i = self.counter(i)
                items.extend(got)
            else:
                raise ValueError(f"cold start {cold!r} at {i}")
        return items


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--report", type=pathlib.Path, default=None)
    args = parser.parse_args(argv)
    assert keri.__version__ == "1.2.14", keri.__version__
    results = []
    for path in sorted((ROOT / "cases" / "cesr").glob("*.json")):
        case = json.loads(path.read_text(encoding="utf-8"))
        if case["profile"] != "keripy-1x-interop":
            continue
        w = Walker(bytes.fromhex(case["input"]["stream"]))
        try:
            got = w.walk()
            outcome = {"decoded": got}
        except Exception as e:  # noqa: BLE001 - any exception is keripy 1.2.14 refusing the stream
            outcome = {"rejected": f"{type(e).__name__}: {e}"}
        verdicts = []
        for a in case["assertions"]:
            if "decoded" in outcome and outcome["decoded"] == a["expected"]:
                verdicts.append("agree")
            else:
                verdicts.append("keripy-1.2.14-differs")
        results.append({"id": case["id"], "keripy": outcome, "verdicts": verdicts,
                        "reemitted_identically": all(w.reemitted)})
    report = {"keripy_version": keri.__version__, "keripy_commit": KERIPY_COMMIT, "cases": results}
    if args.report:
        args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for r in results:
        print(f"{r['id']} {','.join(r['verdicts'])} reemitted={r['reemitted_identically']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
