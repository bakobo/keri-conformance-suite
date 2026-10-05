"""Cross-check the keripy-1x-interop CESR cases against keripy 1.2.14's own Parser.

Run from this directory, in its own pinned environment:

    uv run python check.py [--report PATH]

Each stream goes through keripy 1.2.14's ``Parser.msgParsator`` (``src/keri/core/parsing.py``),
framed, once per message. In 1.2.14 that method reaps and verifies the body with ``Serdery`` and
then hands the extracted attachments to a ``Kevery``; here the Kevery is a recorder that keeps what
the Parser handed it (``processEvent``'s ``sigers`` and ``wigers``,
``processAttachedReceiptCouples``'s ``cigars``) and does nothing else, so the check sees exactly
what keripy's parsing produced and no KERI validation runs. keripy's Parser reports no offsets,
count codes or group ends, so those parts of a case are not cross-checked here; DISAGREEMENTS.md
says so. Cases whose context is a genus 2.00 stream are skipped: keripy 1.2.14 does not implement
the 2.00 tables those streams use.
"""

import argparse
import json
import pathlib
import sys

import keri
from keri.core.parsing import Parser

ROOT = pathlib.Path(__file__).resolve().parents[2]
KERIPY_COMMIT = "bab95c16e949b61398129a3e41a8f68bad84c94f"


class Recorder:
    """Stands in for a Kevery and records what the Parser hands it."""

    def __init__(self):
        self.messages = []

    def processEvent(self, serder, sigers, wigers=None, **kwa):
        self.messages.append({
            "message": {"proto": serder.proto,
                        "version": f"{serder.version.major}.{serder.version.minor}",
                        "serialization": serder.kind, "size": serder.size},
            "sigers": [{"code": s.code, "index": s.index, "raw": s.raw.hex()} for s in sigers],
            "wigers": [{"code": s.code, "index": s.index, "raw": s.raw.hex()}
                       for s in (wigers or [])],
            "cigars": [],
        })

    def processAttachedReceiptCouples(self, serder, cigars, **kwa):
        self.messages[-1]["cigars"] = [
            {"pre": {"code": c.verfer.code, "raw": c.verfer.raw.hex()},
             "sig": {"code": c.code, "raw": c.raw.hex()}} for c in cigars]


def keripy_view(stream: bytes) -> list[dict]:
    rec = Recorder()
    parser = Parser(kvy=rec)
    ims = bytearray(stream)
    while ims:
        gen = parser.msgParsator(ims=ims, framed=True, kvy=rec)
        try:
            next(gen)
        except StopIteration:
            continue
        raise RuntimeError("msgParsator yielded for more bytes on a framed stream")
    return rec.messages


def expected_view(items: list[dict]) -> list[dict]:
    out, stack, pending = [], [], []
    for it in items:
        while stack and stack[-1]["group_end"] <= it["start"]:
            stack.pop()
        if it["kind"] == "message":
            out.append({"message": {k: it[k] for k in ("proto", "version", "serialization", "size")},
                        "sigers": [], "wigers": [], "cigars": []})
        elif it["kind"] == "counter":
            stack.append(it)
        elif it["kind"] == "indexed":
            group = {"A": "sigers", "B": "wigers"}[stack[-1]["code"].lstrip("-")]
            out[-1][group].append({k: it[k] for k in ("code", "index", "raw")})
        else:  # a primitive: only -C couples carry them in these cases
            pending.append({"code": it["code"], "raw": it["raw"]})
            if len(pending) == 2:
                out[-1]["cigars"].append({"pre": pending[0], "sig": pending[1]})
                pending = []
    return out


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
        if any(it["kind"] == "genus" for a in case["assertions"]
               for it in a.get("expected", [])):
            results.append({"id": case["id"], "verdicts": ["skipped-genus-2.00-stream"]})
            continue
        try:
            outcome = {"parsed": keripy_view(bytes.fromhex(case["input"]["stream"]))}
        except Exception as e:  # noqa: BLE001 - any exception is keripy 1.2.14 refusing it
            outcome = {"rejected": f"{type(e).__name__}: {e}"}
        verdicts = []
        for a in case["assertions"]:
            if a["check"] == "rejected":
                # A yield for more bytes on complete input is a rejection under the adapter
                # protocol's end-of-input rule; keripy_view raises on it.
                verdicts.append("agree" if "rejected" in outcome else "keripy-1.2.14-accepts")
            else:
                verdicts.append("agree" if outcome.get("parsed") == expected_view(a["expected"])
                                else "keripy-1.2.14-differs")
        results.append({"id": case["id"], "keripy": outcome, "verdicts": verdicts})
    report = {"keripy_version": keri.__version__, "keripy_commit": KERIPY_COMMIT,
              "path": "Parser.msgParsator with a recording Kevery", "cases": results}
    if args.report:
        args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                               encoding="utf-8")
    for r in results:
        print(f"{r['id']} {','.join(r['verdicts'])} {r.get('keripy', {}).get('rejected', '')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
