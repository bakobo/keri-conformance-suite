# keripy adapter

Connects keripy to the conformance runner over adapter protocol version 1 ([`docs/adapter-protocol.md`](../../docs/adapter-protocol.md)). It implements `cesr.parse` and `cesr.encode` and declares only those operations. It composes nothing: `composes` is empty, and every value it reports is produced by keripy, as the tables below say value by value.

The adapter does not read, reuse or import anything from `generators/`. keripy generated or cross-checked many of the cases, so an adapter that shared code with that generator would test the generator against itself.

## Two instances

| Instance | Project | keripy | Python | Profile it is meant for |
|---|---|---|---|---|
| keripy main | `adapters/keripy/` | main, commit `9a8b7aa70960f16fe7acffd8cf7901941ac912a1` (reports version 2.1.0.dev1) | 3.14 | `cesr-1.0` |
| keripy 1.2.14 | `adapters/keripy/keripy-1.2.14/` | tag `1.2.14`, commit `bab95c16e949b61398129a3e41a8f68bad84c94f` | 3.12 | `keripy-1x-interop` |

Both are uv projects with their own lockfiles. The package lives in `adapters/keripy/`; its keripy-main pin carries the marker `python_version >= '3.14'`, so it applies only in the main instance's Python 3.14 environment. The 1.2.14 project installs the same package by path on Python 3.12, where that marker drops the main pin, and pins keripy 1.2.14 itself. To pin a different keripy, change the commit in the relevant `pyproject.toml` and run `uv lock`.

```
cd adapters/keripy && uv sync                    # keripy main
cd adapters/keripy/keripy-1.2.14 && uv sync      # keripy 1.2.14

# from the repository root
uv run kcs check-adapter "$PWD/adapters/keripy/.venv/bin/kcs-adapter-keripy"
uv run kcs run --adapter "$PWD/adapters/keripy/.venv/bin/kcs-adapter-keripy" --profile cesr-1.0
uv run kcs run --adapter "$PWD/adapters/keripy/keripy-1.2.14/.venv/bin/kcs-adapter-keripy" --profile keripy-1x-interop
```

Point the runner at the console script inside the instance's `.venv` rather than at `uv run`: the runner starts adapters with a scrubbed environment.

`hello` reports the installed keripy, not the pin in `pyproject.toml`: `implementation.version` is the installed `keri` distribution's version and `implementation.commit` is the commit recorded in its PEP 610 `direct_url.json`.

Declared features. keripy main: `cesr.genus-2.00`, `cesr.domain.binary`, `cesr.serialization.json`, `cesr.serialization.cbor`, `cesr.serialization.mgpk`, `keri.version-1.x`, `keri.version-2.x`. keripy 1.2.14: `cesr.genus-1.00`, `cesr.domain.binary`, the three serializations, `keri.version-1.x`. keripy main can read 1.00 count codes, but only after a genus-version code selects that table; the 1.x interoperability streams carry none, so the main instance does not declare `cesr.genus-1.00`. keripy 1.2.14's parser never reads 2.00 count codes, so that instance does not declare `cesr.genus-2.00`.

## Tests

```
cd adapters/keripy && uv run pytest                          # against keripy main
cd adapters/keripy/keripy-1.2.14 && uv run pytest ../tests   # against keripy 1.2.14
```

Tests marked `main` or `onex` run only against that keripy generation. Branch coverage is 100% when the two runs are combined (`coverage combine`).

## Where each value comes from

`cesr.parse` walks the stream frame by frame. Each keripy call is made through one function, `errors.keri()`, which turns any exception keripy raises into a rejection carrying keripy's exception class. An exception raised anywhere else is an adapter bug and becomes a `harness` error. Every request starts from a fresh keripy `Parser`, so nothing carries over between requests.

| Reported value | keripy main | keripy 1.2.14 |
|---|---|---|
| What starts at a top-level frame boundary | `kering.sniff` (`msg`, `txt`, `bny`; `ano` reaches `Parser._extractor`, which raises `ColdStartError`) | `kering.sniff` (raises `ColdStartError` itself) |
| Message `proto`, `version`, `serialization`, `size` | `kering.smell`: proto, protocol version as `major.minor`, kind, size | same |
| Message `end` | `start + size` from `smell` | same |
| Any item's `end` | The item's keripy class extracted through `Parser._extractor(ims, klas, cold, abort=True)` from a copy of the stream that stops at the enclosing group's end; `end` is `start` plus the bytes keripy stripped | `Parser._extractor(..., abort=True, gvrsn=...)`, same |
| Counter `code`, `size` | `Counter.code`, `Counter.count` | same |
| Genus-version counter | `code == KERIACDCGenusVersion`; keripy's parser consumes only the counter, so `size` 0 and `group_end` = `end`; `gvrsn` = `Counter.b64ToVer(ctr.countToB64(l=3))`, written `major.minor` with two minor digits as keripy's `streaming.annot` writes it; `genus` = the code without its `-_` selector. The parser then switches to that table (`Parser.version` setter, which refuses versions keripy does not support) | Same values. keripy 1.2.14's parser discards the counter without switching tables, and so does the adapter |
| Counter `group_end` | If `Parser.methods[ctr.name]` names an extraction method, that keripy method run with `abort=True` on the rest of the enclosing frame; `group_end` is the counter's end plus the bytes it consumed. Otherwise `Counter.byteCount(cold)`, which keripy's parser uses for every 2.00 group and every 1.00 quadlet-counted (`QTDex_1_0`) group | Transcribed from `Parser.msgParsator`; see below |
| Kind of item inside a group | A nested group when its first code character is `-` (keripy's own test in `keri.core.mapping`; in the binary domain the character comes from `codeB2ToB64`). Otherwise `Siger` when the group's parser method is `_ControllerIdxSigs*` or `_WitnessIdxSigs*`, and `Matter` for everything else | The class sequence transcribed from `msgParsator`; see below |
| Primitive `code`, `raw` | `Matter.code`, `Matter.raw` | same |
| Indexed `code`, `raw`, `index` | `Indexer.code`, `.raw`, `.index` | same |
| Indexed `ondex` | Reported only when `Indexer.Sizes[code].os > 0`, meaning the code's table entry defines an ondex field. The value is `Indexer.ondex`. For current-only codes keripy checks that the field is zero and then stores `None`; for those the adapter reads the field back from keripy's own re-serialization (`Indexer.qb64` at the offsets of `Indexer.Sizes`, decoded with keripy's `b64ToInt`) | same |
| Rejection `class` | The class name of the exception keripy raised | same |
| `cesr.encode` | `Matter(raw=raw, code=code).qb64b` or `.qb2` | same |

## What the adapter decides rather than keripy

These are the places where the adapter does more than call keripy. Each mirrors something keripy does inline, so there was no keripy callable to use instead.

1. **The walk itself.** keripy's `Parser` routes whole messages to KERI processors and does not report items or offsets, and it does not accept a bare count code such as `-J` at the top level of a stream. The adapter therefore drives the walk itself, using keripy for every boundary and value. The cases in `cesr-1.0` are CESR framing tests, so this is the only way to put them to keripy at all.
2. **Shortage checks.** Where a body's declared size, or a group's `byteCount`, runs past the end of the stream or of the enclosing group, the adapter rejects with keripy's `ShortageError`. keripy makes the same comparison inline, in `Serder._inhale` (`len(raw) < size`) and in its group methods under `abort=True`. Where keripy main has a group method, keripy's own method raises this, not the adapter.
3. **keripy 1.2.14 group extents and contents (the weakest-sourced values).** keripy 1.2.14 has no `Counter.byteCount` and no per-code extraction methods. Its `Parser.msgParsator` consumes each attachment group inline (`src/keri/core/parsing.py`, lines 752 to 982 at 1.2.14), and only after a message body, so it cannot be called on these streams. The adapter transcribes that loop: for each count, it extracts the same classes in the same order through keripy's `Parser._extractor`, so each item's boundary is still keripy's:
   - `-A` ControllerIdxSigs and `-B` WitnessIdxSigs: one `Siger` per count.
   - `-C` NonTransReceiptCouples: `Verfer`, `Cigar`. `-D` TransReceiptQuadruples: `Prefixer`, `Seqner`, `Saider`, `Siger`.
   - `-E` FirstSeenReplayCouples: `Seqner`, `Dater`. `-G` SealSourceCouples: `Seqner`, `Saider`. `-I` SealSourceTriples: `Prefixer`, `Seqner`, `Saider`.
   - `-F` TransIdxSigGroups: `Prefixer`, `Seqner`, `Saider`, then a nested `-A` group. `-H` TransLastIdxSigGroups: `Prefixer`, then a nested `-A` group. Any other nested code is rejected with `UnexpectedCountCodeError`, as keripy does.
   - `-Z` ESSRPayloadGroup: one `Matter` per count.
   - `-V` and `-0V` AttachmentGroup: `count * 4` bytes in text, `count * 3` in binary (keripy's own expression, `parsing.py` line 762), holding count codes only.
   - `-J` SadPathSigGroups, `-K` RootSadPathSigGroups, `-L` and `-0L` PathedMaterialGroup are not transcribed. A stream that uses them gets an `unsupported` error rather than a guess.
4. **Wire ondex of current-only codes.** See the `ondex` row above.

No composable feature in `profiles/features.json` describes any of this. None of it is protocol behaviour composed on top of keripy. Each item mirrors framing that keripy performs inline.

## Errors

`hello` negotiates from the request's `supported` list (or `[protocol]` when the list is absent) and answers with protocol 1, or with an `unsupported` error when 1 is not offered. Request fields the adapter does not know are ignored. A line that is not a JSON object gets an error whose `id` is null. `keri.process` and `keri.emit` get an `unsupported` error. When keripy refuses to encode in `cesr.encode`, the response is an `unsupported` error naming keripy's exception class, because that operation has no rejection result. Every error message begins with a stable code (`e.request.malformed.p`, `e.request.op.unknown.p`, `e.request.op.undeclared.p`, `e.protocol.version.unsupported.p`, `e.encode.refused.p`, `e.parse.group.untranscribed.p`, `e.adapter.internal.p`, `e.adapter.extractor.yielded.p`). Each rejection is also explained on standard error, which the runner keeps in its report.
