# keripy adapter

Connects keripy to the conformance runner over adapter protocol version 1 ([`docs/adapter-protocol.md`](../../docs/adapter-protocol.md)). It implements `cesr.parse` and `cesr.encode` on both keripy generations, and `keri.process`, `acdc.verify` and `exn.verify` on keripy main only (see the sections of those names below). It composes nothing: `composes` is empty, and every value it reports either comes from keripy or is measured from what keripy's own parser consumed. The tables below say which, value by value.

The adapter does not read, reuse or import anything from `generators/`. keripy generated or cross-checked many of the cases, so an adapter that shared code with that generator would test the generator against itself.

## Two instances

| Instance | Project | keripy | Python | Profile it is meant for |
|---|---|---|---|---|
| keripy main | `adapters/keripy/` | main, commit `9a8b7aa70960f16fe7acffd8cf7901941ac912a1` (reports version 2.1.0.dev1) | 3.14 | `cesr-1.0` |
| keripy 1.2.14 | `adapters/keripy/keripy-1.2.14/` | tag `1.2.14`, commit `bab95c16e949b61398129a3e41a8f68bad84c94f` | 3.12 | `keripy-1x-interop` |

Both are uv projects with their own lockfiles. The package lives in `adapters/keripy/`; its keripy-main pin carries the marker `python_version >= '3.14'`, so it applies only in the main instance's Python 3.14 environment. The 1.2.14 project installs the same package by path on Python 3.12, where that marker drops the main pin, and pins keripy 1.2.14 itself. To pin a different keripy, change the commit in the relevant `pyproject.toml` and run `uv lock`.

```sh
cd adapters/keripy && uv sync                    # keripy main
cd adapters/keripy/keripy-1.2.14 && uv sync      # keripy 1.2.14

# from the repository root
uv run kcs check-adapter "$PWD/adapters/keripy/.venv/bin/kcs-adapter-keripy"
uv run kcs run --adapter "$PWD/adapters/keripy/.venv/bin/kcs-adapter-keripy" --profile cesr-1.0
uv run kcs run --adapter "$PWD/adapters/keripy/keripy-1.2.14/.venv/bin/kcs-adapter-keripy" --profile keripy-1x-interop
```

Point the runner at the console script inside the instance's `.venv` rather than at `uv run`: the runner starts adapters with a scrubbed environment.

`hello` reports the installed keripy, not the pin in `pyproject.toml`: `implementation.version` is the installed `keri` distribution's version and `implementation.commit` is the commit recorded in its PEP 610 `direct_url.json`.

Declared features. keripy main: `cesr.genus-1.00`, `cesr.genus-2.00`, `cesr.item-extents`, `cesr.domain.binary`, `cesr.serialization.json`, `cesr.serialization.cbor`, `cesr.serialization.mgpk`, `keri.version-1.x`, `keri.version-2.x`, and for `keri.process` `crypto.ed25519`, `kel.basic`, `kel.delegation`, `kel.multisig.numeric`, `kel.multisig.weighted`, `kel.nontransferable`, `kel.partial-rotation`, `kel.recovery`, `kel.witness`, `keri.duplicity`, `keri.escrow` and `keri.routing`, all of which keripy's Kevery does itself. keripy main reads 1.00 count codes once a genus/version code selects that table, so it declares `cesr.genus-1.00`. It does not read the genus-less 1.x streams of the interoperability profile as 1.x does, and those cases fail rather than being skipped. keripy 1.2.14: `cesr.genus-1.00`, `cesr.domain.binary`, the three serializations, `keri.version-1.x`. Its parser accepts a genus/version code but never switches tables, so it does not declare `cesr.genus-2.00`. Neither instance declares any `acdc.*` feature; "acdc.verify" below says why.

`cesr.item-extents` promises the decoded items of every stream the implementation accepts (adapter protocol, `cesr.parse`). keripy main declares it. The only stream it cannot itemize is a native CESR body (answered `unsupported`, `e.feature.unsupported.native-body.f`), and that falls under `cesr.native`, which it does not declare. keripy 1.2.14 does not declare it, because the adapter cannot measure its `-H` and `-J` groups (see "Not measurable"), so the runner sends that build no case with a `decoded` assertion. It still receives rejection-only cases. For an unmeasurable group the adapter answers `unsupported` rather than the protocol's accepted summary: the measurement stops before keripy has finished the stream, so whether keripy would accept it is not known.

## Tests

```sh
cd adapters/keripy && uv run pytest                          # against keripy main
cd adapters/keripy/keripy-1.2.14 && uv run pytest ../tests   # against keripy 1.2.14
```

Tests marked `main` or `onex` run only against that keripy generation. Branch coverage is 100% when the two runs are combined, and CI enforces it:

```sh
cd adapters/keripy
COVERAGE_FILE=$PWD/.coverage.main uv run pytest --cov=kcs_adapter_keripy --cov-branch --cov-report=
(cd keripy-1.2.14 && COVERAGE_FILE=$PWD/../.coverage.onex uv run pytest ../tests --cov=kcs_adapter_keripy --cov-branch --cov-report=)
uv run coverage combine .coverage.main .coverage.onex && uv run coverage report -m --fail-under=100
```

## CI and the baseline

CI level 2 (`docs/design.md`) for this adapter is the `keripy-adapter` job in `.github/workflows/ci.yml`. It builds both instances from their lockfiles: Python 3.14 with keripy main, and Python 3.12 with keripy 1.2.14. It runs the adapter's tests in each and gates on their combined branch coverage being 100%, then runs `kcs check-adapter` on both. Finally it runs `kcs run --profile cesr-1.0` on keripy main against `baseline-cesr-1.0.json`, and `kcs run --profile keripy-1x-interop` on keripy 1.2.14 against `baseline-keripy-1x-interop.json`. Each baseline records the verdict, every case's outcome and failure kind (`timeout`, `exited`, `malformed`, `error-harness` and so on, or none), and every assertion's outcome, as last recorded. The comparison is `python -m kcs_adapter_keripy.baseline compare`, and it fails in two cases:
- **A regression:** a different profile, an aborted run, or a verdict change other than to conformant. Also any case or assertion outcome that changed to anything but pass, a case or assertion that disappeared, or a failure kind that appeared or changed. A case that starts crashing therefore fails the gate even though it still fails and the verdict is unchanged.
- **An improvement:** a verdict that became conformant, a new pass, a failure kind that went away, a new case or assertion, or a different keripy commit. This must be recorded in the same change:

```sh
uv run kcs run --adapter "$PWD/adapters/keripy/.venv/bin/kcs-adapter-keripy" --profile cesr-1.0 --report /tmp/r.json
adapters/keripy/.venv/bin/python -m kcs_adapter_keripy.baseline write adapters/keripy/baseline-cesr-1.0.json /tmp/r.json
```

The tool reads at most 64 MiB of a report or baseline (`baseline.MAX_FILE_BYTES`). A larger file is refused with `e.input.range.file-size.f`; a cesr-1.0 report is well under 1 MiB.

The committed baseline is keripy main `9a8b7aa70960f16fe7acffd8cf7901941ac912a1`, verdict conformant: every active assertion passes, and the two disputed cases, CESR-0022 and CESR-0031, fail. The keripy 1.2.14 baseline for `keripy-1x-interop` records CESR-0045 to CESR-0048 as not-supported, because each has a `decoded` assertion and this build does not declare `cesr.item-extents` (CESR-0048 also needs `cesr.genus-2.00`), and the five must-reject cases as passing; its verdict is `no-evidence`, because INTEROP assertions make no conformance claim. Its must-reject cases (CESR-0049 onward) pass because keripy 1.2.14 is the reference their expectations come from: it raises for the unassigned code, and its parser asks for more bytes on the truncated streams, which the adapter reports as a rejection under the end-of-input rule.

## How a stream is parsed

`cesr.parse` hands the stream to keripy's own `Parser.msgParsator`, one message (body plus attachments) per call. That is the same unit keripy's own parse loops (`allParsator`, `parsator`) use. The adapter calls it with `framed=True` until the stream is used up, using one fresh parser per request. keripy main is called as `msgParsator(ims, framed=True, piped=False, version=None)`, so a genus/version code at the top level carries over to later messages exactly as it does in keripy. keripy 1.2.14 is called as `msgParsator(ims, framed=True, pipeline=False)` with no KERI processors attached.

No keripy code is modified. keripy's parser returns objects, not offsets, so two things let the adapter see where keripy was:

- **`Tracked`** (`src/kcs_adapter_keripy/measure.py`) is the `bytearray` the stream is handed over in. It knows the stream offset of its first byte. When keripy strips bytes from its front (`del ims[:n]`), it tells the recorder and advances. When keripy cuts a substream (`ims[:n]`), the substream is also a `Tracked` and knows its own offset.
- **A subclass of keripy's `Parser`** overrides `_extractor` and `extract`, the two methods through which keripy takes every primitive, indexed signature and count code from the stream. Each override records what keripy extracted and where its buffer stood before and after, then returns keripy's result unchanged. The subclass also wraps the helper generators keripy hands a whole group to. On keripy main these are every method named in `Parser.Methods`; on 1.2.14 they are `_nonTransReceiptCouples`, `_transIdxSigGroups` and `_sadPathSigGroup`. Each wrapper records where keripy's buffer stood when the helper returned.

**End of input.** If keripy's parser yields, asking for more bytes, the stream is complete (adapter protocol, "End of input"), so the adapter rejects with keripy's `ShortageError`. This happens on keripy 1.2.14, which waits rather than raising when a body or an item is cut short, and which also waits for attachments after any message. On 1.2.14 a final message with no attachments is therefore a rejection.

**Rejections.** Any exception keripy's parser raises is a rejection, with keripy's exception class as the class. On keripy main a failure inside an enclosed attachments group arrives as keripy's own `SizedGroupError`. There is one exception. keripy 1.2.14's `msgParsator` dispatches the finished message to its KERI processors, and with none attached that dispatch raises (`ValidationError: No kevery to process...`). keripy's own parse loop classes such errors as non-extraction errors and resumes. The adapter treats an exception as this post-extraction kind only when every one of these holds:
- the call consumed a whole message;
- the exception was not raised inside an extraction;
- the exception is not an `ExtractionError`;
- keripy's buffer stands at the end of the stream or at the start of the next message.

## Measured, not sourced

The protocol needs offsets, and keripy's parser does not expose them. Every offset below is measured from what keripy consumed. None is computed from a count, a size or a code table.

| Value | Measured as |
|---|---|
| `start` of every item | The stream offset of keripy's buffer when keripy began taking the item |
| `end` of a primitive, indexed signature or count code that keripy extracted with stripping | The offset of keripy's buffer after the extraction returned |
| `end` of a count code keripy peeked at and then stripped itself (keripy main: `del ims[:ctr.byteSize(cold)]`) | The end of that deletion. The adapter checks that the deletion is exactly the code (`Counter.byteSize`). If keripy also took the group's contents in the same deletion, as it does for a native CESR body, the adapter answers `unsupported` |
| `end` and `size` of a message | The end and length of keripy's deletion of the body (`Serder` stripping it). `proto`, `version` and `serialization` come from keripy's `smell` of those same bytes. The adapter checks that `smell`'s declared size equals the length keripy consumed |
| `group_end`, when keripy cuts the group out as a substream (`eims = ims[:eags]; del ims[:eags]`, `gims = ims[:gs]; del ims[:gs]`, 1.2.14's `pims = ims[:pags]; del ims[:pags]`) | The end of that deletion, which is the first deletion keripy makes from the same buffer after taking the count code |
| `group_end`, when keripy hands the group to a helper method (main's `Parser.Methods`; 1.2.14's `_nonTransReceiptCouples`, `_transIdxSigGroups`) | Where keripy's buffer stood when the helper returned. On main this is the same offset as the substream cut for 2.00 codes; for 1.00 item-counted codes (`_ControllerIdxSigs1` and so on) it is the end of the last item keripy took |
| `group_end`, when keripy 1.2.14 consumes the group inline in `msgParsator` (`-A`, `-B`, `-D`, `-E`, `-G`, `-I`, `-Z`) | Where keripy's buffer stood when keripy took the next count code from the same buffer at the same nesting, or when it finished the message |

Not measurable, answered `unsupported` (`e.feature.unsupported.group-extent.f`): keripy 1.2.14's `-H` (TransLastIdxSigGroups) and `-J` (SadPathSigGroups). keripy consumes both inline in `msgParsator`, together with a nested count code taken the same way. Nothing it does separates the end of the outer group from the start of the nested one.

## Where each value comes from

| Reported value | Source |
|---|---|
| Item boundaries | Measured; see above |
| Counter `code`, `size` | keripy's `Counter.code` and `Counter.count` for the code keripy extracted |
| Genus item `code`, `genus`, `version` | The code keripy extracted when `Counter.code` is `KERIACDCGenusVersion`. `code` is keripy's `Counter.qb64`; `genus` is the code without its `-_` selector; `version` is `Counter.b64ToVer(ctr.countToB64(l=3))`, written with a two-digit minor as keripy's `streaming.annot` writes it. Whether the table then changes is keripy's own business: main switches, 1.2.14 does not |
| Message `proto`, `version`, `serialization` | `kering.smell` of the bytes keripy consumed as the body; `version` is the protocol version, minor unpadded |
| Primitive `code`, `raw` | `Matter.code`, `Matter.raw` of the object keripy extracted (its own class: `Verfer`, `Cigar`, `Seqner` and so on) |
| Indexed `code`, `raw`, `index` | `Indexer.code`, `.raw`, `.index` of the `Siger` keripy extracted |
| Indexed `ondex` | Reported only when keripy's `Indexer.Sizes[code].os > 0`. The value is `Indexer.ondex`. For current-only codes keripy checks that the field is zero and then stores `None`; for those the field is read back from keripy's own `Indexer.qb64`, at the offsets of `Indexer.Sizes`, decoded with keripy's `b64ToInt` |
| Rejection `class` | The class name of the exception keripy raised, or `ShortageError` when keripy asked for bytes after the end of the stream |
| `cesr.encode` | `Matter(raw=raw, code=code).qb64b` or `.qb2` |

Which item kind an extraction becomes depends on the class keripy chose: a `Counter` is a count code or genus item, an `Indexer` is an indexed signature, and any other `Matter` is a primitive. The adapter never chooses a class itself.

## Errors

`hello` negotiates from the request's `supported` list (or `[protocol]` when the list is absent) and answers with protocol 1, or with an `unsupported` error when 1 is not offered. Request fields the adapter does not know are ignored. A request line may be at most 64 MiB (67,108,864 bytes, not counting its newline; `protocol.MAX_REQUEST_LINE`). The adapter reads a line at most that far before deciding. A longer line gets an error whose `id` is null (`e.input.range.request-size.f`), and the rest of it is skipped in small chunks, never held whole. The adapter then answers the next request. A line that is not a JSON object, or a request without a usable `id` (a non-negative integer), gets an error whose `id` is null. Every response the adapter writes is checked against `schema/adapter-protocol.schema.json` in `tests/test_schema.py`. `keri.emit` gets an `unsupported` error, and so do `keri.process`, `acdc.verify` and `exn.verify` on keripy 1.2.14. A `keri.process`, `acdc.verify` or `exn.verify` request with a malformed field (`messages`, `kels`, `registry`, `acdcs`, `schemas`, `presented` or `perspective`) gets a `harness` error (`e.input.format.request.f`); a perspective other than `validator` is `unsupported` (`e.feature.unsupported.perspective.f`). When keripy refuses to encode in `cesr.encode`, the response is an `unsupported` error naming keripy's exception class, because that operation has no rejection result. Every error message begins with a stable code (`e.input.format.request.f`, `e.input.range.unknown-op.f`, `e.feature.unsupported.undeclared-op.f`, `e.feature.unsupported.protocol-version.f`, `e.input.format.encode-refused.f`, `e.feature.unsupported.group-extent.f`, `e.feature.unsupported.native-body.f`, `e.feature.unsupported.perspective.f`, `e.self.unknown.quiescence.f`, `e.self.unknown.f`, and `e.self.unknown.*` codes for each way keripy could step outside what the measurement expects. The codes follow the Bakobo error-code grammar `<sorter>.<descriptor>[.<sub>...].<disposition>`; every one ends in `f`, because retrying the same request gives the same answer). Each rejection is also explained on standard error, which the runner keeps in its report.

## keri.process

`keri.process` (keripy main only) delivers the request's messages, in order, to one fresh keripy validator: a temporary database (`basing.openDB(temp=True)`), a `Kevery(lax=False, local=False)` and a `Parser(kvy=kvy)` made for that request and closed after it, so nothing carries over between requests. Each message's bytes go to `Parser.parse` unchanged; keripy sniffs, frames and routes them itself. Any exception keripy raises while parsing a message is logged on standard error, and the message is then reported by whatever keripy holds. keripy 1.2.14 does not declare the operation, because it validates only KERI 1.x bodies and every KERI case so far carries 2.XX bodies.

**Quiescence.** After each delivery the adapter calls `Kevery.processEscrows()` until a call changes none of keripy's event, signature, receipt and escrow tables (`evts`, `fels`, `kels`, `sigs`, `wigs`, `rcts`, `ooes`, `pses`, `pwes`, `pdes`, `ldes`, `uwes`, `ures`; compared by entry count). If 1,000 calls do not settle, the request fails with `e.self.unknown.quiescence.f` rather than report readings that depend on when the adapter stopped. keripy's escrow timeouts are wall-clock and never reached within a case.

**Which message is which.** Before delivery, each stream is also parsed by a separate keripy `Parser` with no Kevery attached, through the same `msgParsator` call `cesr.parse` uses. Its `Serder` names the message: type, prefix, sequence number and SAID, and for a receipt its witness signatures and couples. A stream keripy cannot parse is reported `rejected` at both readings: keripy keeps nothing of it.

| Reported value | keripy state it is read from |
|---|---|
| `seen` (key event) | keripy recorded a first-seen ordinal for the event: `db.fons` has (prefix, SAID) |
| `duplicitous` | otherwise, the SAID is in the likely-duplicitous escrow, `db.ldes` at (prefix, sn) |
| `pending` (key event) | otherwise, the SAID is in the out-of-order, partially signed, partially witnessed or partially delegated escrow: `db.ooes`, `db.pses`, `db.pwes` or `db.pdes` at (prefix, sn) |
| `rejected` | keripy holds the message in none of those |
| `seen` (receipt) | every witness signature it carries is in `db.wigs` for (prefix, SAID), and every couple in `db.rcts`. keripy attaches witness signatures to an event it holds in escrow, so a receipt can be seen before its event is |
| `pending` (receipt) | otherwise, keripy holds one of its witness signatures in the unverified witness receipt escrow, `db.uwes` at (prefix, sn) |
| `trunk` | the message is a seen key event, `db.kels.getLast` at its sequence number is its SAID, and its sequence number is at most the Kever's (`kever.sner.num`); a superseded event fails the last two, and a receipt is never on the trunk |
| `key_states` | one entry per `kvy.kevers` item: `sner.num`, `serder.said`, `verfers`, `tholder.sith`, `ndigers`, `ntholder.sith`, `wits`, `toader.num` as hex, `delpre` |

Initial readings are taken at quiescence after each message's own delivery, final readings and `trunk` at quiescence after the last.

The adapter's `reading` returns `rejected` for a message it finds in neither keripy's seen state nor any escrow table, so a pass on a `rejected` assertion shows that keripy kept the message nowhere, not which rule dropped it; that is what the case grades, as with the self-agreement note.

**Results.** On keripy main `9a8b7aa70960f16fe7acffd8cf7901941ac912a1`, `keri-1.0` is conformant: every case passes, with every active MUST and SHOULD assertion passing and none failing. `keri-escrow`'s 3 cases pass; its verdict is `no-evidence`, because its assertions are INTEROP. The baselines are `baseline-keri-1.0.json` and `baseline-keri-escrow.json`, written with the baseline tool from fresh runs, and are re-recorded whenever the cases move. The `keripy-adapter` job in `.github/workflows/ci.yml` compares both against fresh runs, as it does `cesr-1.0` and `keripy-1x-interop`.

```sh
uv run kcs run --adapter "$PWD/adapters/keripy/.venv/bin/kcs-adapter-keripy" --profile keri-1.0 --report /tmp/r.json
adapters/keripy/.venv/bin/python -m kcs_adapter_keripy.baseline compare adapters/keripy/baseline-keri-1.0.json /tmp/r.json
```

## acdc.verify

`acdc.verify` (keripy main only) never answers `valid`, and the adapter declares no `acdc.*` feature, so the runner sends it no ACDC case. That is failing closed, not a gap in the adapter: keripy main has no entry point that judges an ACDC 2.00 against a bundle.

What keripy main has, at the pinned commit:

- **A 2.00 ACDC verifier, but only inside IPEX.** keripy verifies ACDC 2.00 nodes in `keri.acdc.ipexing.IpexHandler`, and only when an `/ipex/grant` exchange message carries the disclosed DAG as nested streams. It walks the DAG, evaluates edge operators and edge schema pins, and checks each node's issuer commitment through its registry, a source seal, or a signature by the issuer's current keys. That path needs a grant signed by a sender, IPEX workflow state and a local registry store, none of which a bundle has, and its edge results are one boolean per edge block, not per edge. The adapter does not build a grant to reach it: that would be the adapter composing an IPEX exchange, and no `acdc.*` feature is composable.
- **No schema enforcement for 2.00.** The only places keripy validates an ACDC against its schema (`Schemer.verify`) are its 1.x verifier (`keri.vdr.verifying.Verifier`) and command-line tools. The IPEX path checks an edge's schema pin, not the ACDC's own schema.
- **No parser route.** keripy's `Parser` hands an ACDC message with no type field to a 1.x `Verifier`, which requires a 1.x (`vcp`/`iss`) registry, and refuses every other ACDC message type, including `acm`, `rip` and `bup`.
- **A public 2.00 registry verifier.** `keri.acdc.regeventing.vet` verifies a `rip`/`bup` chain against KELs the caller has already accepted: sequence numbers, prior SAIDs, the registry SAID, an anchoring seal in the KEL of the AID the inception names (refusing one found only in another KEL, and an aggregate seal), duplicity at one sequence number, and a disclosed blinded state against the update's BLID. It does not verify non-blindable updates (`upd`).

So the adapter answers:

| Result | When |
|---|---|
| `verdict` `invalid` | keripy cannot parse the presented stream as exactly one message (bytes left over after keripy's parse of the first message make it unframeable), or parses it as something other than a disclosed ACDC node (a `SerderACDC` whose type is in keripy's `DisclosedNodeIlks`). keripy main requires an attachment group after every message, so a presented ACDC with no attachment group is one it cannot parse |
| `verdict` `incomplete` | every other bundle |
| `edges` | always empty: keripy evaluated none |
| `registry` | the head `vet` returns for the registry named by the presented ACDC's top-level `rd`, as `rd` (`RegStateRecord.regid`), `n` (`.sn`), `d` (`.said`), `td` (`.acdc`) and `ts` (`.state`); `td` and `ts` are null unless `vet` returned both. Otherwise null |

How the registry is vetted. The KELs are delivered to a fresh `Kevery` and driven to quiescence after each, as in `keri.process`, except that a KEL stream keripy's parser does not read as exactly one message is not delivered. The same rule holds for registry streams: one with bytes left over after its first message is left out. The registry streams that keripy parses as a `rip` whose SAID is the `rd`, or a `bup` whose `rd` is the `rd`, are handed to `vet` with the KEL database; streams it cannot parse, and events of other registries, are left out. Each event's last attached source couple is passed to `vet` as its anchor hint. Every blinded-state disclosure attached to a registry stream or to the presented ACDC is rebuilt as a keripy `Blinder`, as `IpexHandler` rebuilds a node's proofs, and offered to `vet` in turn; the first one `vet` accepts for the head gives `td` and `ts`, and with none the head is reported with both null. The adapter withholds, reporting null, when `vet` raises, and when the inception names an AID other than the presented ACDC's issuer, which `vet` does not check unless it is also asked to bind an ACDC. It never reports a head `vet` did not return.

Where this differs from `docs/design.md`. `vet` refuses the whole chain when any presented event fails, where the design's verified chain stops at the last event before the first failure, so keripy reports no registry in cases where the design expects a shorter one. Since the verdict is never `valid`, a registry that is not reported releases the registry-state assertions rather than failing them.

Far nodes (`acdcs`) and schemas (`schemas`) are checked for shape, and `expect_schema`, when present, must be a non-empty string; a request that breaks any of these is refused as malformed (`e.input.format.request.f`). All three are otherwise unused: keripy has no standalone use for them, and the adapter answers `incomplete` before any schema would be evaluated. Nothing the adapter calls reads a clock: `vet` compares no timestamps.

## exn.verify

`exn.verify` (keripy main only) delivers the request's `kels` and then its `messages`, in order, to one fresh keripy validator: a temporary `Habery` with no identifiers of its own (`habbing.openHby(temp=True)`), a `Kevery(lax=False, local=False)` over its database, an `Exchanger` over it, and a `Parser(kvy=kvy, exc=exc)`. keripy's parser hands a KERI 2.x `exn` or `xip` to `Kevery.processMsg`, which passes an `exn` to the `Exchanger`. After each message the adapter runs `Kevery.processEscrows()` and `Exchanger.processEscrow()` until neither changes the `keri.process` tables or the exchange tables `exns`, `epse`, `esigs`, `ecigs` and `ests`.

| Reported value | keripy state it is read from |
|---|---|
| `accepted` | keripy accepted this delivery: the `Exchanger.processEvent` call keripy made while parsing it returned `True` (it authenticated the sender, by a valid sender source seal or by the delivery's signatures, and logged the message in `db.exns`); or keripy put the delivery's signatures into its partially signed exchange escrow, later logged the message, and every signature the delivery carried is among those keripy kept as verified (`db.esigs`) |
| `rejected` | otherwise, including a delivery keripy only holds in escrow (`db.epse`), which is not an acceptance, a copy of a logged message whose own signatures keripy refused, and a stream keripy's parser does not read as exactly one message |

`on_delivery` is read at quiescence after the message's own delivery, `verdict` at quiescence after the last message. The messages in `kels` get no entry, and a KEL stream that is not exactly one message is not delivered. A reading describes the delivery, the message with the attachments it arrived with, so a second delivery of a body keripy has already accepted is read on its own: a forged copy reads `rejected`. The adapter learns what keripy did with each delivery by wrapping the `Exchanger`'s `processEvent` and `escrowPSEvent` to record their outcomes without changing them; it verifies no signature itself. A stream that is not exactly one message is not delivered.

The adapter registers no route handlers, so keripy applies only its generic exchange rules, the ones the KERI layer's exchange-message cases test. Those are keripy's message parsing, which verifies the SAID and refuses fields the message type does not allow, and the `Exchanger`'s sender authentication. Either a source seal attached to the message names an event in the sender's KEL that seals the message's SAID, or the sender's signatures verify against the keys of the establishment event they name, in the sender's KEL, and satisfy its threshold; signatures by any other AID do not authenticate the sender. Registering keripy's IPEX handlers (`keri.acdc.loadHandlers`) would add IPEX workflow policy, such as requiring a grant to carry its disclosed DAG, which no exchange-message case grades. Two consequences of keripy's generic rules are worth knowing when reading results:

- keripy main does not process an exchange inception: `Kevery.processXip` is a stub, so an `xip` is never accepted and is reported `rejected`.
- The `Exchanger` checks neither `p` nor `x` for a route with no handler, so a message with a broken transaction link is accepted if its sender's signatures hold.

keripy's partially signed exchange escrow times out after 10 seconds of wall-clock time, which a case never reaches.
