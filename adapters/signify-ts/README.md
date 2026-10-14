# signify-ts adapter

Connects signify-ts's CESR stream parser to the conformance runner over adapter protocol version 1 ([`docs/adapter-protocol.md`](../../docs/adapter-protocol.md)). It implements `cesr.parse` and `cesr.encode` and declares only those operations. It composes nothing: `composes` is empty, and every value it reports comes from signify-ts's `parse()`, `Matter`, `Indexer` or `Counter`, or is read from the stream at offsets `parse()` reported. It never frames CESR itself.

## What it tests, pinned

Released signify-ts (0.4.0 on npm, 0.4.1 on its `main`) has CESR primitives and event builders but no stream parser, and it leaves KEL, ACDC and exchange-message validation to KERIA. An adapter on a release could honestly answer only `cesr.encode`. The parser this adapter tests is in a fork, [`dhh1128/signify-ts`](https://github.com/dhh1128/signify-ts), as three stacked pull requests to `WebOfTrust/signify-ts`: [#402](https://github.com/WebOfTrust/signify-ts/pull/402) (a CESR 1.x stream parser), [#403](https://github.com/WebOfTrust/signify-ts/pull/403) (CESR 2.0 framing) and [#413](https://github.com/WebOfTrust/signify-ts/pull/413) (CESR 1.1 post-quantum codes). The decision and its tradeoffs are in `this.i`, "The signify-ts adapter tests a pinned fork's stream parser".

| Package | Pin | Source |
|---|---|---|
| `signify-ts` | commit `c5bc46af038440bf8d42275481b9106abf536cf5` (package version 0.4.1) | the top of the #413 branch, `feat/cesr-pq-codes`, rebased onto upstream `main` `5a174b5` |

The pin is a git dependency in `package.json`, locked in `package-lock.json`; npm builds signify-ts with its own `prepare` script on install, which is why `allowScripts` names that commit. The parser is signify-ts's own code in signify-ts's own tree, but it is unreleased and its author also maintains this suite, so results here say nothing about released signify-ts. When the pull requests land, re-pin to a release and re-record the baselines.

`hello` reports `implementation` as `{"name": "signify-ts", "version": "0.4.1 (dhh1128/signify-ts fork)", "commit": "c5bc46af…"}`. The version comes from the installed package's `package.json` and the commit from npm's record of how it resolved the package (`node_modules/.package-lock.json`), never from constants in the adapter, so a stale install cannot report the pin. If npm recorded no commit, `hello` fails (`e.env.dependency.signify-commit.f`) rather than guess. `tests/identity.test.ts` checks that the installed commit, the `package.json` pin and `package-lock.json` agree.

## Build, test, run

Node 24 runs the TypeScript sources directly, so there is no build step. `.node-version` names the version CI uses.

```sh
cd adapters/signify-ts && npm ci && npm run typecheck && npm run coverage

# from the repository root
uv run kcs check-adapter "$PWD/adapters/signify-ts/bin/kcs-adapter-signify-ts"
uv run kcs run --adapter "$PWD/adapters/signify-ts/bin/kcs-adapter-signify-ts" --profile cesr-1.0
```

`bin/kcs-adapter-signify-ts` starts Node with `--disable-wasm-trap-handler`. signify-ts signs and verifies through libsodium compiled to WebAssembly, and V8's default trap handler reserves guard regions far larger than the 4 GiB address-space limit the runner sets, so without the flag the adapter dies at startup with "Out of memory: Cannot allocate Wasm memory". With it, V8 bounds-checks WebAssembly memory accesses instead. `tests/stdio.test.ts` starts the launcher under that limit with `prlimit` when `prlimit` is available.

## Declared features

Declared: `cesr.genus-1.00`, `cesr.genus-2.00`, `cesr.item-extents`, `cesr.serialization.json`, `keri.version-1.x` and `keri.version-2.x`. `parse()` frames bodies by both the 1.x and the 2.x version string, frames attachments with the 1.00 table for a 1.x body and with its own 2.00 table for a 2.x body, and reports a span for every message, group and primitive.

Not declared, and why:

- `cesr.domain.binary`. signify-ts has no qb2: `Matter` and `Indexer` refuse it, and `parse()` reads the text domain only.
- `cesr.native`. `parse()` needs a version string; a native CESR body has none.
- `cesr.serialization.cbor`, `cesr.serialization.mgpk`. `parse()` frames such bodies by their version string but decodes only JSON unless the caller injects a decoder. Injecting one would be adapter code doing the implementation's work, and no case has verified the framing, so they are not claimed.

## How a stream is parsed

The adapter hands the whole stream to `parse()` once, with no options. `parse()` returns the messages it framed, the errors it met and how many bytes it framed.

- If `parse()` reports any error, the stream is rejected and the class is the first error's own code: `no-version-string`, `invalid-version-size`, `malformed-body`, `unparseable-counter`, `unframable-group` or `incomplete`. `parse()` calls `incomplete` recoverable, because more bytes might complete the stream; the protocol says the stream in a request is complete ("End of input"), so here it is a rejection like the rest. The error is also written to standard error.
- Otherwise the stream is accepted, and the adapter reports every item. If `parse()` reports no error but framed fewer bytes than the stream holds, the adapter answers a harness error (`e.self.unknown.unconsumed.f`) rather than decide for it.

`parse()` is built to be resilient. Under genus 2.00 it frames a group whose code it does not know by its size and carries on, and inside a 2.00 group it stops decoding members at the first one it cannot frame without reporting an error, because the group's own size still tells it where the group ends. The adapter reports what `parse()` returned in both cases: a count code with no members, or a group with fewer members than the stream holds. Deciding that such a stream should have been rejected would make the adapter the thing being tested.

## Where each value comes from

| Reported value | Source |
|---|---|
| Accept or reject | Whether `parse()` reported an error |
| Rejection `class` | `ParseError.code` of the first error `parse()` reported |
| Message `start`, `end` | The message's `span` |
| Message `proto`, `version`, `serialization` | The message's `proto`, `version` and `kind`, from `parse()`'s reading of the version string |
| Message `size` | The span's length, which `parse()` took from the version string's size field |
| Counter `code`, `size`, `group_end` | The group's `code`, `count` and the end of its `span` |
| Counter `start` | The start of the group's `span` |
| Counter `end`, genus 1.00 | `start` plus the length of `Counter`'s re-encoding of the code at `start`, the class `parse()` sized it with |
| Counter `end`, genus 2.00 | The group's end less `count` quadlets: `parse()` ends every 2.00 group at its count code's end plus `count × 4` bytes |
| Genus item `start`, `end`, `code` | The group `parse()` framed with a `-_` code under genus 2.00: its span, and the stream's bytes over that span |
| Genus item `genus`, `version` | `genus` is the code's three genus characters; `version` is the group's `count`, which `parse()` read as one base64 number from the three version characters, written as major (`count` ÷ 4096) and minor (`count` mod 4096, at least two digits) |
| Primitive `code`, `raw` | `Matter` read from the stream's bytes over the primitive's span (the class `parse()` framed it with): `.code`, `.raw` |
| Indexed `code`, `raw`, `index` | `Indexer` read the same way: `.code`, `.raw`, `.index` |
| Indexed `ondex` | Reported only when `Indexer.Sizes[code].os > 0`. The value is `Indexer.ondex`. For current-only codes signify-ts checks that the field is zero and then stores none; for those the field is read back from the primitive's own encoding at the offsets of `Indexer.Sizes`, decoded with signify-ts's `b64ToInt` |
| `cesr.encode` text | `new Matter({raw, code}).qb64` |

The adapter checks its arithmetic against the parser wherever both exist: a count code's `end` must lie inside its group and must equal the start of the group's first member, if it has one (`e.self.unknown.group-header.f`), and a primitive read again must have the code `parse()` framed it with (`e.self.unknown.primitive-code.f`). Either mismatch is a harness error, not a report.

## Errors

`hello` negotiates from the request's `supported` list (or `[protocol]` when the list is absent) and answers with protocol 1, or with an `unsupported` error when the number 1 is not offered (`true` is not 1). Request fields the adapter does not know are ignored. A request line may be at most 64 MiB (`MAX_REQUEST_LINE`, not counting its newline). The adapter holds at most that much of a line; a longer line gets an error whose `id` is null (`e.input.range.request-size.f`), and the rest of it is dropped as it arrives. A line that is blank, not UTF-8, not a JSON object, or has no usable `id` (a non-negative integer up to 2^53 − 1, the largest JavaScript's JSON parser reads exactly, so that the response echoes the id the runner sent) gets an error whose `id` is null (`e.input.format.request.f`), and so does a malformed field (`stream`, `code`, `raw`, `domain`), with the request's `id`. `keri.process`, `keri.emit`, `acdc.verify` and `exn.verify` get an `unsupported` error (`e.feature.unsupported.undeclared-op.f`). `cesr.encode` in the binary domain is `unsupported` (`e.feature.unsupported.domain.f`); when signify-ts refuses to encode, the response is an `unsupported` error carrying its message (`e.input.format.encode-refused.f`), because that operation has no rejection result. Any other exception becomes a harness error (`e.self.unknown.exception.f`) and the session continues. Every code ends in `f`: the same request gives the same answer. `tests/schema.test.ts` checks every kind of response against `schema/adapter-protocol.schema.json`.

## CI and the baseline

CI level 2 (`docs/design.md`) for this adapter is the `signify-ts-adapter` job in `.github/workflows/ci.yml`. It installs the Node version `.node-version` names, runs `npm ci` (which refuses a `package-lock.json` that does not match `package.json`), typechecks, runs the tests with the 100% branch gate, runs `kcs check-adapter`, and then runs `kcs run` for `cesr-1.0` and for `keripy-1x-interop` and compares each report with its baseline, `baseline-cesr-1.0.json` and `baseline-keripy-1x-interop.json`, using the keripy adapter's standard-library comparison tool. A regression fails, and so does an improvement until the baseline is updated in the same change.

```sh
uv run kcs run --adapter "$PWD/adapters/signify-ts/bin/kcs-adapter-signify-ts" --profile cesr-1.0 --report /tmp/r.json
PYTHONPATH=adapters/keripy/src uv run python -m kcs_adapter_keripy.baseline write adapters/signify-ts/baseline-cesr-1.0.json /tmp/r.json
uv run kcs run --adapter "$PWD/adapters/signify-ts/bin/kcs-adapter-signify-ts" --profile keripy-1x-interop --report /tmp/i.json
PYTHONPATH=adapters/keripy/src uv run python -m kcs_adapter_keripy.baseline write adapters/signify-ts/baseline-keripy-1x-interop.json /tmp/i.json
```

The committed `cesr-1.0` baseline at `c5bc46a` is `not-conformant`: 16 cases pass, 17 fail and 8 are not sent. The 8 need `cesr.domain.binary`. The 7 `cesr.encode` cases in the text domain pass. Every `cesr.parse` case in this profile opens with a top-level genus/version code (`-_AAACAA`) before its first message, and `parse()` cannot read one there: it looks for a version string anywhere in the first 128 bytes rather than at the start, finds the message's own version string 8 bytes in, takes the message to start at byte 0, and rejects the body as `malformed-body`. So all 17 cases that expect decoded items fail, and the 9 must-reject cases pass for that reason rather than for the defect each one tests. Those 9 passes are not evidence about the parser yet.

In `keripy-1x-interop` the five must-reject cases on KERI 1.0 streams (CESR-0049, CESR-0050, CESR-0052, CESR-0054, CESR-0057) are rejected and pass, as are the three item-counted 1.00 cases CESR-0045, CESR-0046 and CESR-0047, whose decoded items match. CESR-0048 fails, for the leading genus/version code above, so the verdict is `not-interoperable`, the verdict a non-normative profile gets instead of a conformance one. In `cesr-strict` both cases pass and the verdict is `interoperable`; that profile has no committed baseline here, as for the other adapters.
