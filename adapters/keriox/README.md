# keriox adapter

Connects THCLab's keriox to the conformance runner over adapter protocol version 1 ([`docs/adapter-protocol.md`](../../docs/adapter-protocol.md)). It implements `cesr.parse` and `cesr.encode` on keriox's CESR layer (cesrox and said) and `keri.process` on its KEL engine (keri-core), and declares those three operations. It composes nothing: `composes` is empty, and every value it reports either comes from keri-core, cesrox or said or is measured from what cesrox consumed. The tables below say which, value by value.

## What it tests, pinned

| Crate | Version | Commit (from the crate's `.cargo_vcs_info.json`) | Why |
|---|---|---|---|
| `keri-core` | `=0.17.13`, default features off | `b25ba2b1b276706cbe103bc185224071a5e73579` | The newest 0.17.x on crates.io, and the KERI 1.0 line. `keri.process` runs on its processor |
| `cesrox` | `=0.1.8`, feature `cesr-proof` | `40840948fb669424a0b7629979291ee0c777bb0e` | keri-core 0.17.13 (keriox tag `v0.17.13`, the newest 0.17.x on crates.io) requires `cesrox = "0.1.8"` with `cesr-proof` |
| `said` | `=0.4.3` | `a385e69028fa2d9bd8fda31a9401ad0a630e1361` | keri-core 0.17.13 requires `said = "0.4.0"`; 0.4.3 is the newest 0.4.x. It reads version strings |

All three come from crates.io, pinned exactly in `Cargo.toml` and resolved in `Cargo.lock`. The adapter uses only the crates' public API and patches nothing. keri-core 0.18.0 is newer, but it moved to the cesrox 2.0.0 betas, whose CESR 2.0 counters count items where keripy counts quadlets, so no keripy line reads what it writes; that line is not tested here. The crates.io release of keri-core 0.17.13 is commit `b25ba2b1`, not the `ddcd2aba` the 2026-09 Rust survey built from source, and the adapter's tests re-checked the survey's findings on it.

`hello` reports `implementation` as `{"name": "keri-core", "version": "0.17.13 (cesrox 0.1.8, said 0.4.3)", "commit": "b25ba2b1… (cesrox 40840948…, said a385e690…)"}`, with all three full commits. `build.rs` reads the versions from `Cargo.lock` and looks the commits up in a table it carries; a version without a recorded commit fails the build rather than reporting a guess.

## Licence

The adapter's own source is Apache-2.0, like the rest of this repository. keri-core, cesrox and said are EUPL-1.2. A built `kcs-adapter-keriox` binary statically links them, so it is a combined work that includes EUPL-1.2 code. This repository does not distribute built binaries; CI builds one, uses it, and discards it.

## Build, test, run

```sh
cd adapters/keriox
cargo build --locked          # toolchain pinned by rust-toolchain.toml (1.97.1)
cargo test --locked

# from the repository root
uv run kcs check-adapter "$PWD/adapters/keriox/target/debug/kcs-adapter-keriox"
uv run kcs run --adapter "$PWD/adapters/keriox/target/debug/kcs-adapter-keriox" --profile cesr-v1.0
uv run kcs run --adapter "$PWD/adapters/keriox/target/debug/kcs-adapter-keriox" --profile keripy-1x-interop
uv run kcs run --adapter "$PWD/adapters/keriox/target/debug/kcs-adapter-keriox" --profile keri-v1.0.1
```

`keri.process` keeps keri-core's database in a file under the temporary directory (`TMPDIR`, else `/tmp`), one per request, removed when the request is answered.

The adapter is built in the debug profile, but `Cargo.toml` gives every dependency release-build arithmetic and assertions (`overflow-checks = false`, `debug-assertions = false`), so that they behave as they do in a release build, which is how keri-core ships them.

## Declared features, and the results that follow

Declared for the CESR operations: `cesr.genus-1.00`, `cesr.serialization.json`, `keri.version-1.x`. Declared for `keri.process`, each because keri-core does it itself, with nothing composed:

- `crypto.ed25519`: keri-core verifies Ed25519 controller, witness and receipt signatures.
- `kel.basic`, `kel.nontransferable`, `kel.multisig.numeric`, `kel.multisig.weighted`, `kel.partial-rotation`: keri-core validates each, and on the survey's keripy 1.2.14 KELs of each kind it reaches keripy's key state (`tests/process.rs`).
- `kel.delegation`: keri-core escrows a delegated inception until its delegator anchors it. Two gaps fail cases rather than being declared away: it cannot parse a delegated event whose attachments sit in a `-V` frame, the shape keripy uses to replay a KEL, and it accepts a delegated rotation without checking its delegating seal at all (see "Where keri-core differs from keripy").
- `kel.witness`: keri-core holds an event until its witness threshold is met, by attached witness signatures or by separate receipts.
- `keri.escrow`: keri-core escrows out-of-order, partially signed, partially witnessed and undelegated events and promotes them when what they wait for arrives.
- `keri.duplicity`: keri-core files a second event at a sequence number it has already accepted in a duplicitous store instead of only dropping it.
- `keri.routing`: keri-core's `parse_event_stream` frames each stream, and its processor routes each message to event or receipt handling and re-drives its escrows synchronously, so it is quiescent when `process` returns.

Not declared, and why:

- `cesr.genus-2.00`. cesrox 0.1.8 has only the genus 1.00 count-code table (`-A` controller signatures, `-B`, `-C`, `-E`, `-F`, `-G`, `-H`, `-V`, and `-L` with `cesr-proof`), item-counted except `-V`. It has no genus/version code and rejects a stream that starts with one.
- `cesr.domain.binary`. cesrox reads every code as UTF-8 text.
- `cesr.serialization.cbor`, `cesr.serialization.mgpk`. cesrox frames CBOR and MessagePack bodies, but keri-core 0.17.13 reads only JSON bodies, so the adapter has no keriox reader for their version strings and answers `unsupported`.
- `keri.version-2.x`. said 0.4.3 cannot read a 2.XX version string.
- `kel.recovery`. keri-core has no superseding recovery: it files a superseding rotation as duplicitous and keeps the events it should displace on its trunk.
- `crypto.secp256k1`, `crypto.secp256r1`, `crypto.ed448`. keri-core 0.17.13 has secp256k1 keys, but no test here exercises them in a KEL, and it has no P-256 or Ed448 verifier.

`cesr.genus-1.00` is declared because the 1.00 codes cesrox has behave as keripy 1.x's do. cesrox lacks some 1.00 codes (`-I`, `-J`, `-K` and the big counters, among others), so a case that uses one of them fails rather than being skipped.

`cesr.item-extents` is not declared. That feature promises the decoded items of every stream the implementation accepts ([`docs/adapter-protocol.md`](../../docs/adapter-protocol.md), `cesr.parse`), and this adapter knowingly cannot keep that promise: it measures every item's offsets from what cesrox consumed (see "Measured, not sourced") except inside two kinds of group cesrox does not itemize, first-seen couples (`-E`) and pathed material (`-L`). A stream with either is answered with the protocol's accepted summary. Declaring the feature would make the runner send decoded cases the adapter cannot answer, so no case with a `decoded` assertion is sent to it; those are not-supported. The adapter still reports items for every other accepted stream, and a case whose assertions are all rejections is still sent and still gets cesrox's verdict.

Every case in `cesr-v1.0` targets `cesr.genus-2.00`, so the runner sends none of them, and the verdict is `no-evidence`. In `keripy-1x-interop`, CESR-0045 to CESR-0048 have a `decoded` assertion, so those four are not-supported (CESR-0048 also needs `cesr.genus-2.00`). cesrox's output for CESR-0045, CESR-0046 and CESR-0047 does match the expected items exactly, which the adapter's own tests check. Both `cesr-strict` cases need `cesr.genus-2.00` too. The interop must-reject cases on KERI 1.0 streams, CESR-0049, CESR-0050, CESR-0052, CESR-0054 and CESR-0057, have only `rejected` assertions and need only `cesr.genus-1.00`, so they are sent, and all five pass: cesrox rejects each stream, as keripy 1.2.14 does. That run's verdict is `interoperable`, the verdict a non-normative profile gets instead of a conformance one, scoped to the five cases sent.

Every case in `keri-v1.0.1` and `keri-escrow` carries KERI 2.0 bodies behind a genus 2.00 code, so the runner sends none of them to this adapter and both verdicts are `no-evidence`. `keri.process` is exercised so far only by the adapter's own tests (`tests/process.rs`), on keripy 1.2.14 KELs. It gets suite cases when KERI 1.x interop cases are added to `keripy-1x-interop`.

## keri.process

The verdicts are keri-core's. A fresh validator is made for every request: a redb database in a new temporary directory, keri-core's `BasicProcessor`, and the escrows keri-core's `default_escrow_bus` registers on it (out of order, partially signed, partially witnessed, delegation, duplicitous). Each stream is handed unchanged to keri-core's `actor::parse_event_stream`, and each message it yields to the processor's `process`. That processor's notification bus re-drives the escrows synchronously whenever an event is added, and none of keri-core 0.17.13's escrows reads the clock, so when `process` returns keri-core is quiescent: there is nothing for the adapter to trigger. An error from `process` is keri-core refusing the message; it is logged on standard error and kept as the disposition's `reason`. The whole request runs on a worker thread, so a panic inside keri-core is a `harness` error, never a reading.

Each reading is then taken from keri-core's tables, in this order, after each delivery and again after the last:

| Reading | Source |
|---|---|
| Which message a stream is | The first message `parse_event_stream` yields. A stream it cannot parse, or that holds no message, is `rejected` at both readings |
| Key event `seen` | `EventStorage::get_event_at_sn` holds an event at its identifier and sequence number whose digest is the message's |
| `duplicitous` | `DuplicitousEvents::get` for the identifier holds an event with that digest |
| `pending` | The out-of-order escrow table (read by its name, `out_of_order_escrow`, because that escrow keeps its handle private), the partially signed escrow's `contains`, the partially witnessed escrow's `get_event_by_sn_and_digest`, or, for a `dip`, the delegation escrow under the delegator the `dip` names. `reason` names the escrow |
| `rejected` | None of the above |
| Receipt `seen` | keri-core's log holds every signature the receipt carries for the receipted digest (`get_nontrans_couplets`, or `get_trans_receipts` for a transferable receipt), and the receipted event is seen |
| Receipt `pending` | Those signatures are held, and the receipted event is not seen. keri-core keeps a receipt that arrives before its event this way, and has no such escrow for a transferable receipt |
| `trunk` | `true` for a key event whose final reading is `seen`. keri-core has no superseding recovery, so nothing it has accepted ever leaves its trunk. Always `false` for a receipt |
| `key_states` | `EventStorage::get_state` for every identifier any delivered stream names a key event for, omitted where keri-core holds none: `sn`, `said` (its last event digest), and keri-core's own serialization of `k`, `kt`, `n`, `nt`, `b`, `bt` and `di`, reported as `keys`, `kt`, `ndigs`, `nt`, `wits`, `bt` and `delegator` |

## Where keri-core differs from keripy

Re-run on this release, keri-core reaches keripy 1.2.14's final state on 17 of the 2026-09 Rust survey's 20 keripy 1.2.14 KEL items, as the survey found on its source build. The tests pin the three differences behind the other three, and a fourth this adapter's tests found, so that a change in keri-core shows:

- An event for an identifier keri-core has not seen, such as a rotation delivered before its inception, is refused ("Prefix does not match") rather than escrowed, so the events after it wait out of order for ever.
- A delegated event whose attachments are in a `-V` frame cannot be parsed, so keripy's replay of a delegated KEL is refused from the `dip` on.
- A rotation that superseding recovery permits is filed as duplicitous, and the events it should displace stay seen on the trunk.
- A delegated rotation is accepted without its delegating seal being checked. keri-core's `EventData` is an untagged serde enum in which `Rot` precedes `Drt`, so every `drt` body deserializes as a plain rotation and `EventValidator::validate_seal` never runs for it. keripy holds such a `drt` until the delegator's anchoring event arrives. Whatever event the `drt`'s seal names, delivered or not, the `drt` is accepted, which a case would grade as a MUST failure (KERI specification v1.0.1, line 1612).

## How a stream is parsed

The verdict is cesrox's: the adapter hands the whole stream to `cesrox::parse_and_send`, cesrox's own loop that calls `cesrox::parse` (one body and its attachment groups) until the stream is used up, and fails when `parse` cannot continue on a non-empty remainder. That failure is a rejection with class `ParsingError`. Because cesrox reads only from the bytes it is given and never waits for more, the protocol's end-of-input rule needs nothing further.

cesrox returns values, not offsets. To report where each item lay, the adapter replays the public cesrox functions that `parse` and `parse_group` themselves call (`payload::parse_payload`, `group::parsers::parse_group` and `group_code`, `primitives::parsers::parse_primitive::<C>`, `identifier`, `serial_number_parser`), in the order cesrox calls them, on the same bytes, and records what each one consumed. It replays exactly as many items as cesrox's own result holds and checks every replayed value, and every group's end, against what cesrox returned. If anything differs it answers a `harness` error (`e.self.unknown.replay-mismatch.f`) rather than an offset it cannot vouch for.

A first-seen couples group (`-E`) or a pathed-material group (`-L`) is not replayed item by item, because cesrox does not retain what its items would need (see "What it answers with a summary"). The walk steps over such a group to the end cesrox's own `parse_group` gave it and goes on, so a later body whose version string said cannot read is still a rejection. If cesrox and said accept the whole stream, the answer is `{"accepted": {"consumed": n}}`, where `n` is where the walk ended, the end of the stream.

Each request runs on its own worker thread. A panic inside cesrox or said is caught there and answered as a `harness` error (`e.self.unknown.panic.f`); the panic message and location go to standard error, and the adapter goes on to the next request. A panic is never reported as a rejection, because the library did not reject the stream; it failed to answer.

## Measured, not sourced

| Value | Measured as |
|---|---|
| `start` of every item | Where the cesrox function that took the item began, in the stream |
| `end` of every item | Where the remainder that function returned begins |
| `group_end` of a top-level group | Where the remainder of cesrox's own `parse_group` on that group begins |
| `group_end` of a group inside `-V` | The same, from `parse_group` on the frame's contents |
| `group_end` of the `-A` group nested in each `-F` or `-H` element | The end of the last signature cesrox took for it (cesrox reads it inline with `group_code` and a count of signatures) |
| Message `end` | Where the remainder of `parse_payload` begins. cesrox frames a JSON body as one JSON value and does not consult the version string's size |
| Indexed `code` | The first `hard_size()` characters of what cesrox consumed for the signature, `hard_size()` being cesrox's own for the code it parsed. cesrox's `AttachedSignatureCode::to_str()` is not used, because it cannot render every code cesrox's parser accepts |

## Where each value comes from

| Reported value | Source |
|---|---|
| Accept or reject | `cesrox::parse_and_send`; class `ParsingError` |
| Message `proto`, `version`, `serialization`, `size` | said's `SerializationInfo`, deserialized from the body's `v` field with `serde_json`, as keri-core's event types do: `protocol_code`, `major_version`.`minor_version`, `kind.to_str()`, `size`. A body whose `v` said cannot read is a rejection with class `VersionString` |
| Counter `code`, `size` | cesrox's `GroupCode`: the hard part of `to_str()`, and the count it decoded |
| Primitive `code`, `raw` | cesrox's code type (`Basic`, `SelfAddressing`, `SelfSigning`, `SerialNumberCode`) `.to_str()`, and the raw bytes `parse_primitive` decoded |
| Sequence number `raw` (`0A`) | `parse_primitive::<SerialNumberCode>`, which returns the raw bytes it decoded. cesrox's groups call `serial_number_parser`, which returns a `u64` instead; the adapter replays both on the same bytes and checks that they agree |
| Indexed `index` | `Index::current()` |
| Indexed `ondex` | Reported only for cesrox's `Index::Dual` and `Index::BigDual`, from `prev_next()`. cesrox's current-only variants carry no ondex, so none is reported for them, even for codes whose table row defines an ondex field. A case that expects one fails, and that failure is cesrox's |
| `cesr.encode` | `CesrPrimitive::to_str()` on `(code, raw)`, with the code from the first of cesrox's `Basic`, `SelfAddressing` and `SelfSigning` whose `FromStr` accepts it and whose `to_str()` gives it back exactly. A code none of them accepts is cesrox's refusal, answered as a rejection whose class is cesrox's error variant, such as `UnknownCodeError` for `0A` or `M` |

## What it answers with a summary

- A stream with a first-seen couple (`-E`): cesrox reads the timestamp's characters as text and never decodes a raw value.
- A stream with a pathed-material group (`-L`, from `cesr-proof`): cesrox keeps the path in private fields and the contents without offsets.

## What it answers `unsupported`

- A CBOR or MessagePack body (`e.feature.unsupported.serialization.f`).
- `cesr.encode` in the binary domain (`e.feature.unsupported.binary-domain.f`), which this adapter does not declare. A code cesrox reads but cannot give back exactly would be `e.feature.unsupported.code.f`; no such code is known.
- `keri.emit` (`e.feature.unsupported.undeclared-op.f`).
- `keri.process` from any perspective but an ordinary validator's (`e.feature.unsupported.perspective.f`).

## Errors

`hello` negotiates from the request's `supported` list, or `[protocol]` when the list is absent, and answers with protocol 1, or with an `unsupported` error (`e.feature.unsupported.protocol-version.f`) when 1 is not offered. Request fields the adapter does not know are ignored. A request line may be at most 64 MiB (`protocol::MAX_REQUEST_LINE`, not counting its newline); the adapter holds at most that much of a line, answers a longer one with an error whose `id` is null (`e.input.range.request-size.f`), drops the rest of it, and answers the next request. A line that is not a JSON object, including a blank line, or a request whose `id` is not a non-negative integer, gets an error whose `id` is null (`e.input.format.request.f`). A request without a string `op` or with malformed fields is a `harness` error carrying its id (`e.input.format.request.f`), and an unknown `op` is too (`e.input.range.unknown-op.f`). The adapter exits with status 0 at end of input. If it cannot read standard input or write standard output, it explains why on standard error (`e.env.io.stdio.f`) and exits with status 1. A `keri.process` request whose `perspective` is not an object, or whose `messages` is not a list of objects each with a lowercase hex `stream`, is a `harness` error (`e.input.format.request.f`). If keri-core's database cannot be created or read in the temporary directory, the request is a `harness` error (`e.env.io.storage.r`). Every code ends in `f` except `e.self.resource.worker-thread.r`, the failure to start a worker thread, and `e.env.io.storage.r`; both may clear on retry.

## Results

<!-- BEGIN generated results: scripts/reproduce-results writes this table from results/; do not edit it -->

| Implementation | Profile | Verdict | Active MUST pass / fail | Active SHOULD pass / fail | Active INTEROP pass / fail | Active cases not supported | Result |
| --- | --- | --- | --- | --- | --- | --- | --- |
| cesrox 0.1.8 (said 0.4.3) | `cesr-v1.0` | no-evidence | 0 / 0 | 0 / 0 | 0 / 0 | 39 | [2026-10-15, suite b270e092](../../results/cesrox/0.1.8-said-0.4.3/cesr-v1.0.json) |
| cesrox 0.1.8 (said 0.4.3) | `keripy-1x-interop` | interoperable | 0 / 0 | 0 / 0 | 5 / 0 | 4 | [2026-10-15, suite b270e092](../../results/cesrox/0.1.8-said-0.4.3/keripy-1x-interop.json) |

<!-- END generated results -->

## CI and the committed results

The `keriox-adapter` job in `.github/workflows/ci.yml` installs the toolchain `rust-toolchain.toml` names, builds with `--locked`, runs `cargo test` and runs `kcs check-adapter`. It does not run a profile: the table under Results is generated from this adapter's committed results, `results/cesrox/0.1.8-said-0.4.3/<profile>.json`, which the suite's maintainer refreshes and checks locally (`docs/design.md`, Continuous integration). The tool builds the adapter itself, as above, before it runs it:

```sh
uv run python scripts/reproduce-results check --adapter keriox     # compare a fresh run with the committed results
uv run python scripts/reproduce-results refresh --adapter keriox   # replace them, from a clean tree
```

`check` fails on a regression, and on an improvement too, including a different keri-core, cesrox or said commit, until the results are refreshed in the same change.
