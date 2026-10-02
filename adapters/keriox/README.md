# keriox adapter

Connects the CESR layer of THCLab's keriox to the conformance runner over adapter protocol version 1 ([`docs/adapter-protocol.md`](../../docs/adapter-protocol.md)). It implements `cesr.parse` and `cesr.encode` and declares only those operations. It composes nothing: `composes` is empty, and every value it reports either comes from cesrox or said or is measured from what cesrox consumed. The tables below say which, value by value.

## What it tests, pinned

| Crate | Version | Commit (from the crate's `.cargo_vcs_info.json`) | Why |
|---|---|---|---|
| `cesrox` | `=0.1.8`, feature `cesr-proof` | `40840948fb669424a0b7629979291ee0c777bb0e` | keri-core 0.17.13 (keriox tag `v0.17.13`, the newest 0.17.x on crates.io) requires `cesrox = "0.1.8"` with `cesr-proof` |
| `said` | `=0.4.3` | `a385e69028fa2d9bd8fda31a9401ad0a630e1361` | keri-core 0.17.13 requires `said = "0.4.0"`; 0.4.3 is the newest 0.4.x. It reads version strings |

Both come from crates.io, pinned exactly in `Cargo.toml` and resolved in `Cargo.lock`. keri-core itself is not a dependency: these operations need only its CESR layer. The adapter uses only the crates' public API and patches nothing. The cesrox 2.0.0 betas on crates.io are a different line, not what keri-core 0.17.x ships, and are not tested here.

`hello` reports `implementation` as `{"name": "cesrox", "version": "0.1.8 (said 0.4.3)", "commit": "40840948… (said a385e690…)"}`, with both full commits. `build.rs` reads the versions from `Cargo.lock` and looks the commits up in a table it carries; a version without a recorded commit fails the build rather than reporting a guess.

## Licence

The adapter's own source is Apache-2.0, like the rest of this repository. cesrox and said are EUPL-1.2. A built `kcs-adapter-keriox` binary statically links them, so it is a combined work that includes EUPL-1.2 code. This repository does not distribute built binaries; CI builds one, uses it, and discards it.

## Build, test, run

```sh
cd adapters/keriox
cargo build --locked          # toolchain pinned by rust-toolchain.toml (1.97.1)
cargo test --locked

# from the repository root
uv run kcs check-adapter "$PWD/adapters/keriox/target/debug/kcs-adapter-keriox"
uv run kcs run --adapter "$PWD/adapters/keriox/target/debug/kcs-adapter-keriox" --profile cesr-1.0
uv run kcs run --adapter "$PWD/adapters/keriox/target/debug/kcs-adapter-keriox" --profile keripy-1x-interop
```

The adapter is built in the debug profile, but `Cargo.toml` gives every dependency release-build arithmetic and assertions (`overflow-checks = false`, `debug-assertions = false`), so that they behave as they do in a release build, which is how keri-core ships them.

## Declared features, and the results that follow

Declared: `cesr.genus-1.00`, `cesr.serialization.json`, `keri.version-1.x`. Not declared, and why:

- `cesr.genus-2.00`. cesrox 0.1.8 has only the genus 1.00 count-code table (`-A` controller signatures, `-B`, `-C`, `-E`, `-F`, `-G`, `-H`, `-V`, and `-L` with `cesr-proof`), item-counted except `-V`. It has no genus/version code and rejects a stream that starts with one.
- `cesr.domain.binary`. cesrox reads every code as UTF-8 text.
- `cesr.serialization.cbor`, `cesr.serialization.mgpk`. cesrox frames CBOR and MessagePack bodies, but keri-core 0.17.13 reads only JSON bodies, so the adapter has no keriox reader for their version strings and answers `unsupported`.
- `keri.version-2.x`. said 0.4.3 cannot read a 2.XX version string.

`cesr.genus-1.00` is declared because the 1.00 codes cesrox has behave as keripy 1.x's do. cesrox lacks some 1.00 codes (`-I`, `-J`, `-K` and the big counters, among others), so a case that uses one of them fails rather than being skipped.

Every case in `cesr-1.0` targets `cesr.genus-2.00`, so the runner sends none of them: 41 cases not-supported, verdict `no-evidence`. In `keripy-1x-interop`, CESR-0045, CESR-0046 and CESR-0047 pass, and CESR-0048 is not-supported because it also needs `cesr.genus-2.00`. Those assertions are at level INTEROP, so that verdict is `no-evidence` as well.

## How a stream is parsed

The verdict is cesrox's: the adapter hands the whole stream to `cesrox::parse_and_send`, cesrox's own loop that calls `cesrox::parse` (one body and its attachment groups) until the stream is used up, and fails when `parse` cannot continue on a non-empty remainder. That failure is a rejection with class `ParsingError`. Because cesrox reads only from the bytes it is given and never waits for more, the protocol's end-of-input rule needs nothing further.

cesrox returns values, not offsets. To report where each item lay, the adapter replays the public cesrox functions that `parse` and `parse_group` themselves call (`payload::parse_payload`, `group::parsers::parse_group` and `group_code`, `primitives::parsers::parse_primitive::<C>`, `identifier`, `serial_number_parser`), in the order cesrox calls them, on the same bytes, and records what each one consumed. It replays exactly as many items as cesrox's own result holds and checks every replayed value, and every group's end, against what cesrox returned. If anything differs it answers a `harness` error (`e.self.unknown.replay-mismatch.f`) rather than an offset it cannot vouch for.

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
| `cesr.encode` | `CesrPrimitive::to_str()` on `(code, raw)`, with the code from the first of cesrox's `Basic`, `SelfAddressing` and `SelfSigning` whose `FromStr` accepts it and whose `to_str()` gives it back exactly |

## What it answers `unsupported`

- A first-seen couple (`-E`): cesrox reads the timestamp's characters as text and never decodes a raw value (`e.feature.unsupported.raw-not-retained.f`).
- A pathed-material group (`-L`, from `cesr-proof`): cesrox keeps the path in private fields and the contents without offsets (`e.feature.unsupported.pathed-material.f`).
- A CBOR or MessagePack body (`e.feature.unsupported.serialization.f`).
- `cesr.encode` in the binary domain (`e.feature.unsupported.binary-domain.f`), and a code cesrox has no encoder for, such as `0A` or `M` (`e.feature.unsupported.code.f`).
- `keri.process` and `keri.emit` (`e.feature.unsupported.undeclared-op.f`).

## Errors

`hello` negotiates from the request's `supported` list, or `[protocol]` when the list is absent, and answers with protocol 1, or with an `unsupported` error (`e.feature.unsupported.protocol-version.f`) when 1 is not offered. Request fields the adapter does not know are ignored. A request line may be at most 64 MiB (`protocol::MAX_REQUEST_LINE`, not counting its newline); the adapter holds at most that much of a line, answers a longer one with an error whose `id` is null (`e.input.range.request-size.f`), drops the rest of it, and answers the next request. A line that is not a JSON object, including a blank line, or a request whose `id` is not a non-negative integer, gets an error whose `id` is null (`e.input.format.request.f`). A request without a string `op` or with malformed fields is a `harness` error carrying its id (`e.input.format.request.f`), and an unknown `op` is too (`e.input.range.unknown-op.f`). The adapter exits with status 0 at end of input. Every code ends in `f` except `e.self.resource.worker-thread.r`, which is the failure to start a worker thread and may clear on retry.

## CI and the baselines

CI level 2 (`docs/design.md`) for this adapter is the `keriox-adapter` job in `.github/workflows/ci.yml`. It installs the toolchain `rust-toolchain.toml` names, builds with `--locked`, runs `cargo test`, runs `kcs check-adapter`, and then compares two runs with the baselines here: `cesr-1.0` with `baseline-cesr-1.0.json`, and `keripy-1x-interop` with `baseline-keripy-1x-interop.json`. The comparison is the keripy adapter's standard-library tool, `python -m kcs_adapter_keripy.baseline compare` with `PYTHONPATH=adapters/keripy/src`, with the rules its README gives: a regression fails the job, and so does an improvement, including a different cesrox or said commit, until the baseline is updated in the same change:

```sh
uv run kcs run --adapter "$PWD/adapters/keriox/target/debug/kcs-adapter-keriox" --profile cesr-1.0 --report /tmp/r.json
PYTHONPATH=adapters/keripy/src uv run python -m kcs_adapter_keripy.baseline write adapters/keriox/baseline-cesr-1.0.json /tmp/r.json
```
