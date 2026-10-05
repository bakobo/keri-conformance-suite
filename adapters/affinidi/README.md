# Affinidi adapter

Connects Affinidi's Rust CESR/KERI crates to the conformance runner over adapter protocol version 1 ([`docs/adapter-protocol.md`](../../docs/adapter-protocol.md)). It implements `cesr.parse` and `cesr.encode` and declares only those operations. It composes nothing: `composes` is empty, and every value it reports comes from Affinidi's own parsing or from the bytes Affinidi said it consumed. It never parses CESR itself. Affinidi's public API does not say where each item of a stream lay, so the adapter does not report items: it answers every stream Affinidi accepts with the protocol's accepted summary, the number of bytes Affinidi consumed.

## Pins

| Crate | Version | Source commit (from the crate's `.cargo_vcs_info.json`) | Role |
|---|---|---|---|
| `affinidi-keri-core` | `=0.4.0` | `6277ae866c5761edb5cfa807a5f7ac83ebf3700c` (affinidi/affinidi-keri-rs) | Stream parser and message framing; names the implementation in `hello` |
| `affinidi-cesr` | `=0.1.3` | `b970cb01bdd1acd0530137b67460579e4624ab47` (affinidi/affinidi-tdk-rs) | Primitives (`Matter`), used by `cesr.encode` and by the parser; its version and commit are part of `hello`'s implementation identity |

Both are the latest releases on crates.io as of 2026-10-02, pinned exactly in `Cargo.toml` and locked in `Cargo.lock`. The adapter uses only their public API and patches nothing. `hello` reports name `affinidi-keri-core`, version `0.4.0 (affinidi-cesr 0.1.3)` and commit `6277ae86… (affinidi-cesr b970cb01…)`, so moving either pin changes the identity the baseline gate compares. `tests/pins.rs` fails if those constants in `src/protocol.rs` drift from `Cargo.lock` or from the commits crates.io published. To move a pin, change it in `Cargo.toml`, run `cargo update -p <crate> --precise <version>`, update the constants, and re-record the baseline.

The toolchain is Rust 1.95.0 (`rust-toolchain.toml`), the `rust-version` both crates declare.

```sh
cd adapters/affinidi && cargo build --locked && cargo test --locked

# from the repository root
uv run kcs check-adapter "$PWD/adapters/affinidi/target/debug/kcs-adapter-affinidi"
uv run kcs run --adapter "$PWD/adapters/affinidi/target/debug/kcs-adapter-affinidi" --profile cesr-1.0
```

## Declared features

A feature is a claim about what the implementation and this adapter can do together, not about the implementation alone. Declared: `cesr.genus-1.00`, `cesr.serialization.json` and `keri.version-1.x`. Affinidi frames JSON bodies by a legacy `KERI10JSON…_` version string and reads the 1.00 count codes `-A`, `-B`, `-C`, `-E`, `-F`, `-G` and `-V`, with `-0X` as their big forms (`affinidi_keri_core::counter_table`); `-D` is modelled but refused, and other 1.00 codes are unknown to it. A 1.00 case that uses one of those fails rather than being skipped.

Not declared, and why:

- `cesr.item-extents`. Affinidi's parser does not report where any item lay (see "How a stream is parsed"), so the adapter answers accepted streams with a summary. The runner therefore sends it no case with a decoded assertion, only cases whose assertions are all rejections.
- `cesr.genus-2.00`. Affinidi has no genus/version codes, so a stream that opens with `-_AAACAA` is rejected at its first byte. Its `CounterTable::V2` is not the CESR 2.00 master table (it maps `-A` to attached material and `-B` to controller signatures), and no 2.x version string parses (`Version::parse_str` accepts only the 17-character 1.x form). Every case in the `cesr-1.0` profile requires this feature, so none of them is sent.
- `keri.version-2.x`, `cesr.native`: no 2.x version strings and no native CESR bodies (`parser::parse_next` refuses a stream that does not start with `{` or a CBOR/MessagePack map byte).
- `cesr.domain.binary`: the parser rejects non-ASCII attachment bytes, so it reads attachments in the text domain only. `Matter` can encode qb2, but a feature is a claim about the whole implementation.
- `cesr.serialization.cbor`, `cesr.serialization.mgpk`: Affinidi's `Serder` has CBOR and MessagePack kinds, but no case exercises them and this adapter has not verified that framing, so they are not claimed.

## How a stream is parsed

The verdict is Affinidi's: the adapter hands the whole stream to `affinidi_keri_core::parser::parse_all`, the strict parser Affinidi's own verifiers use. Any error is a rejection whose class is the `CoreError` variant, for example `CoreError::ParseError`.

When `parse_all` accepts the stream, the adapter answers `{"accepted": {"consumed": n}}`. It measures `n` by walking the stream again as `parse_all` does: it skips the whitespace `parse_all` skips between messages and calls `parse_next`, the function `parse_all` calls once per message, adding up the bytes `parse_next` says it consumed. If that walk disagrees with `parse_all` — a message `parse_next` rejects, a different number of messages, or a byte count of zero or past the end of the stream — the adapter answers a harness error (`e.self.unknown.measurement.f`) rather than a number it cannot vouch for.

This is the central limitation. Affinidi's parser returns attachments as decoded groups (`Vec<Siger>`, receipt couples and so on). It does not say where any item lay in the stream, which count codes it read, what their size fields held, or where each group ended, and it merges the contents of a `-V` group into the list without a trace of the `-V`. The only way to produce those items would be for the adapter to walk the attachments itself with Affinidi's primitive decoders, deciding from each count code how many items follow. That would be the adapter's parser being tested, with offsets computed from counts, so it does not do it. The summary still lets a case that must be rejected grade Affinidi: if Affinidi accepts such a stream, the case fails.

## Measured, not sourced

| Value | Measured as |
|---|---|
| `consumed` | The sum of the byte counts `parse_next` returned for each message, plus the whitespace `parse_all` skips between messages |

## Where each value comes from

| Reported value | Source |
|---|---|
| Accept or reject | `parser::parse_all` |
| Rejection `class` | `CoreError::<variant>` of the error `parse_all` returned |
| `cesr.encode` text | `Matter::new(code, raw)?.qb64()` |
| `cesr.encode` binary | `Matter::new(code, raw)?.qb2()` |
| Decoded items of any kind | Never reported: Affinidi's parser does not expose them (see above) |

## Errors

`hello` negotiates from the request's `supported` list (or `[protocol]` when the list is absent) and answers with protocol 1, or with an `unsupported` error when the integer 1 is not offered. Request fields the adapter does not know are ignored. A request line may be at most 64 MiB (`protocol::MAX_REQUEST_LINE`, not counting its newline). The adapter reads at most that far before deciding; a longer line gets an error whose `id` is null (`e.input.range.request-size.f`) and the rest of it is skipped a buffer at a time, never held whole. A line that is blank, not UTF-8, not a JSON object, or has no usable `id` (a non-negative integer up to 2^64−1) gets an error whose `id` is null (`e.input.format.request.f`). `keri.process` and `keri.emit` get an `unsupported` error. When Affinidi refuses to encode, the response is an `unsupported` error naming its `CesrError` variant (`e.input.format.encode-refused.f`), because that operation has no rejection result. A panic anywhere in an operation, including inside Affinidi, is caught and answered as a harness error (`e.self.unknown.panic.f`), so the session continues. Every error is also written to standard error, which the runner keeps in its report.

## CI and the baseline

CI level 2 (`docs/design.md`) for this adapter is the `affinidi-adapter` job in `.github/workflows/ci.yml`. It installs Rust 1.95.0 with rustup, builds with `--locked`, runs `cargo fmt --check`, `cargo clippy -D warnings` and `cargo test`, runs `kcs check-adapter`, and then runs `kcs run --profile cesr-1.0` and compares the report with `baseline-cesr-1.0.json`. The comparison is the keripy adapter's tool, run from source with `PYTHONPATH=adapters/keripy/src`; it uses only the standard library, so keripy is not installed. Its rules are the keripy job's: a regression fails, and so does an improvement until the baseline is updated in the same change.

```sh
uv run kcs run --adapter "$PWD/adapters/affinidi/target/debug/kcs-adapter-affinidi" --profile cesr-1.0 --report /tmp/r.json
PYTHONPATH=adapters/keripy/src uv run python -m kcs_adapter_keripy.baseline write adapters/affinidi/baseline-cesr-1.0.json /tmp/r.json
```

The committed baseline is `affinidi-keri-core` 0.4.0 at `6277ae86…` with `affinidi-cesr` 0.1.3 at `b970cb01…`, verdict `no-evidence`: all 41 `cesr-1.0` cases are `not-supported`, because every one requires `cesr.genus-2.00`. That is the accurate result for this implementation, not a gap in the adapter.

In `keripy-1x-interop`, CESR-0045, CESR-0046 and CESR-0047 need `cesr.item-extents` and CESR-0048 also needs `cesr.genus-2.00`, so none is sent; in `cesr-strict`, both cases need `cesr.genus-2.00`. Every case that must be rejected today is a 2.00 case, so the accepted summary does not yet produce evidence for Affinidi; it will once there are must-reject cases on 1.00 streams.
