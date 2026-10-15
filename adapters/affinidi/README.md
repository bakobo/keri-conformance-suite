# Affinidi adapter

Connects Affinidi's Rust CESR/KERI crates to the conformance runner over adapter protocol version 1 ([`docs/adapter-protocol.md`](../../docs/adapter-protocol.md)). It implements `cesr.parse`, `cesr.encode` and `keri.process`, and declares only those operations. For CESR it composes nothing: every value it reports comes from Affinidi's own parsing or from the bytes Affinidi said it consumed, and it never parses CESR itself. For `keri.process` every acceptance is Affinidi's, and so is every rejection of an event the adapter could hand to Affinidi's `Kever`. The routing around those verdicts is the adapter's, including the few refusals routing makes on its own, so `composes` is `["keri.routing"]` (see "keri.process" below). For `cesr.parse`, Affinidi's public API does not say where each item of a stream lay, so the adapter does not report items: it answers every stream Affinidi accepts with the protocol's accepted summary, the number of bytes Affinidi consumed.

## Pins

| Crate | Version | Source commit (from the crate's `.cargo_vcs_info.json`) | Role |
|---|---|---|---|
| `affinidi-keri-core` | `=0.4.0` | `6277ae866c5761edb5cfa807a5f7ac83ebf3700c` (affinidi/affinidi-keri-rs) | Stream parser and message framing; names the implementation in `hello` |
| `affinidi-keri-crypto` | `=0.4.0` | `6277ae866c5761edb5cfa807a5f7ac83ebf3700c` (affinidi/affinidi-keri-rs) | Verification keys (`Verfer`) built from an event's `k` field for `keri.process`; same workspace and commit as `affinidi-keri-core`, so the implementation identity already covers it |
| `affinidi-cesr` | `=0.1.3` | `b970cb01bdd1acd0530137b67460579e4624ab47` (affinidi/affinidi-tdk-rs) | Primitives (`Matter`), used by `cesr.encode` and by the parser; its version and commit are part of `hello`'s implementation identity |

Both are the latest releases on crates.io as of 2026-10-02, pinned exactly in `Cargo.toml` and locked in `Cargo.lock`. The adapter uses only their public API and patches nothing. `hello` reports name `affinidi-keri-core`, version `0.4.0 (affinidi-cesr 0.1.3)` and commit `6277ae86… (affinidi-cesr b970cb01…)`, so moving either pin changes the identity the committed results record. `tests/pins.rs` fails if those constants in `src/protocol.rs` drift from `Cargo.lock` or from the commits crates.io published, and if `affinidi-keri-crypto` is not at `affinidi-keri-core`'s version and commit. To move a pin, change it in `Cargo.toml`, run `cargo update -p <crate> --precise <version>`, update the constants, and refresh the committed results.

The toolchain is Rust 1.95.0 (`rust-toolchain.toml`), the `rust-version` both crates declare.

```sh
cd adapters/affinidi && cargo build --locked && cargo test --locked

# from the repository root
uv run kcs check-adapter "$PWD/adapters/affinidi/target/debug/kcs-adapter-affinidi"
uv run kcs run --adapter "$PWD/adapters/affinidi/target/debug/kcs-adapter-affinidi" --profile cesr-v1.0
```

## Declared features

A feature is a claim about what the implementation and this adapter can do together, not about the implementation alone. Declared for CESR: `cesr.genus-1.00`, `cesr.serialization.json` and `keri.version-1.x`. Affinidi frames JSON bodies by a legacy `KERI10JSON…_` version string and reads the 1.00 count codes `-A`, `-B`, `-C`, `-E`, `-F`, `-G` and `-V`, with `-0X` as their big forms (`affinidi_keri_core::counter_table`); `-D` is modelled but refused, and other 1.00 codes are unknown to it. A 1.00 case that uses one of those fails rather than being skipped.

Declared for `keri.process`, each because Affinidi's `Kever` has the check and the adapter calls it:

- `kel.basic`: `Kever::new` checks an inception's SAID, signatures and prefix derivation; `Kever::verify_update` checks a rotation's or interaction's SAID, sequence number, prior event digest, signatures and pre-rotation commitment. Affinidi records the configuration traits in `c` but enforces none: an interaction after an establishment-only (`EO`) inception is accepted, and a case that checks it fails. The adapter reports what Affinidi did rather than enforcing a trait Affinidi does not.
- `kel.multisig.numeric` and `kel.multisig.weighted`: `Threshold::is_satisfied` over the indexed signatures, for numeric thresholds and for weighted clauses. Affinidi reads a weighted threshold only in its nested form (`[["1/2","1/2"]]`) and rejects keripy's flat single-clause form (`["1/2","1/2"]`), and it reads a numeric threshold as decimal where KERI writes hex, so the two agree only below 10. Cases in those forms fail rather than being skipped.
- `kel.delegation`: `Kever::new_delegated` and `Kever::verify_update_delegated` check that the delegator's event named by the seal source couple anchors a seal for exactly this event. Affinidi does not check the delegator's `DND` (do not delegate) trait, so a delegation that trait forbids is accepted, and a case that checks it fails.
- `kel.witness`: `Kever::verify_witness_receipts_static` counts verified receipt couples (`-C`) from designated witnesses against the event's witness threshold, including after a rotation changes the witness list. It does not count witness indexed signatures (`-B`), the form keripy attaches, so a case that receipts with `-B` fails.
- `crypto.ed25519`: every key and signature the tests use. Affinidi's `Verfer` also verifies secp256k1 and secp256r1, but no test here exercises them, so they are not claimed.
- `keri.routing`: supplied by the adapter, and listed in `composes`.

Not declared, and why:

- `cesr.item-extents`. Affinidi's parser does not report where any item lay (see "How a stream is parsed"), so the adapter answers accepted streams with a summary. The runner therefore sends it no case with a decoded assertion, only cases whose assertions are all rejections.
- `cesr.genus-2.00`. Affinidi has no genus/version codes, so a stream that opens with `-_AAACAA` is rejected at its first byte. Its `CounterTable::V2` is not the CESR 2.00 master table (it maps `-A` to attached material and `-B` to controller signatures), and no 2.x version string parses (`Version::parse_str` accepts only the 17-character 1.x form). Every case in the `cesr-v1.0` profile requires this feature, so none of them is sent.
- `keri.version-2.x`, `cesr.native`: no 2.x version strings and no native CESR bodies (`parser::parse_next` refuses a stream that does not start with `{` or a CBOR/MessagePack map byte).
- `cesr.domain.binary`: the parser rejects non-ASCII attachment bytes, so it reads attachments in the text domain only. `Matter` can encode qb2, but a feature is a claim about the whole implementation.
- `cesr.serialization.cbor`, `cesr.serialization.mgpk`: Affinidi's `Serder` has CBOR and MessagePack kinds, but no case exercises them and this adapter has not verified that framing, so they are not claimed.
- `kel.nontransferable`: `Threshold::from_json_value` refuses `"0"` for every threshold, `nt` included, so Affinidi rejects every non-transferable inception, its own included.
- `kel.partial-rotation`: Affinidi requires a rotation's keys to match the prior next-key digests one for one and in order, and its parser does not read the big indexed signature codes (`2A`…) keripy uses when a signature's two indexes differ.
- `kel.recovery`: `Kever` accepts only the event at the next sequence number, so no superseding rotation is ever accepted.
- `keri.escrow`: Affinidi's `Escrow` type exists, but none of its validation paths uses it. An event that arrives before what it needs is rejected and stays rejected.
- `keri.duplicity`: a second event at a sequence number Affinidi already holds is refused by `Kever` as out of order, not recorded as duplicitous. Affinidi's `Judge` keeps a duplicitous-event log, but this adapter does not use `Judge` (see below).
- `keri.version-2.x`: no 2.x version strings, as above.

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
| `cesr.encode` rejection `class` | `CesrError::<variant>` of the error `Matter` returned |
| Decoded items of any kind | Never reported: Affinidi's parser does not expose them (see above) |

## keri.process

Each request gets a fresh validator, and each message is delivered to it in order. The adapter parses a message with `parser::parse_all`, the strict parser, and requires exactly one message. It then makes the one `Kever` call the message's ilk needs:

| Ilk | Affinidi call |
|---|---|
| `icp` | `Kever::new`, then `Kever::verify_witness_receipts` |
| `dip` | `Kever::new_delegated`, then `Kever::verify_witness_receipts` |
| `rot`, `ixn` | `Kever::verify_update` on the prefix's `Kever`, then `Kever::verify_witness_receipts_static` against the proposed state, then `apply_verified_update` |
| `drt` | `Kever::verify_update_delegated`, then the same witness check and update |

Anything else, an `rct` included, is not handed to a `Kever` and is reported rejected. Affinidi's validator has no processing for a receipt message. Kever counts only receipt couples attached to the event they receipt, and holding a receipt for a later event would be an escrow that Affinidi does not have.

This sequencing is the adapter's, which is why `keri.routing` is in `composes`. It does four things Affinidi leaves to its caller. It picks the call from the ilk. It keeps one `Kever` per prefix, refusing a second inception of a prefix it already holds, as Affinidi's direct mode does. It records the body of every event Affinidi accepted. And it answers Affinidi's `DelegatorAnchors` lookup, whose contract is that it returns anchors only from events already verified, from that record alone. Routing therefore refuses some messages without asking a `Kever`: a receipt message, a message that is not a key event, a stream that is not exactly one message Affinidi can parse and identify, a non-inception event for a prefix no `Kever` holds, a delegated event with no seal source couple, and a second inception of a held prefix. Each is reported rejected, which in this protocol means not accepted, and its `reason` begins `routing:` so that a reader can tell it from a verdict of Affinidi's. Where Affinidi's own did:webs verifier makes the same choices, the adapter follows it: the delegation proof is the first seal source couple attached, and the receipt couples counted are those attached to the event.

The adapter does not use Affinidi's higher-level validator, `affinidi_keri::direct` and the `Judge` built on it. Direct mode returns success for a `rot`, `ixn` or `drt` whose prefix it holds no state for, so its return value cannot back a reading. It also accepts only `icp` as an inception, so it cannot process a delegated identifier at all (`affinidi-keri` 0.4.0, `src/direct.rs`, the "in direct mode we skip" branch, and `Kever::new_from_parts`, which refuses everything but `icp`). `this.i` records the decision.

### Where each value comes from

| Reported value | Source |
|---|---|
| `initial` | `seen` if, after the message's own delivery, Affinidi has accepted an event with exactly this body, otherwise `rejected` |
| `final` | The same test after the last message. An event Affinidi accepted is never removed, so a message seen on delivery stays seen. A message rejected on delivery reads seen at the end only when a later delivery of the same body was accepted |
| `trunk` | Equal to `final` being `seen`: without recovery, every accepted event is on the trunk, and a receipt is never seen |
| `reason` | The `CoreError` Affinidi returned, or why the adapter could not hand the message to a `Kever`; given only for a message not seen on delivery |
| `key_states` | One entry per prefix with a `Kever`, from `Kever::state()` |
| `sn`, `keys`, `ndigs`, `wits`, `delegator` | `KeyState` `sn`, `keys`, `next_keys`, `backers`, `delegator` |
| `said` | `KeyState::last_event_digest`, the SAID of the last event accepted |
| `kt`, `nt` | `KeyState` `threshold` and `next_threshold`. A numeric threshold is the number Affinidi holds, written in hex as KERI writes it, so a `kt` of `"10"`, which Affinidi reads as ten, is reported as `"a"`. A weighted threshold is `Threshold::to_json_value`, always nested |
| `bt` | `KeyState::backer_threshold`, in hex |

The readings use only `seen` and `rejected`. Affinidi has no escrow, so nothing is `pending`, and it records no duplicity, so nothing is `duplicitous`.

## Errors

`hello` negotiates from the request's `supported` list (or `[protocol]` when the list is absent) and answers with protocol 1, or with an `unsupported` error when the integer 1 is not offered. Request fields the adapter does not know are ignored. A request line may be at most 64 MiB (`protocol::MAX_REQUEST_LINE`, not counting its newline). The adapter reads at most that far before deciding; a longer line gets an error whose `id` is null (`e.input.range.request-size.f`) and the rest of it is skipped a buffer at a time, never held whole. A line that is blank, not UTF-8, not a JSON object, or has no usable `id` (a non-negative integer up to 2^64−1) gets an error whose `id` is null (`e.input.format.request.f`). `keri.emit` gets an `unsupported` error. A `keri.process` request whose `perspective` is not an object, or whose `messages` is not a list of objects each with a lowercase hex `stream`, gets a harness error (`e.input.format.request.f`); a perspective other than `{"role": "validator"}` gets an `unsupported` error (`e.feature.unsupported.perspective.f`). Everything Affinidi refuses, and every stream it cannot parse, is a rejected reading, never an error. When Affinidi refuses to encode, the response is a rejection result whose class is the `CesrError` variant, as the protocol requires of a refusal, and Affinidi's message goes to standard error. A panic anywhere in an operation, including inside Affinidi, is caught and answered as a harness error (`e.self.unknown.panic.f`), so the session continues. Every error is also written to standard error, which the runner keeps in its report.

## Results

<!-- BEGIN generated results: scripts/reproduce-results writes this table from results/; do not edit it -->

| Implementation | Profile | Verdict | Active MUST pass / fail | Active SHOULD pass / fail | Active INTEROP pass / fail | Active cases not supported | Result |
| --- | --- | --- | --- | --- | --- | --- | --- |
| affinidi-keri-core 0.4.0 (affinidi-cesr 0.1.3) | `cesr-v1.0` | no-evidence | 0 / 0 | 0 / 0 | 0 / 0 | 39 | [2026-10-15, suite 05c2c7e8](../../results/affinidi-keri-core/0.4.0-affinidi-cesr-0.1.3/cesr-v1.0.json) |
| affinidi-keri-core 0.4.0 (affinidi-cesr 0.1.3) | `keri-escrow` | no-evidence | 0 / 0 | 0 / 0 | 0 / 0 | 3 | [2026-10-15, suite 05c2c7e8](../../results/affinidi-keri-core/0.4.0-affinidi-cesr-0.1.3/keri-escrow.json) |
| affinidi-keri-core 0.4.0 (affinidi-cesr 0.1.3) | `keri-v1.0.1` | no-evidence | 0 / 0 | 0 / 0 | 0 / 0 | 69 | [2026-10-15, suite 05c2c7e8](../../results/affinidi-keri-core/0.4.0-affinidi-cesr-0.1.3/keri-v1.0.1.json) |
| affinidi-keri-core 0.4.0 (affinidi-cesr 0.1.3) | `keripy-1x-interop` | interoperable | 0 / 0 | 0 / 0 | 5 / 0 | 4 | [2026-10-15, suite 05c2c7e8](../../results/affinidi-keri-core/0.4.0-affinidi-cesr-0.1.3/keripy-1x-interop.json) |

<!-- END generated results -->

## CI and the committed results

The `affinidi-adapter` job in `.github/workflows/ci.yml` installs Rust 1.95.0 with rustup, builds with `--locked`, runs `cargo fmt --check`, `cargo clippy -D warnings` and `cargo test`, and runs `kcs check-adapter`. It does not run a profile: the table under Results is generated from this adapter's committed results for `cesr-v1.0`, `keri-v1.0.1`, `keri-escrow` and `keripy-1x-interop`, under `results/affinidi-keri-core/`, which the suite's maintainer refreshes and checks locally (`docs/design.md`, Continuous integration). The tool builds the adapter itself, as above, before it runs it:

```sh
uv run python scripts/reproduce-results check --adapter affinidi     # compare fresh runs with the committed results
uv run python scripts/reproduce-results refresh --adapter affinidi   # replace them, from a clean tree
```

`check` fails on a regression, and on an improvement too, until the results are refreshed in the same change (the rules are in the keripy adapter's README, CI and the committed results).

The committed `cesr-v1.0` result is `affinidi-keri-core` 0.4.0 at `6277ae86…` with `affinidi-cesr` 0.1.3 at `b970cb01…`, verdict `no-evidence`: all 41 `cesr-v1.0` cases are `not-supported`, because every one requires `cesr.genus-2.00`. That is the accurate result for this implementation, not a gap in the adapter.

The committed `keri-v1.0.1` and `keri-escrow` results are `no-evidence` too: every KERI case requires `keri.version-2.x` and `cesr.genus-2.00`, which Affinidi lacks, so none is sent. The adapter's `keri.process` cases will come from KERI 1.x cases in `keripy-1x-interop`.

In `keripy-1x-interop`, CESR-0045, CESR-0046 and CESR-0047 need `cesr.item-extents` and CESR-0048 also needs `cesr.genus-2.00`, so none is sent; in `cesr-strict`, both cases need `cesr.genus-2.00`. The interop must-reject cases on KERI 1.0 streams, CESR-0049, CESR-0050, CESR-0052, CESR-0054 and CESR-0057, need no item extents, so they are sent; Affinidi rejects all five, as keripy 1.2.14 does, and they pass. The `keripy-1x-interop` result records those five passes and the four cases not sent; its verdict is `interoperable`, the verdict a non-normative profile gets instead of a conformance one, scoped like any verdict to the cases the adapter's declared features let the runner send.
