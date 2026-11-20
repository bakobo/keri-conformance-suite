# Affinidi adapter

Connects Affinidi's Rust CESR/KERI crates to the conformance runner over adapter protocol version 1 ([`docs/adapter-protocol.md`](../../docs/adapter-protocol.md)). It implements `cesr.parse`, `cesr.encode` and `keri.process`, and declares only those operations. For CESR it composes nothing: every value it reports comes from Affinidi's own parsing or from the bytes Affinidi said it consumed, and it never parses CESR itself. For `keri.process` every acceptance is Affinidi's, and so is every rejection of an event the adapter could hand to Affinidi's `Kever`. The routing around those verdicts is the adapter's, including the few refusals routing makes on its own, so `composes` is `["keri.routing"]` (see "keri.process" below). For `cesr.parse`, Affinidi's public API does not say where each item of a stream lay, so the adapter does not report items: it answers every stream Affinidi accepts with the protocol's accepted summary, the number of bytes Affinidi consumed.

## Pins

| Crate | Version | Source commit (from the crate's `.cargo_vcs_info.json`) | Role |
|---|---|---|---|
| `affinidi-keri-core` | `=0.8.1` | `4a1433fb82a90cbff48aedf7716eb75e286198f4` (affinidi/affinidi-keri-rs) | Stream parser and message framing; names the implementation in `hello` |
| `affinidi-keri-crypto` | `=0.8.1` | `4a1433fb82a90cbff48aedf7716eb75e286198f4` (affinidi/affinidi-keri-rs) | Verification keys (`Verfer`) built from an event's `k` field for `keri.process`; same workspace and commit as `affinidi-keri-core`, so the implementation identity already covers it |
| `affinidi-cesr` | `=0.1.8` | `10ee3f21fa8546849b5706af9f280d1de7258928` (affinidi/affinidi-tdk-rs) | Primitives (`Matter`), used by `cesr.encode` and by the parser; its version and commit are part of `hello`'s implementation identity |

All three are the latest releases on crates.io as of 2026-11-19, pinned exactly in `Cargo.toml` and locked in `Cargo.lock`. The adapter uses only their public API and patches nothing. `hello` reports name `affinidi-keri-core`, version `0.8.1 (affinidi-cesr 0.1.8)` and commit `4a1433fb… (affinidi-cesr 10ee3f21…)`, so moving either pin changes the identity the committed results record. `tests/pins.rs` fails if those constants in `src/protocol.rs` drift from `Cargo.lock` or from the commits crates.io published, and if `affinidi-keri-crypto` is not at `affinidi-keri-core`'s version and commit. To move a pin, change it in `Cargo.toml`, run `cargo update -p <crate> --precise <version>`, update the constants, and refresh the committed results.

The toolchain is Rust 1.95.0 (`rust-toolchain.toml`), the `rust-version` all three crates declare.

```sh
cd adapters/affinidi && cargo build --locked && cargo test --locked

# from the repository root
uv run kcs check-adapter "$PWD/adapters/affinidi/target/debug/kcs-adapter-affinidi"
uv run kcs run --adapter "$PWD/adapters/affinidi/target/debug/kcs-adapter-affinidi" --profile cesr-v1.0
```

## Declared features

A feature is a claim about what the implementation and this adapter can do together, not about the implementation alone. Declared for CESR: `cesr.genus-1.00`, `cesr.genus-2.00`, `cesr.serialization.json`, `keri.version-1.x` and `keri.version-2.x`. Affinidi frames JSON bodies by a legacy `KERI10JSON…_` version string or a 2.x `KERICAACAAJSON…` one. A stream is read in genus 1.00 until a genus-version counter (`-_AAA…`) switches it, and the genus holds for the messages after it. In 1.00 Affinidi reads the count codes `-A`, `-B`, `-C`, `-E`, `-F`, `-G` and `-V`, with `-0X` as their big forms; `-D` is modelled but refused, and other 1.00 codes are unknown to it. In 2.00 it reads keripy's attachment table, counted in quadlets (`affinidi_keri_core::counter_table`). A case that uses a code Affinidi does not read fails rather than being skipped. Two `cesr-v1.0` SHOULD assertions fail (CESR-0039, CESR-0066).

Declared for `keri.process`, each because Affinidi's `Kever` has the check and the adapter calls it:

- `kel.basic`: `Kever::new` checks an inception's SAID, field list, signatures and prefix derivation; `Kever::verify_update` checks a rotation's or interaction's SAID, field list, sequence number, prior event digest and signatures. Each event's top-level fields must be keripy's list for its version and type, in order, so a 1.x rotation that carries `c` is refused. Affinidi enforces the establishment-only (`EO`) trait: an interaction after an `EO` inception is refused.
- `kel.multisig.numeric` and `kel.multisig.weighted`: `Threshold::is_satisfied` over the indexed signatures, for numeric thresholds, read in hex as KERI writes them, and for weighted clauses, in keripy's flat single-clause form (`["1/2","1/2"]`) as well as the nested one.
- `kel.partial-rotation`: a rotation's signatures must meet the prior next threshold over the commitments they expose, as keripy's `Kever.exposeds` counts them, so a rotation may reorder its keys, reveal only some of the committed ones and hold the rest in reserve, or add keys never committed to. Affinidi reads the big dual-indexed signature codes (`2A`…).
- `kel.nontransferable`: an inception with `nt` `"0"` and an empty `n` is accepted and commits to no next keys, and nothing after it is accepted.
- `kel.recovery`: a non-delegated rotation at a sequence number Affinidi already holds may supersede the interaction events after the last establishment event (keripy's rules A0 to A2), through the same `Kever::verify_update` call. A rotation never supersedes a rotation. Affinidi refuses a superseding delegated rotation (rule B) as unsupported, so a case that needs one fails rather than being skipped. Affinidi keeps no events, only key state, so the adapter reads which accepted events are on the trunk from it (see "Where each value comes from").
- `kel.delegation`: `Kever::new_delegated` and `Kever::verify_update_delegated` check that the delegator's event named by the seal source couple anchors a seal for exactly this event, and refuse a delegation under a delegator whose verified traits include `DND` (do not delegate). A delegated rotation is keripy's `drt`, which names no delegator: it is checked against the delegator recorded at inception.
- `kel.witness`: `Kever::verify_witness_receipts_static` counts verified receipt couples (`-C`) from designated witnesses against the event's witness threshold, including after a rotation changes the witness list. It does not count witness indexed signatures (`-B`, or their 2.00 form), the form keripy attaches, so a case that receipts with them fails.
- `crypto.ed25519`: every key and signature the tests use. Affinidi's `Verfer` also verifies secp256k1 and secp256r1, but no test here exercises them, so they are not claimed.
- `keri.routing`: supplied by the adapter, and listed in `composes`.

Not declared, and why:

- `cesr.item-extents`. Affinidi's parser does not report where any item lay (see "How a stream is parsed"), so the adapter answers accepted streams with a summary. The runner therefore sends it no case with a decoded assertion, only cases whose assertions are all rejections.
- `cesr.native`, `cesr.serialization.cbor`, `cesr.serialization.mgpk`: Affinidi reads native CESR bodies in a 2.00 stream (since 0.8.0), and its `Serder` has CBOR and MessagePack kinds, but no case exercises them and this adapter has not verified that framing, so they are not claimed.
- `cesr.domain.binary`: the parser rejects non-ASCII attachment bytes, so it reads attachments in the text domain only. `Matter` can encode qb2, but a feature is a claim about the whole implementation.
- `keri.escrow`: Affinidi's `Escrow` type exists, but none of its validation paths uses it. An event that arrives before what it needs is rejected and stays rejected.
- `keri.duplicity`: a second event at a sequence number Affinidi already holds is refused by `Kever` (or, for a rotation, judged as a superseding recovery), not recorded as duplicitous. Affinidi's `Judge` keeps a duplicitous-event log, but this adapter does not use `Judge` (see below).

## How a stream is parsed

The verdict is Affinidi's: the adapter hands the whole stream to `affinidi_keri_core::parser::parse_all`, the strict parser Affinidi's own verifiers use. Any error is a rejection whose class is the `CoreError` variant, for example `CoreError::ParseError`.

When `parse_all` accepts the stream, the adapter answers `{"accepted": {"consumed": n}}`. It measures `n` by walking the stream again as `parse_all` does: it skips the whitespace `parse_all` skips between messages, skips a genus-version counter that ends the stream as `parse_all` does (sized by `counter_table::read_counter`, the function `parse_all` sizes it with), and calls `parse_next_in` once per message, carrying the genus a genus-version counter sets from one message to the next as `parse_all` carries it, and adding up the bytes `parse_next_in` says it consumed. If that walk disagrees with `parse_all` — a message `parse_next_in` rejects, a different number of messages, or a byte count of zero or past the end of the stream — the adapter answers a harness error (`e.self.unknown.measurement.f`) rather than a number it cannot vouch for.

This is the central limitation. Affinidi's parser returns attachments as decoded groups (`Vec<Siger>`, receipt couples and so on). It does not say where any item lay in the stream, which count codes it read, what their size fields held, or where each group ended, and it merges the contents of a `-V` group into the list without a trace of the `-V`. The only way to produce those items would be for the adapter to walk the attachments itself with Affinidi's primitive decoders, deciding from each count code how many items follow. That would be the adapter's parser being tested, with offsets computed from counts, so it does not do it. The summary still lets a case that must be rejected grade Affinidi: if Affinidi accepts such a stream, the case fails.

## Measured, not sourced

| Value | Measured as |
|---|---|
| `consumed` | The sum of the byte counts `parse_next_in` returned for each message, plus the whitespace `parse_all` skips between messages and a genus-version counter that ends the stream |

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

This sequencing is the adapter's, which is why `keri.routing` is in `composes`. It does four things Affinidi leaves to its caller. It picks the call from the ilk. It keeps one `Kever` per prefix, refusing a second inception of a prefix it already holds, as Affinidi's direct mode does. It records the body of every event Affinidi accepted. And it answers Affinidi's `DelegatorAnchors` lookups, whose contract is that they answer only from verified state: the anchors of a delegator's event from that record alone, and the delegator's configuration traits from the `KeyState` of the delegator's `Kever`, which exists only once Affinidi has accepted its inception. Routing therefore refuses some messages without asking a `Kever`: a receipt message, a message that is not a key event, a stream that is not exactly one message Affinidi can parse and identify, a non-inception event for a prefix no `Kever` holds, a delegated event with no seal source couple, and a second inception of a held prefix. Each is reported rejected, which in this protocol means not accepted, and its `reason` begins `routing:` so that a reader can tell it from a verdict of Affinidi's. Where Affinidi's own did:webs verifier makes the same choices, the adapter follows it: the delegation proof is the first seal source couple attached, and the receipt couples counted are those attached to the event.

The adapter does not use Affinidi's higher-level validator, `affinidi_keri::direct` and the `Judge` built on it, which since 0.8.1 sit behind `affinidi-keri`'s `store` feature. Direct mode returns success for a `rot`, `ixn` or `drt` whose prefix it holds no state for, so its return value cannot back a reading. It also accepts only `icp` as an inception, so it cannot process a delegated identifier at all (`affinidi-keri` 0.8.1, `src/direct.rs`, the "in direct mode we skip" branch, and `Kever::new_from_parts`, which refuses everything but `icp`). `this.i` records the decision.

### Where each value comes from

| Reported value | Source |
|---|---|
| `initial` | `seen` if, after the message's own delivery, Affinidi has accepted an event with exactly this body, otherwise `rejected` |
| `final` | The same test after the last message. An event Affinidi accepted is never removed, so a message seen on delivery stays seen. A message rejected on delivery reads seen at the end only when a later delivery of the same body was accepted |
| `trunk` | Whether the event is on its prefix's trunk as Affinidi's `Kever` holds it: starting from `KeyState::last_event_digest`, the adapter follows each accepted event's `p` (prior event digest) back to the inception, and every event on that path is on the trunk. An interaction a superseding rotation displaced stays seen but is off it. A receipt is never on it |
| `reason` | The `CoreError` Affinidi returned, or why the adapter could not hand the message to a `Kever`; given only for a message not seen on delivery |
| `key_states` | One entry per prefix with a `Kever`, from `Kever::state()` |
| `sn`, `keys`, `ndigs`, `wits`, `delegator` | `KeyState` `sn`, `keys`, `next_keys`, `backers`, `delegator` |
| `said` | `KeyState::last_event_digest`, the SAID of the last event accepted |
| `kt`, `nt` | `KeyState` `threshold` and `next_threshold`. A numeric threshold is the number Affinidi holds, written in hex as KERI writes it, so a `kt` of `"10"`, which Affinidi reads as ten, is reported as `"a"`. A weighted threshold is `Threshold::to_json_value`, always nested |
| `bt` | `KeyState::backer_threshold`, in hex |

The readings use only `seen` and `rejected`. Affinidi has no escrow, so nothing is `pending`, and it records no duplicity, so nothing is `duplicitous`. A displaced event keeps its anchors in the record the `DelegatorAnchors` lookup answers from, since Affinidi verified it.

## Errors

`hello` negotiates from the request's `supported` list (or `[protocol]` when the list is absent) and answers with protocol 1, or with an `unsupported` error when the integer 1 is not offered. Request fields the adapter does not know are ignored. A request line may be at most 64 MiB (`protocol::MAX_REQUEST_LINE`, not counting its newline). The adapter reads at most that far before deciding; a longer line gets an error whose `id` is null (`e.input.range.request-size.f`) and the rest of it is skipped a buffer at a time, never held whole. A line that is blank, not UTF-8, not a JSON object, or has no usable `id` (a non-negative integer up to 2^64−1) gets an error whose `id` is null (`e.input.format.request.f`). `keri.emit` gets an `unsupported` error. A `keri.process` request whose `perspective` is not an object, or whose `messages` is not a list of objects each with a lowercase hex `stream`, gets a harness error (`e.input.format.request.f`); a perspective other than `{"role": "validator"}` gets an `unsupported` error (`e.feature.unsupported.perspective.f`). Everything Affinidi refuses, and every stream it cannot parse, is a rejected reading, never an error. When Affinidi refuses to encode, the response is a rejection result whose class is the `CesrError` variant, as the protocol requires of a refusal, and Affinidi's message goes to standard error. A panic anywhere in an operation, including inside Affinidi, is caught and answered as a harness error (`e.self.unknown.panic.f`), so the session continues. Every error is also written to standard error, which the runner keeps in its report.

## Results

<!-- BEGIN generated results: scripts/reproduce-results writes this table from results/; do not edit it -->

| Implementation | Profile | Verdict | Active MUST pass / fail | Active SHOULD pass / fail | Active INTEROP pass / fail | Active cases not supported | Result |
| --- | --- | --- | --- | --- | --- | --- | --- |
| affinidi-keri-core 0.8.1 (affinidi-cesr 0.1.8) | `cesr-strict` | interoperable | 0 / 0 | 0 / 0 | 2 / 0 | 0 | [2026-11-20, suite 86a80137](../../results/affinidi-keri-core/0.8.1-affinidi-cesr-0.1.8/cesr-strict.json) |
| affinidi-keri-core 0.8.1 (affinidi-cesr 0.1.8) | `cesr-v1.0` | conformant | 7 / 0 | 10 / 2 | 0 / 0 | 23 | [2026-11-20, suite 86a80137](../../results/affinidi-keri-core/0.8.1-affinidi-cesr-0.1.8/cesr-v1.0.json) |
| affinidi-keri-core 0.8.1 (affinidi-cesr 0.1.8) | `keri-escrow` | no-evidence | 0 / 0 | 0 / 0 | 0 / 0 | 3 | [2026-11-20, suite 86a80137](../../results/affinidi-keri-core/0.8.1-affinidi-cesr-0.1.8/keri-escrow.json) |
| affinidi-keri-core 0.8.1 (affinidi-cesr 0.1.8) | `keri-v1.0.1` | conformant | 191 / 0 | 288 / 45 | 0 / 0 | 17 | [2026-11-20, suite 86a80137](../../results/affinidi-keri-core/0.8.1-affinidi-cesr-0.1.8/keri-v1.0.1.json) |
| affinidi-keri-core 0.8.1 (affinidi-cesr 0.1.8) | `keripy-1x-interop` | not-interoperable | 0 / 0 | 0 / 0 | 123 / 11 | 9 | [2026-11-20, suite 86a80137](../../results/affinidi-keri-core/0.8.1-affinidi-cesr-0.1.8/keripy-1x-interop.json) |

<!-- END generated results -->

## CI and the committed results

The `affinidi-adapter` job in `.github/workflows/ci.yml` installs Rust 1.95.0 with rustup, builds with `--locked`, runs `cargo fmt --check`, `cargo clippy -D warnings` and `cargo test`, and runs `kcs check-adapter`. It does not run a profile: the table under Results is generated from this adapter's committed results for `cesr-v1.0`, `keri-v1.0.1`, `keri-escrow` and `keripy-1x-interop`, under `results/affinidi-keri-core/`, which the suite's maintainer refreshes and checks locally (`docs/design.md`, Continuous integration). The tool builds the adapter itself, as above, before it runs it:

```sh
uv run python scripts/reproduce-results check --adapter affinidi     # compare fresh runs with the committed results
uv run python scripts/reproduce-results refresh --adapter affinidi   # replace them, from a clean tree
```

`check` fails on a regression, and on an improvement too, until the results are refreshed in the same change (the rules are in the keripy adapter's README, CI and the committed results).

The committed results are `affinidi-keri-core` 0.8.1 at `4a1433fb…` with `affinidi-cesr` 0.1.8 at `10ee3f21…`. They replaced the 0.4.0 results, which were `no-evidence` for every profile but `keripy-1x-interop`, because 0.4.0 read neither KERI 2.x nor CESR genus 2.00 and every normative case needs both.

`cesr-v1.0` is `conformant`: every MUST assertion sent passes. Two SHOULD assertions fail, CESR-0039 and CESR-0066. The cases with decoded assertions need `cesr.item-extents` and are not sent. `cesr-strict` is `interoperable`.

`keri-v1.0.1` is `conformant` too, and its SHOULD failures fall in two groups. Affinidi has no escrow, so an event that the spec says SHOULD be held pending under a signing or witness threshold is rejected. It does not count witness indexed signatures, so an event receipted that way is rejected where the case expects it seen (KERI-0036, KERI-0041, KERI-0060, KERI-0061, KERI-0102 to KERI-0104). The cases that need `keri.escrow`, SHA2-256 or Blake2b-256 digests, or the `exn.verify` operation, which this adapter does not offer, are not sent. `keri-escrow` is `no-evidence`: all its cases need `keri.escrow`.

In `keripy-1x-interop`, CESR-0045, CESR-0046, CESR-0047 and CESR-0048 need `cesr.item-extents`, so none is sent. The interop must-reject cases on KERI 1.0 streams, CESR-0049, CESR-0050, CESR-0052, CESR-0054 and CESR-0057, are sent, and Affinidi rejects all five, as keripy 1.2.14 does. The KERI 1.x cases that need `keri.escrow` are not sent. Seven of the cases sent fail, so the profile's verdict is `not-interoperable`, the verdict a non-normative profile gets instead of a conformance one. Affinidi rejects events the cases expect it to hold pending under a signing or witness threshold (KERI-0146, KERI-0151, KERI-0152, KERI-0169, KERI-0172), and it rejects witnessed inceptions receipted with `-B` (KERI-0168, KERI-0173). The rotations, delegated rotation and establishment-only KEL that 0.4.0 got wrong (KERI-0144, KERI-0162, KERI-0167) now pass. The committed result gives each failing assertion.
