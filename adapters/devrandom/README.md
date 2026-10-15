# devrandom adapter

Connects devrandom-labs/cesr, a sans-IO Rust implementation of CESR and KERI 1.x, to the conformance runner over adapter protocol version 1 ([`docs/adapter-protocol.md`](../../docs/adapter-protocol.md)). It implements `cesr.parse`, `cesr.encode` and `keri.process`.

devrandom is a library of verdict functions: it judges one event against a key state it is handed, and stores nothing. Routing messages, escrow and retry, finding a delegator's anchoring event, rewinding on a superseding rotation, recording duplicity and attaching receipts are left to the caller by the library's own account (`keri-rs` `lib.rs`). This adapter is that caller for `keri.process`, and declares each of those behaviours in `composes`: `kel.recovery`, `keri.duplicity`, `keri.escrow` and `keri.routing`. Every verdict still comes from the library; "keri.process" below says exactly which function decides what, and what the adapter adds.

## Pins

| Crate | Version | Source commit (from the crate's `.cargo_vcs_info.json`) | Role |
|---|---|---|---|
| `keri-rs` (imported as `keri`) | `=0.1.0` | `5704a43817bbb1645a69761d18efec06269330cf` | Key-state fold, escrow classification, delegation, duplicity and receipt judgments |
| `keri-codec` | `=0.10.0` | the same | Message parsing, strict canonical body deserialization and SAID verification |
| `keri-events` | `=0.6.0` | the same | Event, receipt and threshold types |
| `cesr-rs` (imported as `cesr`) | `=0.12.0` | the same | Primitives, encoding and signature verification |
| `cesr-stream` | `=0.7.0` | the same | Message framing and attachment-group parsing |

All five are the releases devrandom-labs published to crates.io on 2026-10-02, from the one commit tagged `keri-rs-v0.1.0` in https://github.com/devrandom-labs/cesr, pinned exactly in `Cargo.toml` and locked in `Cargo.lock`. The adapter uses only their public API and patches nothing. `hello` reports name `devrandom-labs/cesr`, version `keri-rs-v0.1.0` (the release tag, because the five crate versions joined are longer than a results path segment may be) and that commit, so moving any pin changes the identity results record. `tests/pins.rs` fails if the versions in `src/protocol.rs` drift from `Cargo.lock` or if any crate was not published from that commit. To move a pin, change it in `Cargo.toml`, run `cargo update -p <crate> --precise <version>`, and update `CRATES`, `IMPLEMENTATION_VERSION` and `IMPLEMENTATION_COMMIT`.

The toolchain is Rust 1.95.0 (`rust-toolchain.toml`), the `rust-version` the workspace declares.

## Licence

The adapter's own source is Apache-2.0, like the rest of this repository. devrandom-labs/cesr is dual-licensed MIT or Apache-2.0.

## Build, test, run

```sh
cd adapters/devrandom
cargo build --locked
cargo test --locked
cargo fmt --check && cargo clippy --locked --all-targets -- -D warnings

# from the repository root
uv run kcs check-adapter "$PWD/adapters/devrandom/target/debug/kcs-adapter-devrandom"
uv run kcs run --adapter "$PWD/adapters/devrandom/target/debug/kcs-adapter-devrandom" --profile keripy-1x-interop
```

The tests derive keys with devrandom's salty custodian, whose argon2 key stretching is slow when unoptimized, so `Cargo.toml` optimizes the `argon2` and `blake2` crates in the debug profile. Nothing on the validation path is optimized differently from a debug build.

## Declared features

A feature is a claim about what the implementation and this adapter can do together. Declared: `cesr.genus-1.00`, `cesr.serialization.json`, `crypto.ed25519`, `kel.basic`, `kel.delegation`, `kel.multisig.numeric`, `kel.multisig.weighted`, `kel.nontransferable`, `kel.partial-rotation`, `kel.recovery`, `kel.witness`, `keri.duplicity`, `keri.escrow`, `keri.routing` and `keri.version-1.x`. Of these, `kel.recovery`, `keri.duplicity`, `keri.escrow` and `keri.routing` are also in `composes`, because the adapter supplies them.

Not declared, and why:

- `cesr.genus-2.00` and `keri.version-2.x`. KERI 1.x is the library's documented permanent scope. Its V2 counter table exists, but its V2 group parser reads a group's count as a number of elements, where the CESR 2.00 table counts quadlets, so it cannot read a CESR 2.00 attachment another implementation writes. A stream that opens with a genus/version code is rejected at once (`ParseError::GenusVersionNotAGroup`). Every case in the normative profiles requires both features, so the runner sends this adapter none of them: their verdicts are `no-evidence`, which is the accurate result for a KERI 1.x implementation, not a gap in the adapter.
- `cesr.item-extents`. devrandom's framer reports where each whole message ends, not where each item inside it lay, and the integrity rule forbids the adapter computing offsets itself, so accepted streams get the protocol's summary (see "cesr.parse").
- `cesr.domain.binary`, `cesr.native`. The adapter reads and encodes in the text domain only, and the library's message layer frames only JSON bodies located by a version string.
- `cesr.serialization.cbor`, `cesr.serialization.mgpk`. The message layer refuses a CBOR or MessagePack cold start.
- `crypto.secp256k1`, `crypto.secp256r1`, `crypto.ed448`. cesr-rs verifies secp256k1 and secp256r1 signatures and refuses Ed448, but no case and no test of this adapter exercises the first two, so they are not claimed.
- `acdc.verify` and `exn.verify` are not offered. Every ACDC and exchange-message case requires CESR 2.00 and KERI 2.x, and devrandom's credential verifier is behind a feature flag this adapter has not exercised.

## cesr.parse

The verdict is devrandom's. For each message in the stream, the adapter calls `cesr_stream::MessageFramer::advance` with end of input set, which frames a body by its version string and the attachment groups after it, or a bare group, and then reads every attachment group with `cesr_stream::Groups::<V1>` and decodes every element of every element-counted group, and every group inside a `-V` attachment frame (the match names every group kind, so one added to cesr-stream fails to compile rather than being accepted unread), so that a malformed primitive inside a framed group is rejected, as it is when devrandom's own message layer reads the group. Other quadlet-counted frames are carried opaquely by devrandom and are left as its framer took them. Any error is a rejection whose class is the raised error's type and variant, for example `ParseError::Truncated`. Two rejections are the adapter's own observation of the framer, and are classed so: `MessageFramer::NoFrameAtEndOfInput` if it reports no frame although the input has ended, and `MessageFramer::SpanOutsideInput` if it reports a span the input does not hold; neither has been seen. If the whole stream frames, the answer is `{"accepted": {"consumed": n}}` with `n` the length of the stream. The framer takes explicit work limits (`cesr::LIMITS`): 16 MiB for a body and for one message's attachments, 4096 attachment groups, 65,536 elements and signatures, 4096 groups in a frame, and nesting 64 deep. A stream past one of them is rejected with devrandom's limit error; no case comes near them.

devrandom's CESR layer accepts a `-V` frame nested inside another; its message layer is what refuses one, and `keri.process` reports that refusal.

## cesr.encode

`MatterBuilder::new().with_code(code).with_raw(raw).build()` and its `to_qb64()`, with the code parsed by `MatterCode::from_str`. A code devrandom's table does not have, a raw value of the wrong length or empty, and a variable-size code (the builder encodes fixed-size codes only) are devrandom's refusals, answered as the protocol's rejection result whose class is the raised error's type and variant, read from the error itself, for example `MatterBuildError::Validation` or `ParsingError::UnknownCode`. The binary domain is answered `unsupported` (`e.feature.unsupported.binary-domain.f`): that limit is the adapter's, which encodes in the text domain only. No case is sent today: every `cesr.encode` case requires `cesr.genus-2.00`.

## keri.process

Each request starts a fresh host (`src/kel.rs`). Messages are delivered in order, and after each delivery the host re-drives everything it holds until a pass changes nothing, so every reading is taken at quiescence.

**Reading a message.** keri-codec's `Message::parse` reads each stream: strict canonical deserialization, SAID verification, and the routing of `-A` and `-B` groups on a key event and of `-C`, `-B` and `-F` groups on a receipt. That parser refuses a key event that carries a seal-source couple (`-G`, which is how keripy 1.x names a delegator's anchoring event) or a first-seen replay couple (`-E`). For exactly those two refusals, the adapter reads the frame again with the library's own pieces: `MessageFramer` finds the frame, `KeriEvent::deserialize` reads the body strictly and verifies its SAID, and `Groups::<V1>` reads the attachments. `-A` and `-B` become the event's signatures as in the message layer, the first `-G` couple names the delegator's anchoring event, and `-E` is dropped, as a remote validator drops first-seen ordinals. Any other group on a key event is refused, as the message layer refuses it. A stream that holds more than one message, a stream the library cannot read, and a message that is neither a key event nor a receipt (a TEL event, an exchange message, a query or reply) are not processed and read `rejected`, with the library's reason.

**What decides.** An inception is judged by `KeyState::incept`, a delegated inception by `KeyState::incept_delegated`, an event above its KEL's head by `KeyState::ingest`, and a delegated rotation by `KeyState::ingest_delegated`. Each takes a `Signed` built with `Signed::from_host_asserted_parts`, whose assertion, that the event was parsed from exactly those bytes, holds because the library's parser produced the event from them. A rejection is read through `Rejection::disposition`: `Awaiting` is held (`pending`), `Terminal` is `rejected`. An event at a sequence number its KEL already holds goes to `KeyState::judge_same_sn` against the recorded event: `Duplicitous` is recorded as `duplicitous`; `Supersedes` rewinds to the state before that sequence number and re-drives the validating fold there, keeping the displaced events `seen` and off the trunk; `Undecided` is held when the host could not give the judgment every delegating event it needs, and `rejected` when it could, because then no rule lets the event supersede up to a non-delegated root, which KERI's C1 rule says must be discarded; anything else is `rejected`. Key states are carried between judgments as the library's owned `KeyStateSnapshot`, which it provides for exactly this kind of host.

**What the adapter composes**, each a duty the library leaves to its caller:

- Routing (`keri.routing`): each event goes to the KEL of its prefix, each receipt to the event it names. An event for an identifier with no KEL yet, other than an inception, is held.
- Escrow (`keri.escrow`): held events are re-driven after every delivery until nothing changes. Signatures delivered in separate copies of the same event (by SAID) are combined, as keripy combines them, so a partially signed event is accepted when the rest arrive.
- Delegation evidence: for a delegated event the adapter finds the delegator's anchoring event, the one a `-G` couple names, or else the first trunk event of the delegator's KEL whose seals anchor it, and passes it with the delegator's current state as `DelegationEvidence::Anchored`. For two delegated rotations contesting one sequence number it passes `judge_same_sn` the delegating events of both, level by level up the delegation chain (`DelegationContest`), until it reaches a delegator that is not itself delegated; where the host does not hold a delegating event, the chain stops there. If the evidence is not held yet, the event is held.
- Superseding recovery (`kel.recovery`): the rewind and re-drive above.
- Duplicity (`keri.duplicity`): recording the event the same-sn judgment calls duplicitous.
- Receipts: a receipt of a seen event is judged endorsement by endorsement, a witness signature by `Witnessing::receipt` against the event's governing witness set, a couple by `cesr::crypto::verify` with the couple's prefix as the key, and a transferable endorsement by `ReceiptedEvent::endorsed_by` against the receiptor's seen establishment event, after `ReceiptedEvent::named_by` checks that the receipt names that event. A receipt of a held event has each witness signature and couple verified the same way and is then attached to the event, a couple at its signer's position in the governing witness set (`Witnessing::witness_index`), which is keripy's promotion of a witness's couple and the two-call recipe devrandom's receipt module documents; the event is then re-driven, and the fold verifies every attached signature again. The governing witness set of a held rotation is the head's, with the rotation's cuts removed and its additions appended in order, as a rotation defines it; a wrong position could only make a valid receipt fail, never a forged one pass. A receipt of an event the host does not hold is held.

**Readings.** An event message reads by the SAID of its event: `seen` if the host accepted that event, `pending` if it holds it, `duplicitous` or `rejected` otherwise. So a later valid copy of an event makes an earlier forged copy read `seen` at the end, as the keripy adapter reads keripy's database by SAID. `trunk` is true for a seen event that is still on its KEL's trunk. A receipt reads `seen` when every endorsement verified against the seen event, or when it was attached to a held event that was then accepted; `pending` while held; `rejected` when an endorsement failed. A receipt is never on the trunk. `key_states` gives each KEL's head: `sn`, `said`, `keys`, `kt` (a hex number, or fractions as a list per clause and a flat list for one clause), `ndigs`, `nt`, `wits`, `bt` in hex, and `delegator`. `reason` carries the library's rejection or the host's reason for holding.

## Results

<!-- BEGIN generated results: scripts/reproduce-results writes this table from results/; do not edit it -->

| Implementation | Profile | Verdict | Active MUST pass / fail | Active SHOULD pass / fail | Active INTEROP pass / fail | Active cases not supported | Result |
| --- | --- | --- | --- | --- | --- | --- | --- |
| devrandom-labs/cesr keri-rs-v0.1.0 | `cesr-v1.0` | no-evidence | 0 / 0 | 0 / 0 | 0 / 0 | 39 | [2026-10-15, suite ca2187ea](../../results/devrandom-labs-cesr/keri-rs-v0.1.0/cesr-v1.0.json) |
| devrandom-labs/cesr keri-rs-v0.1.0 | `keri-escrow` | no-evidence | 0 / 0 | 0 / 0 | 0 / 0 | 3 | [2026-10-15, suite ca2187ea](../../results/devrandom-labs-cesr/keri-rs-v0.1.0/keri-escrow.json) |
| devrandom-labs/cesr keri-rs-v0.1.0 | `keri-v1.0.1` | no-evidence | 0 / 0 | 0 / 0 | 0 / 0 | 69 | [2026-10-15, suite ca2187ea](../../results/devrandom-labs-cesr/keri-rs-v0.1.0/keri-v1.0.1.json) |
| devrandom-labs/cesr keri-rs-v0.1.0 | `keripy-1x-interop` | interoperable | 0 / 0 | 0 / 0 | 5 / 0 | 4 | [2026-10-15, suite ca2187ea](../../results/devrandom-labs-cesr/keri-rs-v0.1.0/keripy-1x-interop.json) |

<!-- END generated results -->

## CI and the committed results

The `devrandom-adapter` job in `.github/workflows/ci.yml` installs Rust 1.95.0 with rustup, builds with `--locked`, runs `cargo fmt --check`, `cargo clippy -D warnings` and `cargo test`, and runs `kcs check-adapter`. It does not run a profile: the table under Results is generated from this adapter's committed results for `cesr-v1.0`, `keri-v1.0.1`, `keri-escrow` and `keripy-1x-interop`, under `results/devrandom-labs-cesr/`, which the suite's maintainer refreshes and checks locally (`docs/design.md`, Continuous integration). The tool builds the adapter itself, as above, before it runs it:

```sh
uv run python scripts/reproduce-results check --adapter devrandom     # compare fresh runs with the committed results
uv run python scripts/reproduce-results refresh --adapter devrandom   # replace them, from a clean tree
```

Every case in the three normative profiles requires `cesr.genus-2.00` or `keri.version-2.x`, so the runner sends none of them and each verdict is `no-evidence`: the accurate result for a KERI 1.x implementation. In `keripy-1x-interop`, the cases with a `decoded` assertion need `cesr.item-extents` and are not sent; the must-reject cases on KERI 1.0 streams are sent, and devrandom rejects them, as keripy 1.2.14 does.

## Errors

`hello` negotiates from the request's `supported` list (or `[protocol]` when the list is absent) and answers with protocol 1, or with an `unsupported` error (`e.feature.unsupported.protocol-version.f`) when 1 is not offered. Request fields the adapter does not know are ignored. A request line may be at most 64 MiB (`protocol::MAX_REQUEST_LINE`, not counting its newline); a longer line gets an error whose `id` is null (`e.input.range.request-size.f`) and the rest of it is skipped a buffer at a time, never held whole. A line that is blank, not UTF-8, not a JSON object, or has no usable `id` (a non-negative integer up to 2^64−1) gets an error whose `id` is null (`e.input.format.request.f`); so does, with its id, a request with no string `op` or with malformed fields. An unknown `op` is a `harness` error (`e.input.range.unknown-op.f`), and `keri.emit`, `acdc.verify` and `exn.verify` are `unsupported` (`e.feature.unsupported.undeclared-op.f`). A `keri.process` perspective other than an ordinary validator's is `unsupported` (`e.feature.unsupported.perspective.f`). If re-driving held events still changes the host after 10,000 passes, the request is a `harness` error (`e.self.unknown.quiescence.f`), because the readings would depend on when the adapter stopped. A panic anywhere in an operation, including inside devrandom, is caught and answered as a `harness` error (`e.self.unknown.panic.f`), so the session continues; a panic is never reported as a rejection. If standard input or output fails, the adapter explains why on standard error (`e.env.io.stdio.f`) and exits with status 1. Every code ends in `f`: none of these can clear on retry. Every error is also written to standard error, which the runner keeps in its report.
