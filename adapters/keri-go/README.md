# keri-go adapter

Connects grapeid/keri-go, a KERI implementation in Go, to the conformance runner over adapter protocol version 1 ([`docs/adapter-protocol.md`](../../docs/adapter-protocol.md)). It implements `cesr.parse`, `cesr.encode` and `keri.process`. keri-go validates a whole key log at a time and has no per-message processor, so the adapter supplies the routing that `keri.process` needs and declares it: `composes` is `["keri.routing"]`. Every acceptance is keri-go's. Every rejection is keri-go's too, except four that the routing makes, each reported with a reason that begins "refused by the adapter's routing, not by keri-go": a delegated event, a message that is not a key event, an event keri-go would accept at a sequence number another seen event already holds, and an establishment event whose witness threshold keri-go could not read (see `keri.process` below). The design decision is node `3t0efrq7` in [`this.i`](../../this.i).

## What it tests, pinned

| Module | Version | Commit | Why |
|---|---|---|---|
| `github.com/grapeid/keri-go` | `v0.1.5` | `f06d1dac5a36dea4b619eb6934e43e6fdc68b835` | The newest tag, and the tip of `main` on 2026-10-15 (last commit 2026-08-10) |

`go.mod` requires exactly `v0.1.5` and `go.sum` locks it, with its one dependency, `github.com/zeebo/blake3` v0.2.4. The commit is the one the tag names in the module's repository; `hello` reports `{"name": "keri-go", "version": "0.1.5", "commit": "f06d1dac…"}` with the full commit. `TestHelloNamesThePinnedModule` fails if `go.mod` and the version `hello` reports disagree. To move the pin, `go get github.com/grapeid/keri-go@<tag>`, update `implVersion` and `implCommit` in `protocol.go` to the tag and the commit it names (`git ls-remote https://github.com/grapeid/keri-go`), and refresh this adapter's results. The adapter uses only keri-go's exported API and patches nothing.

The test-only dependencies are `github.com/santhosh-tekuri/jsonschema/v6`, which checks every kind of response against [`schema/adapter-protocol.schema.json`](../../schema/adapter-protocol.schema.json), and `github.com/dlclark/regexp2`, which runs that schema's patterns as ECMAScript requires (Go's own engine has no lookahead). Neither is linked into the adapter binary.

## Licence

The adapter's own source is Apache-2.0, like the rest of this repository. keri-go is Apache-2.0 (copyright 2026 Rob Andersen); its dependencies are blake3, CC0-1.0, and klauspost/cpuid, MIT. This repository does not distribute built binaries.

## Build, test, run

```sh
cd adapters/keri-go
go build -o kcs-adapter-keri-go .     # Go 1.24 or later, per go.mod
go test -cover ./...

# from the repository root
uv run kcs check-adapter "$PWD/adapters/keri-go/kcs-adapter-keri-go"
uv run kcs run --adapter "$PWD/adapters/keri-go/kcs-adapter-keri-go" --profile keripy-1x-interop
```

The tests build every key log they process with keri-go's own builders and signers, read the input streams (never the expectations) of a few suite cases, and cover every statement of the adapter.

## What keri-go supports, found by reading and running it

keri-go's README says it reads and builds both CESR 1.0 and 2.0. Run against the suite, it reads only 1.0:

- **Its 2.0 version string is not the one the KERI specification uses.** keri-go reads and writes the 16-character `KERICAAJSONAAEq.` of keripy 1.3.6; `version.go` itself records that keripy 2.0.0-dev6 moved to the 19-character `KERICAACAAJSONAAEt.`, and every KERI case uses that form. keri-go's field-order and size checks also read a 2.0 string as if it were 1.0 (`checkEventVersion` parses characters 10 to 16 as hex).
- **It has no genus/version codes and only the 1.00 count codes.** Its stream reader knows `-A`, `-B`, `-C`, `-D` and `-V`, counted as keripy 1.x counts them, and refuses any other code. A stream that opens with `-_AAACAA` is framed with those eight characters inside the body, so `DetectVersion` finds the version string at the wrong offset; and a 2.00 group such as `-K` is read as an unknown 1.00 group and refused.
- **It reads JSON bodies only**, as its README says.
- **Its stream reader skips whitespace before a message but not after one's attachments.** A newline between two messages is refused, although a comment in `kel_stream.go` says pretty-printed streams are tolerated.
- **Its stream reader does not read bodies, and its event reader checks only the values it uses.** `ParseKELStream` frames a body by matching braces, so a body that is not valid JSON passes it. `ParseEvent` refuses a malformed field list, but skips the value of a field it does not read without checking that it is JSON, so `"c":xx` in an inception passes both.
- **Its stream reader copies the remaining stream once per message** (`strings.TrimLeft(string(rest), …)`), so a stream of many short messages costs time quadratic in its length. A 64 MiB request of short messages can run past the runner's time limit, which the protocol counts as a failure of the case, not a gap.
- **It does not refuse a witness threshold it cannot read.** `ParseEvent` leaves an unreadable `bt` as absent, and `ValidateSignedKEL` accepts the event; the adapter refuses it, as below.

## Declared features, and the results that follow

Declared: `cesr.genus-1.00`, `cesr.serialization.json`, `keri.version-1.x`, `crypto.ed25519`, `kel.basic`, `kel.multisig.numeric`, `kel.multisig.weighted`, and `keri.routing`, which the adapter composes. Not declared, and why:

- `cesr.genus-2.00`, `keri.version-2.x`: see above.
- `cesr.item-extents`: keri-go reports no item offsets, so accepted streams are answered with the protocol's summary.
- `cesr.domain.binary`, `cesr.native`, `cesr.serialization.cbor`, `cesr.serialization.mgpk`: keri-go has none of them.
- `kel.delegation`: keri-go has `ValidateDelegationSigned`, but `ValidateSignedKEL` does not consult a delegator, and routing a delegated event to its delegator's log would be more composition than the adapter should claim. Delegated events are rejected.
- `kel.witness`: keri-go counts receipt couples (`-C`) attached to an event and does not route a separate `rct` message to the event it receipts; it does not count witness indexed signatures (`-B`) at all. The adapter enforces the witness threshold with keri-go's count (see below), so a witnessed event is never accepted without it, but it does not claim witness support.
- `kel.partial-rotation`: keri-go's indexed signatures carry no ondex, so it has no dual-indexed signatures.
- `kel.nontransferable`: keri-go builds non-transferable identifiers; their validation rules are not exercised by the adapter's tests, so they are not claimed.
- `kel.recovery`, `keri.escrow`, `keri.duplicity`: keri-go's `Watcher` detects duplicity, but nothing in keri-go escrows or supersedes, and the adapter composes none of them.
- `crypto.ed448`, `crypto.secp256k1`, `crypto.secp256r1`: keri-go is Ed25519 only.
- `crypto.blake2b-256`, `crypto.sha2-256`: keri-go computes and checks Blake3-256 digests only (`Blake3SAID`, code `E`).

Every case in `cesr-v1.0`, `cesr-strict`, `keri-v1.0.1`, `keri-escrow` and `acdc-v1.0` requires `cesr.genus-2.00` and, except the encode cases, `keri.version-2.x`, so the runner sends none of them and each profile's verdict is `no-evidence`. In `keripy-1x-interop`, CESR-0045 to CESR-0048 need `cesr.item-extents` (CESR-0048 also `cesr.genus-2.00`), so those four are not sent. The must-reject cases on KERI 1.0 streams, CESR-0049, CESR-0050, CESR-0052, CESR-0054 and CESR-0057, are sent and all five pass: keri-go refuses each stream, as keripy 1.2.14 does. That profile's verdict is `interoperable`, scoped to the five cases sent.

CESR-0054's stream has a receipt couple whose prefix carries an unassigned code. keri-go refuses it, but because its reader measures the couple at a fixed width and the stream is shorter than that, not because it reads the code; its reader never checks a couple's codes.

## How each operation works

### `cesr.parse`

The adapter hands the stream to keri-go's `ParseKELStream`, which splits it into messages, framing each body by matching braces and measuring each attachment group from its count code, then calls `DetectVersion` and, on each KERI message, `ParseEvent`. Any of them refusing is a rejection whose `class` names it, `ParseKELStream`, `DetectVersion` or `ParseEvent`; keri-go's reason goes to standard error. A stream holding an ACDC body, if keri-go refused nothing else in it, is answered with an `unsupported` error (`e.feature.unsupported.acdc-body.f`): keri-go has no reader that parses an ACDC body without verifying it (`ParseEvent` reads KERI messages and would refuse an ACDC's `s` as a sequence number; `VerifyCredential` also checks SAIDs), so accepting or rejecting one would be the adapter's verdict, not keri-go's. No case today sends one. Otherwise the answer is `{"accepted": {"consumed": n}}` with `n` the length of the stream, because `ParseKELStream` either reads to the end of the stream or refuses it. The adapter never parses CESR itself.

### `cesr.encode`

`MatterQB64(code, raw)`, in the text domain, for any code. `MatterQB64` checks codes against no table and raw values against no size: it encodes by the length of the code alone, so it answers `E` with 31 bytes, or `M`, a code keri-go never names, with an encoding, and refuses only a code whose length the raw value cannot cover. That refusal is answered as the protocol's rejection, `{"reject": {"class": "MatterQB64"}}`, with keri-go's reason on standard error. Every encode case today needs `cesr.genus-2.00`, so none is sent.

### `keri.process`

For each delivered message, in order, starting from empty state per request:

1. `ParseKELStream` must find exactly one message in it, `DetectVersion` must read its version string, and `ParseEvent` must read it. Anything else is `rejected`.
2. Only `icp`, `rot` and `ixn` are routed. A `dip` or `drt`, a receipt, and any other message is `rejected` by the adapter, with a reason saying so. The runner sends no case that needs them, because the features they would need are not declared.
3. The event is routed to its identifier's log of seen messages. If its sequence number is beyond the end of the log, the candidate log is the log plus the event; if that position is already held, the candidate is the log up to that position plus this delivery.
4. keri-go's `ValidateSignedKEL` must accept the candidate log. It checks every event's fields, version-string size, SAID, derivation, thresholds, sequence, prior digest, pre-rotation, and controller signatures against the key state in force.
5. If an establishment event carries a `bt` that keri-go could not read, the adapter rejects it, because the threshold its receipts must meet is unknown and counting it as zero would accept the event unwitnessed. Otherwise, if the witness threshold in force once the event is applied is not zero, keri-go's `ReceiptsMeetThreshold` must count at least that many valid receipt couples, from the witnesses in force, attached to the delivery.
6. If either refuses, the message is `rejected` with keri-go's reason. If both pass and the position was held by a different seen event, the adapter rejects it: keri-go has no rule for choosing between two branches it accepts, and the adapter supersedes nothing (`kel.recovery` is not declared). Otherwise the message is `seen` and, unless it repeats a seen event, appended to the log.

Nothing is escrowed, so a message's reading after the last delivery is its reading on arrival, and `trunk` is `true` exactly when the message is seen.

### What the adapter computes, and what comes from keri-go

| Value | Source |
|---|---|
| Accept or reject of each delivery | keri-go: `ParseKELStream`, `DetectVersion`, `ParseEvent`, `ValidateSignedKEL`, `ReceiptsMeetThreshold`; the adapter decides which log a message joins, and makes the four routing refusals named at the top |
| End of an event's body, for `ReceiptsMeetThreshold` | The size in the version string, read by keri-go's `ParseVersionString`; `ValidateSignedKEL` has already checked that it equals the length of the body keri-go framed |
| Witnesses and witness threshold in force | Replayed by the adapter from `b`, `br`, `ba` and `bt` as keri-go's `ParseEvent` read them, as keri-go's own `ValidateKEL` does internally without exporting the result |
| `key_states`: `sn`, `said` | The last seen event, as `ParseEvent` read it |
| `keys`, `kt`, `ndigs`, `nt` | The last seen establishment event's `k`, `kt`, `n` and `nt`, as `ParseEvent` read them |
| `wits`, `bt` | The replayed witness list and threshold, `bt` in lowercase hex |
| `delegator` | Always `null`: no delegated event is ever seen |

## Errors

`hello` negotiates from the request's `supported` list, or `[protocol]` when the list is absent, and answers with protocol 1, or with an `unsupported` error (`e.feature.unsupported.protocol-version.f`) when the integer 1 is not offered. Request fields the adapter does not know are ignored. A request line may be at most 64 MiB (`maxRequestLine`, not counting its newline); a longer line gets an error whose `id` is null (`e.input.range.request-size.f`) and is skipped without being held. A line that is not a JSON object, including a blank line, or whose `id` is not an integer from 0 to 2^64−1, gets an error whose `id` is null (`e.input.format.request.f`). A request without a string `op` or with malformed fields is a `harness` error carrying its id (`e.input.format.request.f`), and an unknown `op` is too (`e.input.range.unknown-op.f`). `keri.emit`, `acdc.verify` and `exn.verify` get an `unsupported` error (`e.feature.unsupported.undeclared-op.f`), as do `cesr.encode` in the binary domain (`e.feature.unsupported.binary-domain.f`) and `cesr.parse` on a stream holding an ACDC body (`e.feature.unsupported.acdc-body.f`). A panic anywhere in an operation, including inside keri-go, is caught, its stack written to standard error, and answered as a `harness` error (`e.self.unknown.panic.f`); the adapter goes on to the next request. The adapter exits with status 0 at end of input; if it cannot read standard input or write standard output it says why on standard error (`e.env.io.stdio.f`) and exits with status 1. Every code ends in `f`: none of these failures clears on retry.

## Results

<!-- BEGIN generated results: scripts/reproduce-results writes this table from results/; do not edit it -->

| Implementation | Profile | Verdict | Active MUST pass / fail | Active SHOULD pass / fail | Active INTEROP pass / fail | Active cases not supported | Result |
| --- | --- | --- | --- | --- | --- | --- | --- |
| keri-go 0.1.5 | `cesr-v1.0` | no-evidence | 0 / 0 | 0 / 0 | 0 / 0 | 39 | [2026-10-15, suite 9ec34529](../../results/keri-go/0.1.5/cesr-v1.0.json) |
| keri-go 0.1.5 | `keri-v1.0.1` | no-evidence | 0 / 0 | 0 / 0 | 0 / 0 | 69 | [2026-10-15, suite 9ec34529](../../results/keri-go/0.1.5/keri-v1.0.1.json) |
| keri-go 0.1.5 | `keripy-1x-interop` | interoperable | 0 / 0 | 0 / 0 | 5 / 0 | 4 | [2026-10-15, suite 9ec34529](../../results/keri-go/0.1.5/keripy-1x-interop.json) |

<!-- END generated results -->

## CI and the committed results

The `keri-go-adapter` job in `.github/workflows/ci.yml` installs the Go version `go.mod` names, verifies the module cache against `go.sum`, builds with `-mod=readonly`, runs `gofmt`, `go vet` and the tests with every statement covered, and runs `kcs check-adapter`. It does not run a profile: the table under Results is generated from this adapter's committed results for `cesr-v1.0`, `keri-v1.0.1` and `keripy-1x-interop`, under `results/keri-go/`, which the suite's maintainer refreshes and checks locally (`docs/design.md`, Continuous integration). The tool builds the adapter itself, as above, before it runs it:

```sh
uv run python scripts/reproduce-results check --adapter keri-go     # compare fresh runs with the committed results
uv run python scripts/reproduce-results refresh --adapter keri-go   # rewrite them, from a clean tree
```

`keri-v1.0.1` is run, although no case reaches the adapter, so that its result records that every case there needs a feature keri-go does not have. `keri-escrow` is not run: every case in it needs `keri.escrow`, which the adapter does not declare.

