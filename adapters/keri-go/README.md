# keri-go adapter

Connects grapeid/keri-go, a KERI implementation in Go, to the conformance runner over adapter protocol version 1 ([`docs/adapter-protocol.md`](../../docs/adapter-protocol.md)). It implements `cesr.parse`, `cesr.encode` and `keri.process`. keri-go validates a whole key log at a time and has no per-message processor, so the adapter supplies the routing that `keri.process` needs and declares it: `composes` is `["keri.routing"]`. Every verdict, accept or reject, is keri-go's. The design decision is node `3t0efrq7` in [`this.i`](../../this.i).

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

Every case in `cesr-v1.0`, `cesr-strict`, `keri-v1.0.1`, `keri-escrow` and `acdc-v1.0` requires `cesr.genus-2.00` and, except the encode cases, `keri.version-2.x`, so the runner sends none of them and each profile's verdict is `no-evidence`. In `keripy-1x-interop`, CESR-0045 to CESR-0048 need `cesr.item-extents` (CESR-0048 also `cesr.genus-2.00`), so those four are not sent. The must-reject cases on KERI 1.0 streams, CESR-0049, CESR-0050, CESR-0052, CESR-0054 and CESR-0057, are sent and all five pass: keri-go refuses each stream, as keripy 1.2.14 does. That profile's verdict is `interoperable`, scoped to the five cases sent.

CESR-0054's stream has a receipt couple whose prefix carries an unassigned code. keri-go refuses it, but because its reader measures the couple at a fixed width and the stream is shorter than that, not because it reads the code; its reader never checks a couple's codes.

## How each operation works

### `cesr.parse`

The adapter hands the stream to keri-go's `ParseKELStream`, which splits it into messages, framing each body by matching braces and measuring each attachment group from its count code, then calls `DetectVersion` on each message. Either one refusing is a rejection whose `class` names it, `ParseKELStream` or `DetectVersion`; keri-go's reason goes to standard error. Otherwise the answer is `{"accepted": {"consumed": n}}` with `n` the length of the stream, because `ParseKELStream` either reads to the end of the stream or refuses it. The adapter never parses CESR itself.

### `cesr.encode`

`MatterQB64(code, raw)`, in the text domain, for the five codes keri-go names: `E` (Blake3-256 digest), `D` and `B` (Ed25519 keys), `0B` (Ed25519 signature) and `A` (Ed25519 seed). `MatterQB64` would apply the same arithmetic to any code, but it does not check codes or raw sizes against a table, so a code keri-go does not name is answered `unsupported` rather than with bytes keri-go never claimed.

### `keri.process`

For each delivered message, in order, starting from empty state per request:

1. `ParseKELStream` must find exactly one message in it, `DetectVersion` must read its version string, and `ParseEvent` must read it. Anything else is `rejected`.
2. Only `icp`, `rot` and `ixn` are routed. A `dip` or `drt`, a receipt, and any other message is `rejected`, with a reason saying so.
3. The event is routed to its identifier's log of seen messages. If its sequence number is beyond the end of the log, the candidate log is the log plus the event; if the position is already held by the same event (same SAID), the candidate is the log up to that position plus this delivery; if it is held by a different event, the delivery is `rejected`, because nothing supersedes.
4. keri-go's `ValidateSignedKEL` must accept the candidate log. It checks every event's fields, version-string size, SAID, derivation, thresholds, sequence, prior digest, pre-rotation, and controller signatures against the key state in force.
5. If the witness threshold in force once the event is applied is not zero, keri-go's `ReceiptsMeetThreshold` must count at least that many valid receipt couples, from the witnesses in force, attached to the delivery.
6. If both pass the message is `seen` and, unless it repeats a seen event, appended to the log; otherwise it is `rejected`, with keri-go's reason.

Nothing is escrowed, so a message's reading after the last delivery is its reading on arrival, and `trunk` is `true` exactly when the message is seen.

### What the adapter computes, and what comes from keri-go

| Value | Source |
|---|---|
| Accept or reject of each delivery | keri-go: `ParseKELStream`, `DetectVersion`, `ParseEvent`, `ValidateSignedKEL`, `ReceiptsMeetThreshold`; the adapter decides only which log a message joins and refuses what it does not route |
| End of an event's body, for `ReceiptsMeetThreshold` | The size in the version string, read by keri-go's `ParseVersionString`; `ValidateSignedKEL` has already checked that it equals the length of the body keri-go framed |
| Witnesses and witness threshold in force | Replayed by the adapter from `b`, `br`, `ba` and `bt` as keri-go's `ParseEvent` read them, as keri-go's own `ValidateKEL` does internally without exporting the result |
| `key_states`: `sn`, `said` | The last seen event, as `ParseEvent` read it |
| `keys`, `kt`, `ndigs`, `nt` | The last seen establishment event's `k`, `kt`, `n` and `nt`, as `ParseEvent` read them |
| `wits`, `bt` | The replayed witness list and threshold, `bt` in lowercase hex |
| `delegator` | Always `null`: no delegated event is ever seen |

## Errors

`hello` negotiates from the request's `supported` list, or `[protocol]` when the list is absent, and answers with protocol 1, or with an `unsupported` error (`e.feature.unsupported.protocol-version.f`) when the integer 1 is not offered. Request fields the adapter does not know are ignored. A request line may be at most 64 MiB (`maxRequestLine`, not counting its newline); a longer line gets an error whose `id` is null (`e.input.range.request-size.f`) and is skipped without being held. A line that is not a JSON object, including a blank line, or whose `id` is not an integer from 0 to 2^64−1, gets an error whose `id` is null (`e.input.format.request.f`). A request without a string `op` or with malformed fields is a `harness` error carrying its id (`e.input.format.request.f`), and an unknown `op` is too (`e.input.range.unknown-op.f`). `keri.emit`, `acdc.verify` and `exn.verify` get an `unsupported` error (`e.feature.unsupported.undeclared-op.f`), as do `cesr.encode` in the binary domain (`e.feature.unsupported.binary-domain.f`), a code keri-go does not name (`e.feature.unsupported.code.f`), and a code keri-go refuses to encode (`e.input.format.encode-refused.f`). A panic anywhere in an operation, including inside keri-go, is caught, its stack written to standard error, and answered as a `harness` error (`e.self.unknown.panic.f`); the adapter goes on to the next request. The adapter exits with status 0 at end of input; if it cannot read standard input or write standard output it says why on standard error (`e.env.io.stdio.f`) and exits with status 1. Every code ends in `f`: none of these failures clears on retry.
