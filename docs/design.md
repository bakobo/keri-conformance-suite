# Design

This document is the reference for how the suite works and why. It is written to stand on its own: the repository's `this.i` records the same decisions while the suite incubates at Bakobo, but `this.i` will be removed when the suite moves to the KERI Foundation, and this file will remain.

The adapter wire protocol has its own document, [`adapter-protocol.md`](adapter-protocol.md).

## What the suite is for

Implementations of CESR, KERI, ACDC and IPEX need a way to show that they are correct, and today they have none beyond agreeing with keripy on whatever inputs their authors thought to try. A survey of ten Rust codebases in September 2026 found defects that a shared corpus would have caught immediately — for example, CESR 2.0 counters that count items where keripy counts quadlets, which made every stream unreadable to keripy and every keripy stream unreadable to them.

The suite supplies that corpus. Each **case** is a fixed input together with an **expected verdict** that does not depend on any implementation. An implementation runs the cases through a small **adapter** and the **runner** compares what it reports with what the case expects. The result is a **result record**: a version-stamped, machine-readable account of which cases passed, which failed, and which did not apply.

## Principles

These rules shape everything below. Each exists to prevent a specific failure.

**The spec text is the authority, not keripy.** keripy generates most expected values, because it is the reference implementation and the only one that covers everything. That makes it easy for keripy's bugs to become the suite's law. So every case cites the spec clause it tests, and where keripy's output contradicts that clause, the case is marked `disputed` instead of being resolved here. A disputed case is excluded from conformance results until the spec working group settles the question.

**No case without a normative clause.** A case must cite the clause it tests and carry that clause's requirement level: `MUST`, `SHOULD` or `MAY`. Only `MUST` cases decide conformance; `SHOULD` and `MAY` results are reported separately. This matters in practice. The KERI spec says a validator SHOULD escrow an event whose signatures do not yet satisfy its thresholds, so an implementation that drops such an event is conformant on that point, and an out-of-order case that expects it to be escrowed and accepted later is a `SHOULD` case. Behaviour that no spec clause requires — keripy's escrow taxonomy, its error classes, its HTTP endpoints, roles such as registrars and observers that have no spec yet — belongs in a labelled non-normative profile, or waits for a spec.

**Published expectations never change.** A case id is permanent, and so is its expected verdict. If a case turns out to be wrong, it is deprecated and a corrected case is added under a new id that the old one points to. A result recorded against a suite release therefore never silently changes meaning, and an implementation that regresses between releases has changed, rather than the suite having moved under it.

**Fixtures are generated, never hand-edited.** Cases are produced from small declarative scenario files by generators. CI regenerates every case in a pinned environment and fails if any byte differs. Editing an expected value to make an implementation pass is therefore not just forbidden but impossible to merge.

**Not supported is declared, not claimed.** An adapter declares the features its implementation supports when it starts. The runner does not send a case that needs an undeclared feature, and records that case as `not-supported`. If an adapter answers a case it declared support for with anything but a verdict, that is a failure. An adapter cannot hide a failure by calling it unsupported.

**Shared defects are flagged.** When keripy both produced a case's expected value and is the implementation under test, a pass proves only that keripy agrees with itself. The result record marks such passes as self-agreement.

## Layers and verdicts

Cases are grouped into four layers. Each layer has its own operation in the adapter protocol and its own verdict shape.

### CESR

A CESR case gives a stream and expects either its decoded structure or a rejection.

The decoded structure is a flat sequence of items in stream order. Each item is a primitive (code and raw bytes), an indexed signature (code, raw bytes, index and, where present, the other index), a counter (code and count, plus the genus and version where the counter carries them), or a serialized message (protocol, version, serialization kind, size and SAID). Raw bytes are hex. The structure is deliberately flat: grouping is implied by the counters, and a flat sequence is something every parser can produce without adopting another parser's object model.

A rejection names a class — for example, truncated input, an unknown code, or a count that overruns the stream. The class is informative. A case passes if the implementation rejects a stream that must be rejected, whatever class it reports, and the class is compared and reported but never fails a case.

The CESR layer also has an encoding operation: given a code and raw bytes, produce the text or binary encoding. That tests the emitting side, where parsing tests the reading side.

### KERI

A KERI case gives a sequence of messages, delivered in order, and expects a disposition for each message and the final key state of each identifier involved.

The dispositions are:

- `accepted` — the message was validated and applied.
- `pending` — the message was not accepted, but may become acceptable once something else arrives, such as more signatures, a receipt, a prior event or a delegator's seal.
- `rejected` — the message was dropped as invalid. A message with no verifiable controller signature is always rejected; the spec says such a message MUST be dropped rather than escrowed.
- `duplicitous` — the message conflicts with an event already accepted for the same identifier and sequence number, and was not accepted because of that conflict.

Each message gets two dispositions: its **initial** disposition, at the moment it was delivered, and its **final** disposition, after the whole sequence was delivered. A message delivered out of order is typically `pending` initially and `accepted` finally. The initial disposition tests what a validator MUST NOT do too early — accept an event before its thresholds are met. The final disposition and the final key state test what it ends up believing.

The final key state of an identifier records its sequence number, the SAID of its latest event, its current signing keys and threshold, its next key digests and threshold, its witnesses and witness threshold, and its delegator if it has one. Those are the facts a relying party acts on, so they are what two implementations must agree about.

A disposition can carry a reason class, such as an unmet signing threshold or a broken pre-rotation commitment. Like CESR rejection classes, reasons are informative. keripy's finer escrow categories (out-of-order, partially signed, partially witnessed, awaiting delegation) are reported when an adapter supplies them, and never decide a case, because the spec does not define them and other implementations name and structure escrows differently.

The KERI layer also has an emitting operation: given raw key seeds and event parameters, produce the signed event. Ed25519 signing is deterministic, so for Ed25519 the expected output is exact bytes. Where a signature scheme is not deterministic, the case checks that the output verifies and that every unsigned part matches. Cases supply raw private key seeds rather than salts, because salt-to-key derivation is a keripy convention and not part of the spec. Any timestamp an event or message carries is a fixed input.

Escrow timeouts are out of scope. Adapters process each case synchronously, and a case never depends on elapsed time.

### ACDC

An ACDC case gives a bundle — the issuer's KEL, the registry's TEL, the credential, and any chained credentials with their own KELs and TELs — and expects `valid` or `invalid`, with an informative reason.

Disclosure forms are tested as construction properties. The SAID of a credential's compact form must equal the SAID of its expanded form; a selectively disclosed attribute must verify against its blinded commitment; a partially disclosed chain must still verify through its edges. Chain-link confidentiality and contractually protected disclosure have a protocol half, which IPEX cases test, and a legal half — whether the terms bind anyone — which no test can check. The suite says so instead of pretending otherwise.

### IPEX

IPEX is a protocol, and its transport is not specified. The suite tests it in two ways, and the first comes first.

**Transcript cases** give a recorded sequence of exchange messages (apply, offer, agree, grant, admit, spurn) together with the KELs and TELs they depend on, and expect the implementation, acting as an observer, to classify each message as a valid next step or a protocol violation. For example, a transcript in which the discloser grants a full credential before the disclosee has agreed to the rules attached to the offer is a violation by the discloser.

**Role cases**, later, will have the implementation play the discloser or the disclosee against a scripted peer, through an adapter that hides the transport.

### Roles

Witnesses, watchers and similar roles are tested in two ways. What a role must believe is tested through ordinary KERI cases: witness thresholds and receipt validity under KAWA; duplicity detection and first-seen behaviour for a watcher, given divergent KELs from different sources. How a role behaves as a running service is a different question, because it depends on a transport the spec does not define. Tests of that kind, such as a witness serving receipts over keripy's HTTP interface, belong in a non-normative profile.

## Cases

Each case is one JSON file, at `cases/<layer>/<id>.json`. Case ids are a layer prefix and a four-digit number — `CESR-0001`, `KERI-0001`, `ACDC-0001`, `IPEX-0001` — assigned in order and never reused. The number carries no meaning; the file's metadata does.

A case records:

- `id`, `title`, and a short `description` of what it tests and why.
- `status`: `active`, `draft` (a target still in flux, such as 2.x), `disputed`, or `deprecated`.
- `requirement`: `MUST`, `SHOULD` or `MAY`.
- `clauses`: each spec clause the case tests, as a link to a stable anchor in a pinned spec commit.
- `targets`: the wire versions the case's inputs use, and the `features` an implementation must support to run it.
- `input` and `expected`, in the shapes described above.
- `provenance`: the scenario and generator that produced the case, and the implementation and commit that produced the expected value — or, for cases derived directly from the spec, the spec commit.
- For a deprecated case, `superseded_by`; for a disputed case, a `dispute` record giving the clause, what keripy does, what the clause appears to require, and where the question was raised.

## Scenarios and generators

A scenario is a small declarative file, under `scenarios/<layer>/`, that describes cases without their bytes: which identifiers exist, which keys they use, which events are built and in what order they are delivered, and what tampering is applied. A generator turns scenarios into cases. The first generator drives keripy; others can follow, and a CESR generator that works from the spec's own code tables would remove keripy from the provenance of the CESR layer entirely.

Generators must be deterministic. Keys come from fixed seeds, timestamps are fixed, and a generator records its own version and the commit of whatever it drove. CI regenerates every case from its scenario and fails on any difference.

## Targets and profiles

Cases identify what they target by the protocol versions that appear on the wire, not by implementation release numbers, which are ambiguous — keripy's 2.x line corresponds to 1.0 of most of the specs.

A **profile**, under `profiles/`, is a named set of wire versions and features, with a status. Profiles let an implementation say precisely what it claims: "passes every active MUST case in profile P". A profile whose target is still moving is `draft`, is pinned to the keripy commit and spec commits its cases were generated from, and produces advisory results. The 1.0 profiles are populated first. The 2.x profile is built at the same time as a draft, because implementations are shipping on 2.x before its specs settle.

Behaviour outside the specs gets its own clearly named non-normative profiles, so that interop checks of real value — a witness's HTTP interface, for example — have a home that cannot be mistaken for conformance.

## Versioning

Three things are versioned, and every result record states all three.

**The suite** uses semantic versioning. Adding cases is a minor release. Deprecating cases, or changing the adapter protocol incompatibly, is a major release. Changes to documentation and metadata are patches. Because expected verdicts never change in place, a minor release can only add cases; it can make an implementation that previously passed everything fail a new case, but it cannot make an old pass become a failure.

**The adapter protocol** has its own version, declared in the handshake. The runner accepts the current protocol version and the one before it, so adapters maintained outside this repository have a full major cycle to catch up.

**An adapter** follows its implementation's release line, because that is what its users will pin, and reports the exact implementation commit it was built against.

A conformance claim is therefore a tuple: suite version, profile, adapter version, and implementation commit.

## Adapters

An adapter is a small standalone program that connects one implementation to the runner. Adapters build against a released or pinned version of their implementation and use only its public API. They never patch the implementation; where it lacks an entry point the suite needs, the adapter composes one on top. That way an adapter keeps working whether or not the implementation's maintainers ever choose to host it.

Adapters start in this repository under `adapters/<name>/`, each self-contained so it can be lifted into its implementation's repository unchanged. The keripy adapter stays here permanently, because keripy is also a generator.

## Continuous integration

CI runs at three levels:

1. **On every pull request, cheaply:** the runner's own tests, validation of every case against the case schema, and regeneration of every case with a byte-for-byte comparison.
2. **On every pull request, more slowly:** each adapter is built against its pinned implementation and run against the suite, and its results are compared with a baseline committed for that adapter. A regression fails the pull request. An improvement asks for the baseline to be updated in the same pull request.
3. **Nightly, advisory:** each adapter is built against its implementation's latest development head and run, and the result records are kept as artifacts. Accumulated, those records are the compatibility matrix; nobody maintains one by hand.

## Security

A must-reject case that a released implementation wrongly accepts is, in effect, a public proof of concept against that implementation. Such a case is held out of the public tree until the affected project has been told privately and has had up to 90 days to ship a fix. `SECURITY.md` describes how to report one.

The runner executes adapter programs, and adapters execute implementation code. The runner treats an adapter's output as untrusted: it bounds the size of every response, validates its shape before reading it, and enforces a time limit on every request.
