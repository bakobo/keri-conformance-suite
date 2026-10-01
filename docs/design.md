# Design

This document is the reference for how the suite works and why. It is written to stand on its own: the repository's `this.i` records the same decisions while the suite incubates at Bakobo, but `this.i` will be removed when the suite moves to the KERI Foundation, and this file will remain.

The adapter wire protocol has its own document, [`adapter-protocol.md`](adapter-protocol.md).

## What the suite is for

Implementations of CESR, KERI, ACDC and IPEX need a way to show that they are correct, and today they have none beyond agreeing with keripy on whatever inputs their authors thought to try. A survey of ten Rust codebases in September 2026 found defects that a shared corpus would have caught immediately — for example, CESR counters that count items where the CESR specification requires them to count quadlets, which made every stream unreadable to keripy and every keripy stream unreadable to them.

The suite supplies that corpus. Each **case** is a fixed input together with a set of **assertions** about what an implementation must report for it. An implementation runs the cases through a small **adapter** and the **runner** checks each assertion against what the adapter reports. The result is a **result record**: a version-stamped, machine-readable account of which assertions held, which failed, and which did not apply.

## Principles

These rules shape everything below. Each exists to prevent a specific failure.

**The spec text is the authority, not keripy.** keripy generates most expected values, because it is the reference implementation and the only one that covers everything. That makes it easy for keripy's bugs to become the suite's law. So every assertion cites the spec clause it tests, and where keripy's output contradicts that clause, the case is marked `disputed` instead of being resolved here. A case is also disputed when two clauses of the specs themselves state conflicting rules about what it tests. A disputed case is excluded from conformance results until the question is settled by the spec working group.

**Requirement levels attach to assertions, not to cases.** One case typically checks several things at different levels. An out-of-order delivery, for example, checks that the early event is not accepted when it arrives — a MUST, because the spec forbids accepting an event whose signatures do not satisfy its thresholds — and that it is accepted once its predecessor arrives, which is only a SHOULD, because the spec says a validator SHOULD escrow such an event rather than requiring it to. Each assertion carries the clause it rests on and that clause's level: `MUST`, `SHOULD` or `MAY`. Only MUST assertions decide conformance; SHOULD and MAY results are reported separately. A case with no assertion that rests on a clause does not belong in the conformance cases.

**Behaviour the specs do not define lives in named profiles.** keripy's escrow taxonomy, its error classes, its HTTP endpoints, the CESR 1.00 count-code table that keripy 1.x uses, and roles such as registrars and observers that have no specification yet are all real and all useful to test, but none of them is conformance. Cases for them belong to a clearly labelled non-normative profile, which reports interoperability with a named implementation and never claims more.

**Published expectations never change.** A case id is permanent, and so is every assertion in it. If a case turns out to be wrong, it is deprecated and a corrected case is added under a new id that the old one points to. A result recorded against a suite release therefore never silently changes meaning, and an implementation that regresses between releases has changed, rather than the suite having moved under it.

**Fixtures are generated, never hand-edited.** Cases are produced from small declarative scenario files by generators. CI regenerates every case in a pinned environment and fails if any byte differs. Editing an expected value to make an implementation pass is therefore not just forbidden but impossible to merge.

**Anything but an answer is a failure.** An adapter declares the features its implementation supports when it starts, and the runner does not send a case that needs an undeclared feature; that case is recorded as `not-supported`. For every case the runner does send, the adapter must answer. A crash, a hang past the time limit, an oversized or malformed response, or an `unsupported` reply to a case it declared support for are all failures of every assertion in that case. This matters most for the cases that matter most: a parser that panics or loops on a hostile stream fails the must-reject cases built to catch it, instead of disappearing from the tally. The only outcome that is not scored is a fault on the runner's side, such as being unable to start the adapter at all, and the runner retries such a fault before recording it.

**Results say whose logic was tested.** A library that verifies events but does not route, escrow or detect duplicity needs its adapter to supply that logic before it can run a KERI case. When an adapter does that, it declares which behaviours it composes, and the result record and any conformance claim say so: "conformant with the adapter composing escrow" is a different claim from "conformant". Otherwise a deployment of the bare library could be credited with behaviour only the adapter performs.

**Shared defects are flagged.** When keripy both produced a case's expected values and is the implementation under test, a pass proves only that keripy agrees with itself. The result record marks such passes as self-agreement.

## Layers and verdicts

Cases are grouped into four layers. Each has its own operation in the adapter protocol and its own report shape.

### CESR

A CESR case gives a byte stream and asserts either its decoded structure or a rejection.

The stream is delivered as raw bytes, never pre-decoded or pre-split, so that a parser must find its own way in: sniff the domain of the first byte, find the boundary of each serialized message from its version string, and cross any switch between text and binary domains or between JSON, CBOR and MessagePack bodies.

The decoded structure describes the wire, not any implementation's object model. It is a sequence of items in stream order, each with its start and end offset in the stream. An item is one of:

- a **primitive**: its code and its raw value, in hex;
- an **indexed signature**: its code, its raw value, and each index field that its code's table entry defines on the wire — nothing an implementation infers;
- a **count code**: its code and the value of its size field exactly as encoded, plus the genus and version where the code carries them;
- a **serialized message body**: its protocol, version, serialization kind and declared size, for bodies framed by a version string (JSON, CBOR, MessagePack). A body in native CESR is reported as what it is on the wire: a count code followed by its primitives.

Offsets are how framing is checked. A count code's assertion includes the offset at which its group ends, so a parser that reads a size field as a number of items where the spec says quadlets ends the group in the wrong place and fails, even if it reports the raw size value correctly.

A rejection names a class — for example, truncated input, an unknown code, or a count that overruns the stream. The class is informative. An assertion that a stream must be rejected holds if the implementation rejects it, whatever class it reports.

The CESR layer also has an encoding operation: given a code and raw bytes, produce the text or binary encoding.

### KERI

A KERI case delivers a sequence of messages, in order, to a fresh validator, and asserts what the validator did with each message and what it ended up believing.

**Perspective.** What a validator should do depends on who it is: the same sequence can leave an event pending for an ordinary validator and accepted by a witness of that identifier. Every KERI case therefore states its perspective, and the first cases all take the perspective of an ordinary validator with no special relationship to the identifiers involved. Cases from the perspective of a witness, a delegator or a watcher follow, each stated as such.

**Quiescence.** After each message is delivered, the implementation processes everything it can — including anything held in escrow that the new message unblocks — until nothing further changes. The adapter is responsible for driving the implementation to this point, and the adapter protocol requires it. The **initial** disposition of a message is its state at quiescence after its own delivery; its **final** disposition is its state at quiescence after the last message. Defining both at quiescence is what makes them a property of the implementation rather than of when an adapter happened to look.

**The decision procedure.** Each message's disposition is determined by the first of these steps that applies. Each step cites the clause it rests on, and the generator records which step decided each disposition.

1. The message is not well-formed — its encoding does not parse, its SAID does not match its content, or its fields violate the event schema — so it is **rejected**.
2. The validator holds the key state needed to verify the message, and none of its controller signatures verifies against it, so it is **rejected**. The KERI spec says such a message MUST be dropped, not escrowed. This step comes before any conflict check, so a conflicting event carrying a forged signature is rejected, never treated as evidence of duplicity.
3. The message is valid but cannot yet be accepted: its signatures do not satisfy the signing or witness threshold, its prior event has not been accepted, or a delegator's approval has not been seen. It is **not accepted**, and an implementation SHOULD keep it as **pending**.
4. The message conflicts with an event already accepted at the same sequence number. If the specification's recovery rule permits it to supersede that event, it is **accepted** and the earlier event becomes **superseded**. Otherwise it is **not accepted**, and an implementation MAY record it as **duplicitous**.
5. Otherwise it is **accepted**. A message identical to one already accepted is accepted again without changing anything.

**What is graded at which level.** The MUST assertions use only the distinction between accepted and not accepted, initially and finally, because that is the distinction the MUST clauses draw. Whether a not-accepted message is reported as pending, rejected or duplicitous is a refinement, asserted at the level of the clause that defines it: rejection of an unverifiable message is a MUST; pending is a SHOULD; duplicitous is a MAY. A message's final disposition can also be **superseded**, asserted at the level of the recovery clause.

**Key state.** A case asserts the final key state of each identifier involved: its sequence number, the SAID of its latest accepted event, its current signing keys and threshold, its next key digests and threshold, its witnesses and witness threshold, and its delegator if it has one. Those are the facts a relying party acts on. A key-state assertion takes the weakest level of any disposition it depends on, so the key state at the end of an out-of-order delivery is a SHOULD, because reaching it depends on escrow. Thresholds are compared after normalization by the runner, so that `"1"` and `"0x1"`, or a single weighted clause written with and without its enclosing list, compare equal; adapters report thresholds as their implementation holds them.

A disposition can also carry a reason, such as an unmet signing threshold or a broken pre-rotation commitment, and keripy's finer escrow categories (out-of-order, partially signed, partially witnessed, awaiting delegation). These are reported when an adapter supplies them and never decide a case.

**Emitting events.** The KERI layer also has an emitting operation: given raw key seeds and event parameters, produce the signed event. The assertions are that the event body is byte-for-byte what the specification's serialization rules determine, which includes its SAID; that every signature verifies against the stated keys; and that the attachments, once parsed, carry the same signatures with the same indexes. The framing of attachments is not asserted byte-for-byte, because the specification allows more than one valid way to group them. Cases supply raw private key seeds rather than salts, because salt-to-key derivation is a keripy convention and not part of the specification. Any timestamp an event carries is a fixed input.

Escrow timeouts are out of scope. Adapters drive each case synchronously, and no case depends on elapsed time.

### ACDC

An ACDC case gives a bundle and an evaluation point, and asserts a verdict. The bundle is the issuer's KEL, the registry's TEL, the credential, and any chained credentials with their own KELs and TELs. The evaluation point fixes which TEL and KEL events count as having happened, so a regenerated case never depends on the clock.

The verdict is one of `valid`, `revoked` (the credential was valid when issued and has since been revoked), `invalid` (something in it does not verify), or `incomplete` (a dependency it needs is missing from the bundle). Like KERI dispositions, these are graded at the level of the clause that defines each distinction, and a refinement the spec does not define is informative.

Disclosure forms are tested as construction properties. The SAID of a credential's compact form must equal the SAID of its expanded form; a selectively disclosed attribute must verify against its blinded commitment; a partially disclosed chain must still verify through its edges. Chain-link confidentiality and contractually protected disclosure have a protocol half, which IPEX would test, and a legal half — whether the terms bind anyone — which no test can check.

### IPEX

The IPEX exchange messages (apply, offer, agree, grant, admit, spurn) are specified, but the rules for which message may validly follow which, and for when a message starts a new exchange rather than continuing one, are not yet stated normatively. Until they are, the suite tests only what is specified: that each exchange message is well-formed, carries a verifiable signature, and refers correctly to the credentials and prior messages it names. Transcript cases that classify each message as a valid or invalid next step will be added when a normative transition rule exists to cite, and until then belong to a non-normative profile. Writing them now would make the suite the specification of IPEX's state machine, which is the working group's decision to make.

### Roles

What a role must believe is tested through ordinary KERI cases taken from that role's perspective: witness thresholds and receipt validity under KAWA; duplicity detection and first-seen behaviour for a watcher given divergent KELs from different sources. How a role behaves as a running service depends on a transport the specifications do not define, so tests of that kind — a witness serving receipts over keripy's HTTP interface, for example — belong in a non-normative profile.

## Cases

Each case is one JSON file, at `cases/<layer>/<id>.json`. Case ids are a layer prefix and a four-digit number — `CESR-0001`, `KERI-0001`, `ACDC-0001`, `IPEX-0001` — assigned in order and never reused. The number carries no meaning; the file's metadata does.

A case records:

- `id`, `title`, and a short `description` of what it tests and why.
- `status`: `active`, `draft`, `disputed`, or `deprecated`.
- `profile`: the profile the case belongs to.
- `targets`: the wire versions its inputs use, and the `features` an implementation must support to run it.
- `input`, including the perspective and evaluation point where they apply.
- `assertions`: each with what it checks, the expected value, the clause it rests on as a link to a stable anchor in a pinned specification commit, and that clause's requirement level.
- `provenance`: the scenario and generator that produced the case, and the implementation and commit that produced its expected values — or, for values derived directly from a specification, the specification commit.
- For a deprecated case, `superseded_by`; for a disputed case, a `dispute` record giving the clauses involved, what keripy does where that is the question, and where the question was raised.

## Scenarios and generators

A scenario is a small declarative file, under `scenarios/<layer>/`, that describes cases without their bytes: which identifiers exist, which keys they use, which events are built and in what order they are delivered, what tampering is applied, and which decision-procedure step each message is expected to reach. A generator turns scenarios into cases. The first generator drives keripy; others can follow, and a CESR generator that works from the specification's own code tables would remove keripy from the provenance of most of the CESR layer.

A generator does not take keripy's word for a disposition. It computes each disposition from the decision procedure and the scenario, uses keripy to produce the bytes and to cross-check, and records any disagreement between keripy and the procedure as a candidate dispute for a maintainer to review. That matters because keripy's behaviour does not always match the procedure, and when it does not, the difference is exactly what the suite exists to surface.

Generators must be deterministic. Keys come from fixed seeds, timestamps are fixed, and a generator records its own version and the commit of whatever it drove. CI regenerates every case from its scenario and fails on any difference.

## Targets and profiles

Cases identify what their inputs are by the protocol versions that appear on the wire, not by implementation release numbers, which are ambiguous — keripy's 2.x release line implements version 1.0 of most of the specifications, and the wire format it emits by default carries version 2.00 codes.

A **profile**, under `profiles/`, is a named set of cases that an implementation can claim: "passes every active MUST assertion in profile P". A profile's status comes from the maturity of the text its assertions cite, not from the wire version of its inputs. The specifications at version 1.0 define the 2.00 code tables and require 2.XX implementations to accept 1.XX version strings, so cases built on those clauses are normative and active, including the count-code cases that motivated the suite. Where expected values come from an implementation whose behaviour is still moving — keripy's main branch, for example, ahead of a release — the case is `draft`, pinned to the commit it was generated from, and its results are advisory until it is regenerated against a release.

Some behaviour that many deployments depend on has no normative text: the CESR 1.00 count-code table used by keripy 1.x, for example. The suite tests it anyway, in a profile named for what it is — interoperability with keripy 1.x — so that nobody mistakes passing it for conformance.

## Versioning

Three things are versioned, and every result record states all three.

**The suite** uses semantic versioning. Adding cases is a minor release. Deprecating cases, or changing the adapter protocol incompatibly, is a major release. Changes to documentation and metadata are patches. Because assertions never change in place, a minor release can only add cases; it can make an implementation that previously passed everything fail a new case, but it cannot turn an old pass into a failure.

**The adapter protocol** has its own version, declared in the handshake. The runner accepts the current protocol version and the one before it, so adapters maintained outside this repository have a full major cycle to catch up.

**An adapter** follows its implementation's release line, because that is what its users will pin, and reports the exact implementation commit it was built against.

A conformance claim is therefore a tuple: suite version, profile, adapter version, implementation commit, and the list of behaviours the adapter composes, if any.

## Adapters

An adapter is a small standalone program that connects one implementation to the runner. Adapters build against a released or pinned version of their implementation and use only its public API. They never patch the implementation. Where it lacks something a case needs, the adapter composes it on top and declares that it has done so. That way an adapter keeps working whether or not the implementation's maintainers ever choose to host it, and its results stay honest about what was tested.

Adapters start in this repository under `adapters/<name>/`, each self-contained so it can be lifted into its implementation's repository unchanged. The keripy adapter stays here permanently, because keripy is also a generator.

## Continuous integration

CI runs at three levels:

1. **On every pull request, cheaply:** the runner's own tests, validation of every case against the case schema, and regeneration of every case with a byte-for-byte comparison.
2. **On every pull request, more slowly:** each adapter is built against its pinned implementation and run against the suite, and its results are compared with a baseline committed for that adapter. A regression fails the pull request. An improvement asks for the baseline to be updated in the same pull request.
3. **Nightly, advisory:** each adapter is built against its implementation's latest development head and run, and the result records are kept as artifacts. Accumulated, those records are the compatibility matrix; nobody maintains one by hand.

## Security

A case that a released implementation handles unsafely is, in effect, a public proof of concept against that implementation. "Unsafely" means failing a MUST assertion in a way with a security consequence: accepting what must be rejected, retaining what must be dropped, or crashing or hanging. That includes keripy.

Such a case is embargoed. It is held outside the public tree, in a private repository, until the affected project has been told privately and has had up to 90 days to ship a fix, as `SECURITY.md` describes. The embargo takes precedence over every other rule here, including the rule that a case keripy contradicts is published as disputed. While a case is embargoed, nothing derived from it is published either: not its scenario, not baseline changes it would cause, and not nightly results that include it. CI runs embargoed cases only in the private repository.

The runner executes adapter programs, and adapters execute implementation code. The runner treats an adapter's output as untrusted: it bounds the size of every response, validates its shape before reading it, and enforces a time limit on every request.
