# Design

This document is the reference for how the suite works and why. It is written to stand on its own: the repository's `this.i` records the same decisions while the suite incubates at Bakobo, but `this.i` will be removed when the suite moves to the KERI Foundation, and this file will remain.

The adapter wire protocol has its own document, [`adapter-protocol.md`](adapter-protocol.md). Terms with a meaning specific to the suite are defined at the end of this document, under Terms.

**Status.** This document describes the suite as designed. As of the first release candidate, what exists is the runner's skeleton and the feature vocabulary; the case schema, cases, runner commands, adapters and CI levels 2 and 3 are being built in that order.

## What the suite is for

Implementations of CESR, KERI, ACDC and IPEX need a way to show that they are correct, and today they have none beyond agreeing with keripy on whatever inputs their authors thought to try. A survey of ten Rust codebases in September 2026 found defects that a shared corpus would have caught immediately — for example, CESR counters that count items where the CESR specification requires them to count quadlets, which made every stream unreadable to keripy and every keripy stream unreadable to them.

The suite supplies that corpus. Each **case** is a fixed input together with a set of **assertions** about what an implementation must report for it. An implementation runs the cases through a small **adapter** and the **runner** checks each assertion against what the adapter reports. The result is a **conformance report**: a version-stamped, machine-readable account of which assertions held, which failed, and which did not apply.

## Principles

These rules shape everything below. Each exists to prevent a specific failure.

**The spec text is the authority, not keripy.** Expected values are derived from the pinned specification wherever a generator can do so: the CESR generator reads its code tables from the specification text and encodes from them. keripy, the reference implementation, is used to generate bytes only where the specification gives no tables to derive them from, and to cross-check what the generators produce, never as the authority. Even so, it would be easy for keripy's bugs to become the suite's law. So every assertion cites the spec clause it tests, and where keripy's output contradicts that clause, the case is marked `disputed` instead of being resolved here. A disputed case is excluded from conformance results until the question is settled by the spec working group.

**When the specification disagrees with itself, the keyword sentence governs.** A sentence that carries an RFC 2119 keyword (MUST, SHOULD, MAY) outranks a table, a legend or an example that says something different. The assertion keeps that sentence's level and stays active, and the conflict is recorded in the assertion's `spec_conflicts` and raised with the working group. A case is disputed only when an implementation's behaviour, not the specification's own text, contradicts the clause. For example, the CESR specification says a count code's size MUST count quadlets, while its symbol legends describe the same digits as counting primitives; the cases follow the MUST and record the legends.

**An obligation the specification states only for producers is graded SHOULD for validators.** The CESR specification says, for example, that pad bits MUST be zero, but not what a parser MUST do with a stream whose pad bits are not. Rejecting such a stream is the natural reading, so the suite asserts it, but at SHOULD, with the inference recorded in the assertion's `inferred_from`, and each such inference is raised as a request that the specification state the validator's rule. If it does, the case is re-issued at the stated level under a new id. `generators/SPEC-ISSUES.md` keeps the list. The KERI layer grades one more kind of inference the same way. The KERI specification states when a validator may accept an event but never that it must, so every assertion that a valid event is accepted is an inferred SHOULD, as described under KERI.

**Requirement levels attach to assertions, not to cases.** One case typically checks several things at different levels. An event delivered with too few signatures, for example, is checked for not being accepted when it arrives — a MUST, because the KERI specification forbids accepting an event whose signatures do not satisfy its thresholds — and for being accepted once the missing signatures arrive, which is only a SHOULD, because the specification says such an event SHOULD be escrowed rather than requiring it. Each assertion carries the clause it rests on and that clause's level: `MUST`, `SHOULD` or `MAY`. Only MUST assertions decide the verdict, but SHOULD and MAY results are reported beside it, and a conformance claim states its SHOULD results (see Versioning). A case with no assertion that rests on a clause does not belong in the conformance cases.

**Behaviour the specs do not define lives in named profiles.** keripy's escrow taxonomy, its error classes, its HTTP endpoints, the CESR 1.00 count-code table that keripy 1.x uses, and roles such as registrars and observers that have no specification yet are all real and all useful to test, but none of them is conformance. Cases for them belong to a clearly labelled non-normative profile, which reports interoperability with a named implementation and never claims more.

**Published expectations never change.** A case id is permanent, and so is every assertion in it. If a case turns out to be wrong, it is deprecated and a corrected case is added under a new id that the old one points to. A conformance reported against a suite release therefore never silently changes meaning, and an implementation that regresses between releases has changed, rather than the suite having moved under it.

**Fixtures are generated, never hand-edited.** Cases are produced from small declarative scenario files by generators. CI regenerates every case in a pinned environment and fails if any byte differs. Editing an expected value to make an implementation pass is therefore not just forbidden but impossible to merge.

**Anything but an answer is a failure.** An adapter declares the features its implementation supports when it starts, and the runner does not send a case that needs an undeclared feature; that case is recorded as `not-supported`. For every case the runner does send, the adapter must answer. A crash, a hang past the time limit, an oversized or malformed response, or an `unsupported` reply to a case it declared support for are all failures of every assertion in that case; so is a summary of an accepted stream given where decoded items were required. This matters most for the cases that matter most: a parser that panics or loops on a hostile stream fails the must-reject cases built to catch it, instead of disappearing from the tally. The only outcome that is not scored is a fault on the runner's side, such as being unable to start the adapter at all, and the runner retries such a fault before recording it.

**Results say whose logic was tested.** A library that verifies events but does not route, escrow or detect duplicity needs its adapter to supply that logic before it can run a KERI case. When an adapter does that, it declares which behaviours it composes, and the conformance report and any conformance claim say so: "conformant with the adapter composing escrow" is a different claim from "conformant". Otherwise a deployment of the bare library could be credited with behaviour only the adapter performs.

**Shared defects are flagged.** When keripy both produced a case's expected values and is the implementation under test, a pass proves only that keripy agrees with itself. The conformance report marks such passes as self-agreement.

## Layers and verdicts

Cases are grouped into four layers. Each has its own operation in the adapter protocol and its own report shape.

### CESR

A CESR case gives a byte stream and asserts either its decoded structure or a rejection.

The stream is delivered as raw bytes, never pre-decoded or pre-split, so that a parser must find its own way in: sniff the domain of the first byte, find the boundary of each serialized message from its version string, and cross any switch between text and binary domains or between JSON, CBOR and MessagePack bodies.

The decoded structure describes the wire, not any implementation's object model. It is a sequence of items in stream order, each with its start and end offset in the stream. An item is one of:

- a **primitive**: its code and its raw value, in hex;
- an **indexed signature**: its code, its raw value, and each index field that its code's table entry defines on the wire — nothing an implementation infers;
- a **count code**: its code, the value of its size field exactly as encoded, and the offset at which its group ends;
- a **genus/version code**: its code, its genus and its version, which it carries instead of a size;
- a **serialized message body**: its protocol, version, serialization kind and declared size, for bodies framed by a version string (JSON, CBOR, MessagePack). A body in native CESR is reported as what it is on the wire: a count code followed by its primitives.

Offsets are how framing is checked. A count code's assertion includes the offset at which its group ends, so a parser that reads a size field as a number of items where the spec says quadlets ends the group in the wrong place and fails, even if it reports the raw size value correctly.

A rejection names a class — for example, truncated input, an unknown code, or a count that overruns the stream. The class is informative. An assertion that a stream must be rejected holds if the implementation rejects it, whatever class it reports.

Some implementations parse a stream correctly but never say where each item lay: they hand back decoded values without offsets. An adapter must not work the offsets out itself, from counts or code tables, because then the adapter's parsing is what gets tested. So reporting item extents is a feature, `cesr.item-extents`, and every case with a decoded-structure assertion requires it. An adapter without it may answer a stream its implementation accepts with a summary instead: the number of bytes consumed, and nothing about the items. A case whose assertions are all rejections does not require the feature, so such an adapter still gives real evidence where it matters most: a summary for a stream that must be rejected fails the assertion, because the implementation accepted it.

The CESR layer also has an encoding operation: given a code and raw bytes, produce the text or binary encoding.

### KERI

A KERI case delivers a sequence of messages, in order, to a fresh validator, and asserts what the validator did with each message and what it ended up believing. Line numbers in this section are of `spec/spec-body.md` in the KERI specification at tag v1.0.1, commit `71cb54eb`.

**Perspective.** What a validator should do depends on who it is: the same sequence can leave an event pending for an ordinary validator and accepted by a witness of that identifier. Every KERI case therefore states its perspective, and the first cases all take the perspective of an ordinary validator with no special relationship to the identifiers involved. Cases from the perspective of a witness, a delegator or a watcher follow, each stated as such.

**What MUST means here.** In the KERI layer a MUST assertion tests safety: the validator never accepts what the specification forbids, and drops what it says to drop. That includes the limits on superseding recovery. Rule C1 says that the root KEL of a delegation "by definition MUST be non-delegated therefore either A. or B. MUST be satisfied, or else the superseding rotation MUST be discarded" (line 1823). A non-delegated KEL is its own root, so for every KEL a rotation that tries to supersede an event outside rules A and B is discarded at MUST. A rotation signed with a stolen current key, trying to supersede an interaction that already lies before a later rotation, is refused at that level. Accepting valid events, which is liveness, is graded SHOULD, because no sentence obliges a validator to accept anything: the sentences that mention acceptance state preconditions for it (lines 1258–1264, 1612 and 1780). Each liveness assertion records that inference in `inferred_from`. One consequence is that a validator that accepts nothing passes every MUST assertion, so a conformance report and any claim made from it state their SHOULD results beside the verdict.

**Two readings.** Each message is reported by two readings. It is **seen** if the validator has accepted it into its copy of the KEL. The specification treats accepted and first seen as the same thing and makes it permanent: "Once an event has been first seen, it is always seen and can't be unseen" (line 1788). It is on the **trunk** if it lies on the KEL's undisputed path. An event that a superseding rotation displaces stays seen and leaves the trunk: "All the already-seen but superseded events in the superseded fork still remain in the KEL" (line 1799). **Superseded** therefore means seen and off the trunk; it is not a third value. A message that is not a key event, such as a receipt, is never on the trunk.

**Quiescence.** After each message is delivered, the implementation processes everything it can — including anything held in escrow that the new message unblocks — until nothing further changes. The adapter is responsible for driving the implementation to this point, and the adapter protocol requires it. A message's **initial** seen reading is taken at quiescence after its own delivery, and its **final** seen reading and its trunk reading at quiescence after the last message. Defining every reading at quiescence is what makes it a property of the implementation rather than of when an adapter happened to look.

**The decision procedure.** Each message's readings are determined by the first of these steps that applies. Each step cites the clause it rests on, and the generator records which step decided each message. The procedure keeps two kinds of failure apart. An intrinsic failure is a property of the message's own bytes, and nothing can cure it. A failure relative to the trunk, such as a prior digest that does not name the event on the trunk, can be cured, because later events or a supersession that changes the trunk can make the same message acceptable. Steps 2 and 3 judge a message against state, and they apply only when the validator holds that state. Until it does, the message falls through to step 4, and it is judged again at each later quiescence.

1. **Intrinsic failure.** The encoding does not parse, the SAID does not match the content, the fields violate the event's schema, or an inception's `d` and `i` differ where they must be equal (lines 1737 and 1381). The message is not seen. The specification requires these checks but does not say that a failing message is dropped, so only not-seen is graded.
2. **No verifiable controller signature.** The message carries no controller signature, or the validator holds the key state needed to verify it and none of its controller signatures verifies. The message is not seen and is **rejected**: a validator "MUST drop that message (i.e., not escrow or otherwise accept it)" (line 1266). This step comes before any conflict check, so a conflicting event carrying a forged signature is rejected, never treated as evidence of duplicity.
3. **Forbidden by state the validator holds.** The validator holds state of the identifier, or of its delegator, that forbids the event. That covers a non-establishment event in an establishment-only KEL (line 377), a delegated event whose delegator has the do-not-delegate trait (line 379), and any event after a non-transferable inception or an abandoning rotation (line 340). The message is not seen. In the first two cases it is also rejected, because their sentences say drop. The third says only that "no more key events MUST be allowed", so only not-seen is graded. When the state that would forbid the event is not yet held, as with a delegated inception that arrives before its delegator's KEL, this step does not yet apply.
4. **Not yet acceptable.** The message is sound in itself but cannot be accepted against what the validator has seen. Its signatures may not satisfy the signing or witness threshold (lines 1258–1264). Its prior event may not have been seen, or its prior digest may not name the event on the trunk (line 1737). A rotation's keys may not satisfy the pre-rotation commitment of the latest establishment event on the trunk (line 1494). Or the delegating seal may not have been seen (line 1612). The message is not seen. Whether the validator keeps it as **pending** is graded only for a signature or witness threshold shortfall, which "SHOULD escrow the event" (line 1266). That sentence is the specification's only escrow obligation.
5. **Conflict on the trunk.** A different event already lies on the trunk at the message's location. If the message is a rotation that rule A or B permits to supersede that event (lines 1806–1819, applied up a chain of delegators by rule C), the message is seen and on the trunk, and the displaced event and every event after it stay seen and leave the trunk. Otherwise the message is not seen. For a rotation that is a MUST, and the rotation is also rejected, since "the superseding rotation MUST be discarded" (line 1823). For any other event, such as a second interaction ("An interaction event may not supersede any event", line 1810) or a second inception, no keyworded sentence applies, so not-seen is graded SHOULD, inferred from rule A2 and from line 1799, which says such an event "cannot be first seen at all". The conflict is with the trunk, not with every seen event. After a recovery, a new event at a location held only by a superseded event extends the trunk and conflicts with nothing.
6. Otherwise the message is seen. A key event is then also on the trunk; a receipt or other non-key-event message is never on the trunk, as the Receipts section below says. A message identical to one already seen changes nothing.

**What is graded at which level.**

- **Not seen**, where a clause forbids acceptance, is a MUST. That covers every outcome of steps 1 to 5 except a conflicting event that is not a rotation, which is a SHOULD as step 5 says.
- **Rejected**, where a clause says drop, is a MUST, graded at the reading at which the clause applied when the message was delivered. A message that was kept and only later became subject to a drop rule — a delegated inception escrowed before its delegator's do-not-delegate trait was seen — is graded only as not seen, because the specification gives the re-evaluation of escrowed events no level.
- **Pending** is a SHOULD, for a signature or witness threshold shortfall only (line 1266).
- **Seen and on the trunk**, for a message the procedure accepts, is a SHOULD, inferred: this is liveness. So is accepting a rotation that rule A or B permits to supersede, with the events it displaces still seen and off the trunk. An event under its threshold that is finally seen once the missing signatures arrive, on a later copy or in a receipt, rests directly on line 1266 at SHOULD.
- **Escrow with no text** — keeping an out-of-order event, a delegated event awaiting its seal, or a receipt that arrives before its event (line 1286, "can escrow") until it can be used — is graded only in a named non-normative profile, at `INTEROP`. The safety half of such a case, that the early message is not seen on arrival, is still a MUST.
- **Duplicitous** is informative from a validator's perspective. The only sentence about keeping conflicting events (line 51) concerns watchers.

A MUST assertion is never gated behind a feature an adapter can decline. A case that checks that a superseding rotation is refused does not require `kel.recovery`, and a case that checks that an early event is not seen on arrival does not require `keri.escrow`; the liveness assertions that need those behaviours go in separate cases that do. Otherwise an adapter could decline a feature and skip a safety case.

**Key state.** A case asserts the final key state of each identifier involved: its sequence number, the SAID of its latest event on the trunk, its current signing keys and threshold, its next key digests and threshold, its witnesses and witness threshold, and its delegator if it has one. Those are the facts a relying party acts on. Every key-state assertion is conditional. It names one message, and says that if that message was finally seen, the identifier's key state is exactly this; if it was not, the assertion does not apply and is reported as `not-applicable`, neither a pass nor a failure. The assertion keeps the level of the clause that fixes the state's content, not the level of the acceptance it is conditioned on. After a rotation that breaks its pre-rotation commitment, for example, the assertion "if the inception was seen, the keys are still the inception's keys" is a MUST under lines 1262 and 1494, so an implementation that refuses the rotation but applies it to its state fails a MUST. Thresholds are compared after normalization by the runner, so that `"1"` and `"0x1"`, or a single weighted clause written with and without its enclosing list, compare equal; adapters report thresholds as their implementation holds them.

**Receipts.** A receipt is not a key event (line 1286), so it is never on the trunk. Its seen reading, whether the validator attached its signatures to its copy of the event (line 1782), is reported but graded only where a clause grades it. Cases grade a receipt by its effect on the event it receipts (lines 1264, 1266 and 1782). One sentence conflicts with that. Line 1266 says a validator MUST drop "a key event or non-key-event message that does not have attached at least one verifiable Controller signature". A receipt is a non-key-event message that carries witness signatures, not controller signatures, so read literally the sentence requires every witness receipt to be dropped, contradicting the same paragraph's completion of a threshold "to a receipt of that event" and lines 1286 and 1782. The suite applies the drop rule to key events only, records the conflict in `spec_conflicts` on every assertion that relies on a receipt, and raises it with the working group.

A message's report can also carry a reason, such as an unmet signing threshold or a broken pre-rotation commitment, and keripy's finer escrow categories (out-of-order, partially signed, partially witnessed, awaiting delegation). These are reported when an adapter supplies them and never decide a case.

**Emitting events.** The KERI layer also has an emitting operation: given raw key seeds and event parameters, produce the signed event. The assertions are that the event body is byte-for-byte what the specification's serialization rules determine, which includes its SAID; that every signature verifies against the stated keys; and that the attachments, once parsed, carry the same signatures with the same indexes. The framing of attachments is not asserted byte-for-byte, because the specification allows more than one valid way to group them. Cases supply raw private key seeds rather than salts, because salt-to-key derivation is a keripy convention and not part of the specification. Any timestamp an event carries is a fixed input.

Escrow timeouts are out of scope. Adapters drive each case synchronously, and no case depends on elapsed time.

### ACDC

An ACDC case gives a bundle and an evaluation point, and asserts a verdict. The bundle is the issuer's KEL, the registry's TEL, the credential, and any chained credentials with their own KELs and TELs. The evaluation point fixes which TEL and KEL events count as having happened, so a regenerated case never depends on the clock.

The verdict is one of `valid`, `revoked` (the credential was valid when issued and has since been revoked), `invalid` (something in it does not verify), or `incomplete` (a dependency it needs is missing from the bundle). Like KERI dispositions, these are graded at the level of the clause that defines each distinction, and a refinement the spec does not define is informative.

Disclosure forms are tested as construction properties. The SAID of a credential's compact form must equal the SAID of its expanded form; a selectively disclosed attribute must verify against its blinded commitment; a partially disclosed chain must still verify through its edges. Chain-link confidentiality and contractually protected disclosure have a protocol half, which IPEX would test, and a legal half — whether the terms bind anyone — which no test can check.

### IPEX

The IPEX exchange messages (apply, offer, agree, grant, admit, spurn) are specified, but the rules for which message may validly follow which, and for when a message starts a new exchange rather than continuing one, are not yet stated normatively. Until they are, the suite tests only what is specified: that each exchange message is well-formed, carries a verifiable signature, and refers correctly to the credentials and prior messages it names. Transcript cases that classify each message as a valid or invalid next step will be added when a normative transition rule exists to cite, and until then belong to a non-normative profile. Writing them now would make the suite the specification of IPEX's state machine, which is the working group's decision to make.

### Roles

What a role must believe is tested through ordinary KERI cases taken from that role's perspective: witness thresholds and receipt validity under KAWA (KERI's Algorithm for Witness Agreement, defined in the KERI specification); duplicity detection and first-seen behaviour for a watcher given divergent KELs from different sources. How a role behaves as a running service depends on a transport the specifications do not define, so tests of that kind — a witness serving receipts over keripy's HTTP interface, for example — belong in a non-normative profile.

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

A scenario is a small declarative file, under `scenarios/<layer>/`, that describes cases without their bytes: which identifiers exist, which keys they use, which events are built and in what order they are delivered, what tampering is applied, and which decision-procedure step each message is expected to reach. A generator turns scenarios into cases. The CESR and KERI generators build bytes from the specification itself: the CESR one from its code tables, the KERI one from its field rules with its own Ed25519 and BLAKE3, each checked against published test vectors. keripy is a cross-check rather than the source (`generators/keripy_keri_check`): it rebuilds every untampered KERI body byte for byte, verifies every signature, and replays each case, and a disagreement is recorded in `generators/DISAGREEMENTS.md` without changing an expected value.

A generator does not take keripy's word for a disposition. It computes each disposition from the decision procedure and the scenario, uses keripy to produce the bytes and to cross-check, and records any disagreement between keripy and the procedure as a candidate dispute for a maintainer to review. That matters because keripy's behaviour does not always match the procedure, and when it does not, the difference is exactly what the suite exists to surface.

Generators must be deterministic. Keys come from fixed seeds, timestamps are fixed, and a generator records its own version and the commit of whatever it drove. CI regenerates every case from its scenario and fails on any difference.

## Targets and profiles

Cases identify what their inputs are by the protocol versions that appear on the wire, not by implementation release numbers, which are ambiguous — keripy's 2.x release line implements version 1.0 of most of the specifications, and the wire format it emits by default carries version 2.00 codes.

A **profile**, under `profiles/`, is a named set of cases that an implementation can claim: "passes every active MUST assertion in profile P", stated together with its SHOULD results. A profile's status comes from the maturity of the text its assertions cite, not from the wire version of its inputs. The specifications at version 1.0 define the 2.00 code tables and require 2.XX implementations to accept 1.XX version strings, so cases built on those clauses are normative and active, including the count-code cases that motivated the suite. Where expected values come from an implementation whose behaviour is still moving — keripy's main branch, for example, ahead of a release — the case is `draft`, pinned to the commit it was generated from, and its results are advisory until it is regenerated against a release.

Some behaviour that many deployments depend on has no normative text: the CESR 1.00 count-code table used by keripy 1.x, for example. The suite tests it anyway, in a profile named for what it is — interoperability with keripy 1.x — so that nobody mistakes passing it for conformance.

## Versioning

Three things are versioned, and every conformance report states all three.

**The suite** uses semantic versioning. Adding cases is a minor release. Deprecating cases, or changing the adapter protocol incompatibly, is a major release. Changes to documentation and metadata are patches. Because assertions never change in place, a minor release can only add cases; it can make an implementation that previously passed everything fail a new case, but it cannot turn an old pass into a failure.

**The adapter protocol** has its own version, declared in the handshake. The runner accepts the current protocol version and the one before it, so adapters maintained outside this repository have a full major cycle to catch up.

**An adapter** follows its implementation's release line, because that is what its users will pin, and reports the exact implementation commit it was built against.

A conformance claim is therefore a tuple: suite version, profile, adapter version, implementation commit, the list of behaviours the adapter composes, if any, and the number of active SHOULD assertions that passed and that failed. A claim never states the MUST verdict alone. In the KERI layer, where accepting a valid event is a SHOULD, a validator that accepts nothing passes every MUST assertion, and only its SHOULD failures tell it apart from a working one. The runner's report and its printed summary carry those counts, and say so explicitly when any SHOULD assertion failed.

## The runner

The runner, `kcs`, is a Python package (Python 3.12 or later, managed with uv) with **no runtime dependencies**. That is deliberate. It must install wherever an adapter author works, whatever language their implementation is in, and it must never pull in an implementation under test, which is what would happen if it depended on keripy or on a CESR library. Generators, which do drive keripy, run in their own pinned environments and are not part of the runner.

The runner treats every adapter as untrusted code, because adapters run implementation code against hostile inputs and a parser bug can be exploitable. It bounds each response's size and each request's time, reads responses line by line with a size cap rather than buffering until a newline that may never come, and kills the adapter's whole process group on a violation. It also caps the adapter's memory and CPU time with resource limits, starts it with a scrubbed environment so it inherits no credentials, and refuses to run as root. The runner supports POSIX systems only, because its containment depends on POSIX process controls, and it refuses to start elsewhere. Network isolation is not something it can impose itself; CI provides it by running adapters, and above all the nightly runs against development heads, in jobs that hold no secrets and no write token.

### Checking an adapter

An adapter is a contract that people outside this repository implement, in several languages, so they need a way to check their adapter before they ever run a case. The suite provides two:

- **Message schemas.** `schema/adapter-protocol.schema.json` describes every request and response in JSON Schema, so an adapter author can validate their own messages in their own test suite, in any language.
- **`kcs check-adapter`.** This runs a fixed set of probes against an adapter and reports each one: the handshake is well-formed and its features are in the vocabulary; responses echo request ids; a malformed request gets an error response rather than a crash; and two invariants the adapter protocol requires and the runner otherwise cannot see. **Statelessness:** the probe creates an identifier in one request and, in the next, delivers an event for that identifier that a fresh validator must not accept; an adapter that leaks state between requests accepts it. **Quiescence:** the probe delivers a sequence in which a later message's disposition depends on whether an escrowed event was promoted first, so an adapter that does not drain escrow after each message reports the wrong disposition.

The runner also runs the statelessness probe at the start of every session, and can run a profile's cases in a shuffled order and compare the results with the ordered run, which catches state leaking between real cases.

## Adapters

An adapter is a small standalone program that connects one implementation to the runner. Adapters build against a released or pinned version of their implementation and use only its public API. They never patch the implementation. Where it lacks something a case needs, the adapter composes it on top and declares that it has done so. That way an adapter keeps working whether or not the implementation's maintainers ever choose to host it, and its results stay honest about what was tested.

Adapters start in this repository under `adapters/<name>/`, each self-contained so it can be lifted into its implementation's repository unchanged. The keripy adapter stays here permanently, because keripy is also a generator.

## Clause coverage

A list of cases cannot say where the suite is thin, so the suite also measures which normative sentences its cases test. `scripts/clause-coverage` enumerates every sentence of each pinned specification text that carries an uppercase RFC 2119 keyword, maps each assertion's clause and inference quotes onto those sentences, and writes a report per specification under [`coverage/`](coverage/README.md), which that directory's README explains how to read. The report is generated, never edited, and CI fails when it is stale. It counts only the public cases in this repository, so it reveals nothing about an embargoed one.

Beside each clause registry, `scenarios/<layer>/triage.json` records a hand-kept judgment of each sentence: whether a validator can be tested on it through an adapter, whether it binds a role no adapter plays and is out of scope, or whether no case could test it and why, and whether it has a security consequence. A sentence with no judgment is reported as unassessed rather than guessed. A judgment that no longer identifies exactly one sentence of its pinned text is refused (a sentence repeated in the text is identified by its section and, if needed, its occurrence within that section), so re-pinning a specification forces the triage to be revisited. The report measures which sentences are cited, not how well; that judgment belongs in a dated assessment that cites the report, written by hand beside it. The first is [`coverage/assessment-2026-10.md`](coverage/assessment-2026-10.md).

## Continuous integration

CI runs at three levels:

Only the first level exists so far; the other two arrive with the first adapters.

1. **On every pull request, cheaply:** the runner's own tests, validation of every case against the case schema, and regeneration of every case and of the clause coverage report, each with a byte-for-byte comparison.
2. **On every pull request, more slowly:** each adapter is built against its pinned implementation and run against the suite, and its results are compared with a baseline committed for that adapter. A regression fails the pull request. An improvement asks for the baseline to be updated in the same pull request.
3. **Nightly, advisory:** each adapter is built against its implementation's latest development head and run, and the conformance reports are kept as artifacts. Accumulated, those records are the compatibility matrix; nobody maintains one by hand.

## Security

A case that a released implementation handles unsafely is, in effect, a public proof of concept against that implementation. "Unsafely" means handling a hostile input in a way with a security consequence — accepting what should be rejected, retaining what should be dropped, letting one input disturb the processing of others, or crashing or hanging — whatever the level of the assertion it fails. The consequence decides, not the grade: an inferred SHOULD can still describe a real attack. That includes keripy.

Such a case is embargoed. It is held outside the public tree, in a private repository that mirrors the public one and adds the embargoed cases, until the affected project has been told privately and has had up to 90 days to ship a fix, as [`SECURITY.md`](../SECURITY.md) describes. The embargo takes precedence over every other rule here, including the rule that a case keripy contradicts is published as disputed. While a case is embargoed, nothing derived from it is published either: not its scenario, not baseline changes it would cause, and not nightly results that include it. CI runs embargoed cases only in the private repository. Case ids are allocated in the private mirror, from the same sequence as every other case, so an embargoed case keeps its id when it is published; until then the public tree simply has a gap in its numbering. Gaps are normal and carry no meaning.

The runner executes adapter programs, and adapters execute implementation code. The runner treats an adapter's output as untrusted: it bounds the size of every response, validates its shape before reading it, and enforces a time limit on every request.

## Terms

- **Case.** A fixed input and a set of assertions about it, in one file under `cases/`. Its id is permanent.
- **Assertion.** One checkable claim about what an implementation must report for a case, with the clause it rests on and that clause's requirement level. Its outcome is pass, fail, or not-applicable when it is conditional and its condition does not hold.
- **Adapter.** A small standalone program that connects one implementation to the runner over the adapter protocol. Beyond translating requests, it owes two invariants — a fresh state for every request, and quiescence after every delivered message — and it must declare any behaviour it supplies itself rather than delegating to the implementation.
- **Profile.** A named set of cases that an implementation can claim to pass, such as "passes every active MUST assertion in profile P", stated together with its SHOULD results. A profile's status comes from the maturity of the specification text its assertions cite. A non-normative profile reports interoperability with a named implementation and is never a conformance claim.
- **Conformance report.** The machine-readable output of a run: suite version, profile, adapter and implementation identity, composed behaviours, and the outcome of every assertion.
- **Disputed.** The status of a case whose expected values an implementation's behaviour contradicts, where the clause appears to say otherwise. A disputed case is excluded from conformance results until the specification working group settles it. Conflicts inside the specification's own text do not make a case disputed; they are recorded in `spec_conflicts`.
- **Seen.** Of a KERI message: accepted into the validator's copy of the KEL. The specification calls this first seen and makes it permanent.
- **Trunk.** The undisputed path through a KEL. A superseded event is seen and off the trunk.
- **Self-agreement.** A pass where keripy both produced the expected value and is the implementation under test. It shows only that keripy agrees with itself, and the conformance report marks it so.
- **Embargoed.** The status of a case that would disclose an unfixed security defect in a released implementation; it is held in a private mirror until the affected project has had a chance to ship a fix.
