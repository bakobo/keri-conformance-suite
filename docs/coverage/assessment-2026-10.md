# CESR and KERI case adequacy, October 2026

This is a dated assessment of how well the suite's public CESR and KERI cases test their specifications, written on 2026-10-09 against 52 CESR cases and 60 KERI cases. It reads the generated clause coverage report in [README.md](README.md), [cesr.md](cesr.md) and [keri.md](keri.md), and adds the judgment that the report deliberately leaves out: whether the cases that cite a sentence probe it at its edges, and which missing cases matter most. Line numbers are those of the pinned texts, CESR v1.0 at commit `0371296` and KERI v1.0.1 at commit `71cb54e`. It will go stale as cases are added; the report will not, because CI regenerates it.

## What the report measures, and what it does not

The report lists every sentence of each pinned text that carries an uppercase RFC 2119 keyword and the public cases whose assertions cite it. Every obligation in both texts now carries a triage judgment, so the summary separates sentences a validator could be tested on from those that bind a role no adapter plays and those no case could test. Of 88 CESR obligations, 70 are testable by a validator and 12 are covered by an active case. Of 244 KERI obligations, 146 are testable by a validator and 17 are covered. Of the obligations triaged as security-bearing, 4 of 11 are covered in CESR and 16 of 77 in KERI; the uncovered counts include sentences that bind a controller, witness or delegator, which no case in the current protocol can reach.

Those numbers understate CESR and overstate how thin KERI is, for different reasons. Most of CESR's normative content is in its code tables, which carry no keywords: a table row that fixes a code's length or meaning is as binding as any MUST sentence, but sentence coverage cannot see it. A measure of which table entries the cases exercise is tracked separately. In KERI the opposite holds: a handful of sentences, such as the signing thresholds at line 1258 and the validation rules at lines 1737 and 1780, carry most of the safety load, and the cases concentrate there. A sentence count treats a field-order rule and the pre-rotation check as equal, and they are not.

Coverage also says nothing about depth. A sentence cited by one positive case is counted as covered, exactly like one cited by twenty cases that probe each boundary. That is why this assessment exists. Two KERI quotes match no keyword sentence, because the sentence at line 1799 that says a non-superseding event "cannot be first seen at all" states its rule without a keyword; the report lists them at the end of the KERI part.

Two limits of the adapter protocol bound what any case can show today. `cesr.encode` has no rejection result, so every encoding case is positive by construction and no case can check that an encoder refuses a raw value that does not fit its code. And `keri.process` reports dispositions for key events and receipts only, so the routed messages (`qry`, `rpy`, `pro`, `bar`, `xip`, `exn`) and their field rules are triaged out of scope until an operation reports them.

## Where the suite is strong

Count-code framing in CESR is the suite's deepest area. The founding cases check that a count code's size counts quadlets in the text domain and triplets in the binary domain (line 591), with offsets that make a parser counting items rather than quadlets fail loudly. Nested groups, large codes, a genus override and truncation and early-end negatives sit around them, and the places where the specification's own examples conflict with its rules are recorded as disputes rather than smoothed over.

The indexed signature table is covered at every index and ondex width, including the current-only form.

In KERI, the controller signing threshold is tested from many sides: forged signatures, unsigned events, events under threshold, a threshold completed by a second copy of the event, and a weighted threshold with two clauses. First-seen behaviour and duplicity are tested adversarially: a pending event losing to a later fully signed one, a corrupt copy that must not evict an event already kept, a retrograde interaction, and a disputed branch that must not be extendable after recovery.

The grading itself is careful. Key-state assertions are conditional on the message they follow from, so an implementation that refuses an event but applies it to its state fails a MUST. Safety assertions are kept out of cases that require optional features wherever the generator allows it, so that an adapter cannot skip a safety case by declining a feature.

## Where the suite is thin

The positive cases share one format and one algorithm suite. Every case uses JSON bodies, Ed25519 signatures and Blake3 digests, and every KERI case uses 2.x bodies. So CBOR and MessagePack (which a CESR parser must support, line 388), native CESR bodies, legacy 1.x KELs (which a 2.x implementation must support, CESR line 1158 and KERI line 273), digests other than Blake3, and signature schemes other than Ed25519 have no KERI evidence at all. Most deployed KELs carry 1.x bodies, so this is the largest interoperability gap.

CESR's variable-size primitives have no positive parse case, though ACDC and seals depend on them.

Several KERI areas have only valid inputs, or none: seal shapes, receipt structure, witness list structure, weighted threshold arithmetic beyond two clauses, the specification's own reserve and custodial rotation examples, and every native CESR event body.

A few safety cases depend on a capability feature even though every assertion they make is that something is not accepted. The cases for events after a non-transferable inception require partial rotation whenever a rotation signature uses an index code other than the simplest, and some receipt cases require routing. A validator that lacks the feature passes such a case by refusing anyway, so the gate removes evidence without protecting anyone. The design states this rule for escrow and recovery, and its reasoning covers these features too.

## The most consequential missing cases

These are ranked by what an implementation that gets the requirement wrong would expose, safety first and then interoperability. Each names the clause and a case that would test it. None of them describes a known defect in any implementation; each is a requirement no public case tests yet.

1. A rotated-out key signs the next event. KERI lines 1370, 1737 and 1266. Incept, rotate, then deliver an interaction at the next sequence number signed by the inception key; expect it rejected and the key state still the rotation's.
2. A rotation signed by the current key instead of the exposed next keys. KERI lines 1262 and 1494. Rotate with a new key list signed only by the inception's current key, with variants that do and do not include the pre-rotated key; expect not seen, with the key state still the inception's.
3. A signature index out of range. KERI lines 1258 and 1266. A sole signature at index 5 against a one-key list, and a witness signature indexed past the end of the witness list; expect not seen.
4. A signature over the wrong bytes. KERI line 1266. Attach the inception's valid signature to an interaction from the same controller; expect rejected.
5. A delegating seal in the wrong delegator's KEL. KERI line 1612. A delegated inception naming one delegator, anchored only by an interaction in a different identifier's KEL; expect not seen.
6. A plain rotation on a delegated KEL. KERI line 1612, read as requiring a seal for every establishment event of a delegated identifier, which is an interpretation worth confirming with the working group. A `rot` rather than a `drt` after a delegated inception, with no seal; expect not seen.
7. Inception-only configuration traits in a rotation. KERI lines 367 and 377. A rotation that carries `EO` or `DND`; expect it dropped.
8. The dual threshold on rotation. KERI lines 1262, 1494, 1537, 1543 and 1574. A rotation whose signatures meet the prior next threshold but not the current one, and the reverse; a weighted next threshold; and the specification's reserve and custodial rotation examples replayed as cases.
9. Weighted threshold arithmetic. KERI lines 1419 and 1421. Three weights of 1/3 all signed, whose exact sum is one; a weight list longer or shorter than the key list; a numeric threshold above the number of keys.
10. Digest agility. CESR lines 1186 and 1194, KERI line 1325. An event whose SAID and next-key digests use SHA2-256 or Blake2b, and a SAID whose code names one algorithm while its value was computed with another; expect the first seen and the second not.
11. Legacy 1.x KELs. KERI line 273 and CESR line 1158. A 1.x inception and rotation, parsed and processed. The specification does not define the 1.x field sets, so the expected fields need a decision before the cases are written.
12. CBOR and MessagePack. CESR line 388. Frame a CBOR and a MessagePack inception at the CESR layer, then process one KEL in each at the KERI layer.
13. Receipt and witness list structure. KERI lines 345, 353, 1252 and 1782. A receipt for a different SAID than the event it accompanies; a backer threshold larger than the witness list; a witness listed twice; a transferable witness prefix.
14. Field and value structure. KERI lines 261, 323, 335 and 539, with the per-message field orders at lines 556 to 882. Extra, missing or reordered top-level fields; an inception with a nonzero sequence number; a sequence number above the maximum; an unknown message type; an empty key list.
15. Variable-size primitives. CESR's variable raw-size table, which carries no keyword sentence. Positive parses with zero, one and two lead bytes.
16. Genus override negatives. CESR line 816. A genus/version code as the first element of a group that does not allow override, which must have no override meaning.
17. The text-domain alphabet. CESR line 93. A text-domain primitive containing `+`, `/` or `=`; expect rejected.
18. A JSON body nested in a group. CESR line 376. A group that encloses a correctly wrapped JSON body, and one that encloses it bare; expect the first parsed and the second rejected.
19. Native CESR KERI bodies. KERI lines 2077 and 2079, with the native body annex. One case per 2.0 native event type.

## A security lens

The gaps above sort into three tiers, which decide where a case belongs.

The first tier is security properties the specifications state as MUST: pre-rotation, the signing and witness thresholds, delegation seals, configuration traits, and digest verification. Items 1 to 10 are of this kind. A case for them belongs in the normative profile at MUST, because an implementation that fails it can be made to accept an event its controller did not authorize.

The second tier is hostile input. Where the specification makes an input invalid, such as a text-domain character outside the alphabet, a missing required field, or a value above a stated maximum, the case is a normative must-reject. Where it does not, the case belongs in a labelled non-normative hardening profile rather than in conformance. A signed JSON body that repeats a field label is the clearest example: parsers that keep the first value and parsers that keep the last derive different key states from one signed event, but no keyword sentence forbids the repetition, so a case for it is a hardening verdict and not a conformance one.

The third tier is network and service behaviour: witness and watcher operation, OOBI resolution, and anything that depends on a transport the specifications do not define. These are out of scope for conformance cases, as the triage records, and belong in a profile only once an adapter operation can observe them.
