# Self-assessment: case adequacy and the results matrix

This is a dated assessment of how well the suite's public cases test their specifications and what its published results can show, written on 2026-10-16 at suite commit `45a368a`. It replaces [the assessment of 2026-10-09](assessment-2026-10.md) as the current one; that file stays as the record of where the suite stood a week earlier, and its list of missing cases is the one the cases added since were written against. This one reads the generated clause coverage report in [README.md](README.md), [cesr.md](cesr.md), [keri.md](keri.md) and [acdc.md](acdc.md), and the committed results the site publishes, and adds the judgment the report leaves out: whether the cases that cite a sentence probe it at its edges, why cells of the matrix are still empty, and which missing cases matter most. Line numbers are those of the pinned texts, CESR v1.0 at commit `0371296`, KERI v1.0.1 at commit `71cb54e` and ACDC v1.0 at commit `4a543c5`. It will go stale as cases are added; the report will not, because CI regenerates it.

## What the suite holds

There are 59 CESR cases, of which 53 are active, 4 draft and 2 disputed; 160 KERI cases, of which 151 are active and 9 disputed; and 76 ACDC cases, all draft. A week ago there were 52 CESR and 60 KERI cases. Of the KERI cases, 16 are exchange-message cases run through `exn.verify` and 34 carry KERI 1.x bodies in the non-normative `keripy-1x-interop` profile; the rest are key-event cases in `keri-v1.0.1` and `keri-escrow`. The CESR and KERI cases added since the first assessment were issued as drafts and promoted to active on 2026-10-16 by a maintainer who had read them, except those named under the gaps below (`docs/design.md`, Cases).

Eight builds of seven implementations are run against those cases: keripy main and keripy 1.2.14, keriox, the Affinidi KERI core, devrandom-labs/cesr, keri-go, cesrixir and signify-ts. Their results are run by the suite's maintainer from a recorded suite commit and committed under `results/` labelled `maintainer-run`, and CI never runs an adapter (`docs/publishing-results.md`).

## What the report measures, and what it does not

The report lists every sentence of each pinned text that carries an uppercase RFC 2119 keyword and the public cases whose assertions cite it, and counts a sentence as covered only when an active case cites it. Of 88 CESR obligations, 70 are testable by a validator and 14 are covered, against 12 a week ago. Of 244 KERI obligations, 159 are testable by a validator and 28 are covered, against 17. The security-bearing obligations covered rose from 4 to 5 of 11 in CESR and from 16 to 20 of 79 in KERI. ACDC has 242 obligations, 193 of them testable by a validator, and none is covered, because every ACDC case is still a draft.

The coverage numbers moved less than the case counts did, and that is expected rather than disappointing. Most of the new KERI cases press on sentences that were already covered, such as the signing thresholds at line 1258 and the drop rule at line 1266, from sides no earlier case reached. A sentence cited by one positive case still counts exactly as much as one cited by twenty that probe each boundary, so depth is invisible to the report. The 34 KERI 1.x cases add no coverage at all, by design: they are interop cases, and a basis that quotes a normative sentence never covers it.

The caveats of the first assessment still hold. Most of CESR's normative content is in its code tables, which carry no keywords, so sentence coverage understates CESR. In KERI a few sentences carry most of the safety load, so a count that treats a field-order rule and the pre-rotation check as equal overstates how thin the suite is where it matters.

One limit of the adapter protocol that the first assessment named is gone and one remains. `cesr.encode` can now answer with a refusal, in the same form as a parse rejection, and `cesr.parse` can answer an accepted stream with a summary instead of item extents, so a rejection case reaches an adapter whose library cannot report extents. `keri.process` still reports dispositions for key events and receipts only, so the routed messages (`qry`, `rpy`, `pro`, `bar`, `xip`) remain triaged out of scope until an operation reports them; `exn` alone is reachable, through `exn.verify`.

## What the results matrix shows

Every build has a result for every profile it can take part in. The empty and partial cells that remain have four causes, and none of them is a missing run.

The first is that an adapter offers no operation a profile uses. Only keripy main's adapter offers `acdc.verify`, so `acdc-v1.0` is not applicable for every other build. keripy main's cell is no-evidence: no ACDC case is active, and the adapter declares no `acdc.*` feature in any case, because keripy main has no entry point that judges an ACDC 2.00 against a bundle (`adapters/keripy/README.md`, acdc.verify). cesrixir, signify-ts and keripy 1.2.14 offer only the CESR operations, so the KERI profiles are not applicable to them. signify-ts is an edge client that validates no KEL, and that cell will stay empty.

The second is the wire. keriox, the Affinidi core, devrandom-labs/cesr, keri-go and keripy 1.2.14 speak KERI 1.x bodies over CESR 1.00 attachments, and every normative CESR and KERI case uses the 2.00 count-code table and 2.x bodies. Their normative cells are therefore no-evidence: no case they can run exists, rather than cases they fail. The `keripy-1x-interop` profile is where these implementations now have evidence about their KELs, since the 34 KERI 1.x cases mirror normative scenarios on the wire they speak. A pass there is an interoperability result with keripy 1.x, never a conformance claim, and those normative cells will stay no-evidence until the working group defines the 1.x field sets and the CESR 1.00 table (gap 7 below).

The third is undeclared features. keripy main's `keri-v1.0.1` cell is conformant with two active cases not supported, the positive digest-agility cases KERI-0117 and KERI-0119, because it declares neither `crypto.sha2-256` nor `crypto.blake2b-256`. signify-ts declines the binary domain, so 8 of its `cesr-v1.0` cases are not supported. In `keripy-1x-interop` the 1.x KEL implementations each decline some of escrow, item extents, witnesses, delegation, partial rotation, recovery and non-transferable inception, and the CESR-only builds decline every KEL case.

The fourth is the verdicts themselves. Several cells are not-conformant or not-interoperable because an implementation fails cases, which is what the matrix exists to show; each result's page says which cases and which assertions.

## Where the suite is strong

Count-code framing in CESR remains the deepest area, with the size rules in both domains (line 591), nested and large groups, a genus override inside and outside its group, and truncation and early-end negatives. Genus override negatives (line 816) and the text-domain pad character (line 93) now have must-reject cases.

The KERI signing threshold is now tested from nearly every side the first assessment asked for. A rotated-out key signing the next event (KERI-0084), a rotation signed by the current key instead of the exposed next keys (KERI-0085 to KERI-0087), signatures indexed past the end of the key or witness list (KERI-0088, KERI-0089), and signatures made over another event's bytes (KERI-0100 to KERI-0102) are all refused at MUST. The dual threshold on rotation has cases that meet the prior next threshold but not the rotation's own and the reverse, a rotation signed only by a newly added key, a weighted next threshold met and missed, and the specification's reserve and custodial rotation examples replayed with each of their failures (KERI-0127 to KERI-0139). Weighted arithmetic is tested where binary floating point goes wrong: three weights of 1/3 and ten of 1/10, each summing to exactly one (KERI-0140 to KERI-0142).

Delegation now has a seal anchored in the wrong delegator's KEL (KERI-0090), and receipts and witness lists have structural negatives: a receipt whose SAID is not the event its signatures cover, a backer threshold larger than the witness list, and a witness listed twice (KERI-0103 to KERI-0107). Field structure has cases for extra, missing and reordered top-level fields, an unknown message type, a nonzero inception sequence number, a sequence number above the maximum and an empty key list (KERI-0109 to KERI-0116).

Digest agility is the first area to break the single-algorithm monoculture: KELs whose every digest is SHA2-256 or Blake2b-256, and SAIDs whose code names one algorithm while their value was computed with another (KERI-0117 to KERI-0122). The mismatched-code cases need no feature, so every KERI 2.x validator runs them.

The grading is as careful as before. Key-state assertions stay conditional on the message they follow from, safety halves of escrow and recovery scenarios are split into ungated companions, and every normative expected value comes from the specification's rules through the suite's own model. keripy is a cross-check there and never the authority. Where it disagrees, the case is disputed rather than changed, and `generators/DISAGREEMENTS.md` records why.

## Where the suite is thin

ACDC is the largest hole. 76 cases exist and none is active, because no implementation has evaluated them yet, and the batch was issued draft for that reason (`docs/design.md`, ACDC). Until an adapter on the main branch declares `acdc.version-2.x`, the ACDC column of the matrix says nothing about anyone.

The positive cases still share one serialization and one signature suite. Every case uses JSON bodies and Ed25519 signatures. CBOR and MessagePack, native CESR bodies, and signature schemes other than Ed25519 have no evidence. Digests other than Blake3 now have positive cases, but no adapter declares either feature, so they have produced no evidence yet.

Legacy 1.x KELs have evidence only in the non-normative profile. That was a deliberate choice, recorded in `this.i`: the specification defines neither the 1.x field sets nor the CESR 1.00 table, so the cases take keripy 1.2.14's field sets and say they are interop. It means five of the eight builds have no conformance verdict for their KELs.

Several cases are written but cover nothing because they are disputed or held. The four configuration-trait cases (KERI-0123 to KERI-0126) and the transferable-witness case (KERI-0108) are disputed, because keripy main disagrees and the text has not been ruled on. The four variable-size primitive cases (CESR-0058 to CESR-0061) remain draft, because they put a generic list inside an attachments group and the text neither allows nor forbids it.

Two known weaknesses in individual cases are recorded as ticks rather than fixed. The case for a rotation after a non-transferable inception (KERI-0024, and its 1.x mirror KERI-0161) requires partial rotation needlessly, and its rotation is malformed in a way a validator can refuse on body shape without enforcing the rule. The ungated companions of the escrow cases cannot grade the completing copy, because its disposition depends on whether the first copy was kept, and the case language has no conditional assertion for that.

## The most consequential missing cases

These are ranked by what an implementation that gets the requirement wrong would expose, safety first and then interoperability. Each names the clause and a case that would test it. None describes a known defect in any implementation; each is a requirement no active case tests yet.

Of the nineteen items in the 2026-10-09 assessment, items 1 to 5, 8, 10, 14 and 16 are now covered by active cases, and items 9, 13 and 17 partly so. Items 7 and 15 have cases written that cover nothing yet, as described above. Items 6, 9's remaining variants, 11's normative form, 12 and 19 were left out pending a ruling or a decision, and item 18 is still open. What remains, renumbered:

1. A plain rotation on a delegated KEL. KERI line 1612, read as requiring a seal for every establishment event of a delegated identifier, which is an interpretation the working group has not confirmed. A `rot` rather than a `drt` after a delegated inception, with no seal; expect not seen. Old item 6; held for a ruling.
2. Inception-only configuration traits in a rotation. KERI lines 367 to 373. The cases exist (KERI-0123 to KERI-0126) and are disputed; a ruling either way would let them cover line 367 or be deprecated. Old item 7.
3. The remaining weighted-threshold variants. KERI lines 1419 and 1421. A weight list longer or shorter than the key list, and a numeric threshold above the number of keys; the text does not say whether either is malformed or merely unsatisfiable. Old item 9; held for a ruling.
4. A transferable witness. KERI lines 353 and 1252 bind the producer, and keripy accepts such an inception; the case (KERI-0108) is disputed until the validator's rule is stated. Old item 13, in part.
5. Positive digest-agility evidence. The cases exist (KERI-0117, KERI-0119); what is missing is an adapter that declares `crypto.sha2-256` or `crypto.blake2b-256`. This is adapter work, not case work, and it is listed here because until it happens digest agility is tested only from the refusing side.
6. Transferable receipts and witness receipt couples. KERI line 1782, which requires a validator to verify the signatures attached to a receipt and which no active case covers. Every receipt case uses witness-indexed signatures, so no case exercises a receipt from a transferable identifier or a non-transferable receipt couple.
7. Legacy 1.x KELs as conformance cases. KERI line 273 and CESR line 1158. Needs the working group to define the 1.x field sets and the CESR 1.00 count-code table; until then the interop profile is the only home. Old item 11.
8. CBOR and MessagePack. CESR line 388. Frame a CBOR and a MessagePack inception at the CESR layer, then process one KEL in each at the KERI layer. cesrixir declares both serializations, so a case would now reach an implementation. Old item 12.
9. Variable-size primitives. CESR's variable raw-size table, which carries no keyword sentence. The draft cases need either a ruling that an attachments group may carry a generic list or a move to a container every parser reads. Old item 15.
10. A JSON body nested in a group. CESR line 376. A group that encloses a correctly wrapped JSON body, and one that encloses it bare; expect the first parsed and the second rejected. Old item 18, unchanged.
11. An encoder that must refuse. The protocol now carries a refusal from `cesr.encode`, and no case asks for one: a raw value whose length does not fit its code should be refused.
12. Native CESR KERI bodies. KERI lines 2077 and 2079, with the native body annex. One case per 2.0 native event type. Old item 19; held for a decision.
13. Signature schemes other than Ed25519. The feature vocabulary already names Ed448, secp256k1 and secp256r1; no case uses them.
14. ACDC promotion. Not a missing case but a missing step: the 76 ACDC drafts need an implementation's evaluation before they can be read and promoted, and until then ACDC's 69 security-bearing obligations are all uncovered.

## A security lens

The three tiers of the first assessment still decide where a case belongs, and the October cases moved most of the first tier into the suite.

The first tier is security properties the specifications state as MUST: pre-rotation, the signing and witness thresholds, delegation seals, configuration traits and digest verification. Of the first assessment's items in this tier, only the plain rotation on a delegated KEL, the configuration traits and two weighted-threshold variants remain, and each waits on a ruling rather than on work. A failure here means an implementation can be made to accept an event its controller did not authorize.

The second tier is hostile input. Where the specification makes an input invalid, the case is a normative must-reject, and the field-structure and text-alphabet cases added in October are of this kind. Where it does not, the case belongs in a labelled non-normative hardening profile; a signed JSON body that repeats a field label is still the clearest example, and no hardening profile exists yet. How a case that exposes unsafe handling in a released implementation is disclosed is governed by `docs/design.md` (Security), not by this assessment.

The third tier is network and service behaviour: witness and watcher operation, OOBI resolution, and anything that depends on a transport the specifications do not define. These remain out of scope for conformance cases until an adapter operation can observe them.
