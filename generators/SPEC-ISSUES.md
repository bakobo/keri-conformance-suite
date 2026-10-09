# CESR specification issues found while building the conformance cases

Against the CESR specification v1.0 (tag `v1.0`, commit `037129608b9e6960858b752019ac273d40d7386c`, file `spec/spec-body.md`; line numbers are that file's). This is the list to take to the specification working group. Each entry gives the lines involved, the text, what the specification should state, and what the suite would do if it did.

The suite's policy (decided 2026-10-01):

- **Inferred consumer obligations.** Where the specification states a MUST about what a stream is but not what a parser does with a stream that breaks it, the case's rejection assertion is graded SHOULD and carries an `inferred_from` record. If the specification states the parser rule, those cases are re-issued at MUST. Expectations are immutable once published, so re-issuing means new case ids, with the SHOULD cases deprecated in their favour.
- **Spec-internal conflicts.** An assertion resting on a sentence with an RFC 2119 keyword keeps that sentence's level and stays active. Conflicting tables, legends or examples are recorded in the assertion's `spec_conflicts` and do not make the case disputed. A correction to the conflicting text changes no case.

## Inferred consumer obligations (cases graded SHOULD)

### I1. A count that does not match its group (line 591)

- **Text.** "Count Code tables", line 591: "The size component MUST count the Quadlets/triplets in its following group."
- **Gap.** This binds the producer. Nothing says what a parser does when a group's size ends it inside an element, or runs past the end of the input.
- **The specification should state** that a parser MUST reject a stream in which a count code's group ends inside an element, and MUST reject a group whose size runs past the end of a framed input. It should also say what "the end of the input" means for a framed input as opposed to a live stream. The suite currently supplies that rule itself, as a harness rule in `docs/adapter-protocol.md` ("End of input").
- **Re-issued at MUST if stated:** CESR-0032 (stream ends inside a signature), CESR-0033 (group ends inside a signature).

### I2. A stream that ends inside a small count code (line 599)

- **Text.** "Small Count Code table", line 599: "Codes in the small Count Code table MUST be each four characters long."
- **Gap.** This states the code's length, not what a parser does with three characters of one at the end of the input.
- **The specification should state** that a parser MUST reject a count code cut short by the end of a framed input (see I1 on end of input).
- **Re-issued at MUST if stated:** CESR-0034.

### I3. A stream that ends inside a large count code (line 605)

- **Text.** "Large Count Code table", line 605: "Codes in the large Count Code table MUST be each 8 characters long."
- **Gap and correction.** The same as I2, for the eight-character codes.
- **Re-issued at MUST if stated:** CESR-0035.

### I4. A count code whose second character is a numeral (line 601)

- **Text.** "Small Count Code table", line 601: "If the second character is not a letter but is a numeral `0` - `9` or `-` or `_`, then it MUST be either a selector for a different Count Code table or an error."
- **Gap.** The clause calls such a code "an error" but not what a parser does with it. Genus 2.00 defines no table for the numerals, so `-0AB` is an error, yet a parser that skips it is not told it is wrong.
- **The specification should state** that a parser MUST reject a count code whose selector names no table defined for the genus in force.
- **Re-issued at MUST if stated:** CESR-0037.

### I5. Nonzero pad bits or lead bytes (line 234)

- **Text.** "Code characters and lead bytes", line 234: "Therefore all CESR primitives MUST employ [[ref: mid-padding]] as defined." The pad and lead bytes are defined as zero ("pre-pad leading bytes of zeros").
- **Gap.** This defines a well-formed primitive. Nothing says a parser must reject one whose pad bits or lead bytes are not zero, and a lenient parser that masks them returns the same raw value. The stronger reason to require rejection is canonicality: if nonzero padding is accepted, one value has several encodings, and a native CESR body could carry more than one SAID.
- **The specification should state** that a parser MUST reject a primitive or indexed signature whose pad bits or lead bytes are not all zero.
- **Re-issued at MUST if stated:** CESR-0038 (indexed signature, text domain), CESR-0039 (primitive, text domain), CESR-0040 (indexed signature, binary domain).

### I6. A stream that resumes with something other than a frame (line 440)

- **Text.** "Stream parsing rules", line 440: "The Stream MUST resume with a frame starting byte that begins with one of the 8 Tritets, either another Count Code expressed in the ‘T’ or ‘B’ domain or a new JSON, CBOR, or MGPK encoded mapping or a new annotated encoding."
- **Gap.** This binds what a stream contains. Nothing says what a parser does when the next frame starts with a bare primitive. The case's `D` has tritet 0b010, which the start table assigns to a text op code (`_`), and `D` is no op code. The specification also does not define annotated text beyond saying it starts with LF, CR or tab, so a parser cannot tell how far "annotation" may run.
- **The specification should state** that a parser MUST reject a frame whose first byte begins none of the permitted frames, and that a byte with tritet 0b010 other than `_` begins none. It should also define annotated text, or say that its syntax is out of scope.
- **Re-issued at MUST if stated:** CESR-0041.

### I7: a body shorter than its version string declares (line 1129)

"Version 2.XX string field format", line 1129: "A Stream parser MUST be able to use the Version String to extract and deserialize (deterministically) any serialized Stream field maps." This states a capability for well-formed streams; it does not say what a parser does with a body shorter than its declared size, so rejecting one is inferred and graded SHOULD (revised 2026-10-02 after review; it was first graded MUST).

- **The specification should state** that a parser MUST reject a body shorter than the size its version string declares, once the input is known to be complete.
- **Re-issued at MUST if stated:** CESR-0042.

## Spec-internal conflicts (cases stay MUST and active)

### C1. What a count code's size counts (line 591 against lines 674, 714 and 1103)

- **The rule the cases follow.** Line 591: "The size component MUST count the Quadlets/triplets in its following group." The same paragraph adds that a count code "always counts the number of quadlets/triplets in the group not the number of primitives".
- **Conflicting text.**
  - Line 674, "Encoding Scheme Symbols Table": "When part of a Count Code determines the count of the following Primitives or groups of Primitives".
  - Line 714, "Encoding scheme format symbol table": "When part of a Count Code determines the count of following Primitives or groups of Primitives".
  - Line 1103, "Examples": "where `##` is replaced by the two-character Base64 count of the number of complex groups". The example's own values follow line 591: `-XBf` is 95 quadlets for one group, and `-KBC` is 66 quadlets for three signatures.
- **Correction.** Make the two legends read "the number of following quadlets or triplets", and make the example say `##` is the number of quadlets in the group. Counting items rather than quadlets is the defect that motivated the suite: a September 2026 survey of Rust implementations found counters that do it, and that left their streams and keripy's mutually unreadable. Whether those implementations took the item reading from these legends is not known.
- **Cases recording it:** every decoded `cesr-1.0` assertion, CESR-0012 to CESR-0031. They already rest on a MUST, so none is re-issued.

### C2. The size of indexed code `3A######` (line 702 against line 1086)

- **The rule the case follows.** The Annex "Indexed code table for genus/version `--AAACAA`" (line 1086) gives `3A######` a code length of 8, under the MUST at line 1068 ("A compliant KERI/ACDC genus MUST have the following codes in its contextual indexed code table.").
- **Conflicting text.** Line 702, the body's "Indexed code table": `|     `3`   |   1        |     3       |      3      |      6    |`. That is a code size of 6, though its own format `3$######&&&&` has eight code characters, and a 114-byte signature with pad size 0 needs a code that is a multiple of four characters.
- **Correction.** Change the body row's code size to 8.
- **Case recording it:** CESR-0023. Already MUST, so it is not re-issued.

### C3. Whether a genus/version code has a count (lines 806-808 against line 609)

- **Text.** The universal table (line 806) lists `-_AAA###` with Count Length `3*`, and the note at lines 808-809 says this "isn't a count of items". The KERI table lists `-_AAACAA` with no count length, and its note says the count lengths are 0. Line 609: "A protocol genus and version code itself MUST NOT provide a count of the following Quadlets or triplets".
- **Correction.** Drop the count length from the universal row, or say that `###` are version digits.
- **Effect on the suite.** None on any case. The adapter protocol reports a genus/version code as a `genus` item with no size, following line 609; keripy stores the version as a count of 8192.

## Gaps the suite tests outside the normative profile

### G1. No default genus for a stream without a genus/version code

- **Text.** Line 1158 requires 2.XX implementations to support 1.XX version strings, and the note after the master table says the 1.00 tables are not in this specification. Nothing says which table applies to the count codes of a stream that has no genus/version code.
- **Effect.** keripy 1.2.14 reads such streams with the 1.00 table and keripy main with the 2.00 table, so the same bytes frame differently.
- **The specification should state** a default genus/version, or require a leading genus/version code before any count code.
- **Cases:** CESR-0045, CESR-0046 and CESR-0047, in the non-normative `keripy-1x-interop` profile. They would stay there, since the 1.00 table is not specified.

### G2. Override scoping cannot be tested while only one table is defined

- **Text.** Lines 609 and 814-818 scope a genus/version override to its enclosing `-A`/`-B`/`-C` group. Line 814: "Should the first Group Code embedded in each of these groups be a genus/version code, then the parser MUST switch code tables to the code table given by that genus/version code."
- **Effect.** That an override ends with its group is observable only by switching to a different table, and the specification defines only genus 2.00. CESR-0029 tests the switch to the same table (MUST). CESR-0048 tests that a 1.00 override ends with its group, but the 1.00 table comes from keripy, so it sits in `keripy-1x-interop`.
- **The specification should** define the 1.00 table or a second table; then CESR-0048's shape could be issued at MUST in `cesr-1.0`.

### G3. Unassigned codes that carry their own size

- **Text.** Line 599 requires only that a small count code's type be a letter. Line 618 says old parsers "will break" on new codes, which describes rather than requires.
- **Effect.** A parser can skip `-dAB` or `4ZAB` by its size. The suite expects rejection only in the non-normative `cesr-strict` profile: CESR-0043 and CESR-0044.
- **The specification should state** that a parser MUST reject a code its genus/version does not assign, including one whose size it can read. If it does, CESR-0043 and CESR-0044 are re-issued at MUST in `cesr-1.0`.

### G4. What an ondex on a current-only signature means

- **Text.** The Annex indexed table gives `2B`, `0B` and `3B` (current only) a nonzero ondex length and puts no constraint on its value. Neither the CESR nor the KERI specification says what such an ondex means.
- **Effect.** keripy rejects a nonzero value, so CESR-0022 is disputed, keripy against the specification. KERI-layer logic that counts ondexes could weigh a current-only signature against the prior next keys.
- **The specification should state** that a current-only code's ondex MUST be zero (CESR-0022 would then be re-issued as a must-reject case at MUST), or what the ondex means.

## Editorial

- The Annex indexed table is headed "for genus/version `--AAACAA`"; everywhere else the code is `-_AAACAA`.
- The master table writes the large seal-source-couple row as `-S#####`; it should be `--S#####`.
- The Encoding Scheme Table's "proto + genus" row gives Type Chars 1, but its format `**$$$###` has three.
- Line 1144 renders the genus version `CAQ` as `1.16`; line 1142 renders the same digits as `2.16` for the protocol version.
- The master table names `1AAG` "DateTime Base64 custom encoded 32 char ISO-8601" without defining the custom encoding; the cases use keripy's (`:` as `c`, `.` as `d`, `+` as `p`).
- The commit tagged `v1.0` says "Specification Status: v1.1" in `spec/spec-head.md`.

# KERI specification issues found while building the conformance cases

Against the KERI specification v1.0.1 (tag `v1.0.1`, commit `71cb54ebb445dd9d8cb33cd29a5f50894fafc569`, file `spec/spec-body.md`; line numbers are that file's). The KERI cases grade by the decision procedure and the grading rules in `docs/design.md` ("KERI"). Each entry gives the text, what the specification should state, and what the cases do until it does. Entries are numbered K-G (gaps: behaviour no keyworded sentence states), K-I (inferred or interpreted text) and K-C (the specification against itself).

## Gaps the KERI cases depend on

### K-G1. No sentence obliges a validator to accept a valid event (lines 1258-1264, 1612, 1780)

- **Text.** Every validator sentence about acceptance states a precondition: line 1780, "MUST first verify the event's controller signatures, witness signatures (if witnessed), and delegator anchoring seal (if delegated) before it can accept that event into its copy of that event's KEL"; lines 1258-1264, "MUST ... in order for that event to be accepted as valid"; line 1612, "before the event may be accepted as valid". None says a validator must accept an event that passes.
- **Effect.** A validator that accepts nothing violates no MUST. Every case that grades a message `seen`, or on the trunk, does so at SHOULD with `inferred_from` (the clause registry's `liveness` inference), and a conformance claim states its SHOULD results beside the verdict.
- **The specification should state** that a validator MUST accept an event that is well formed, verifies, satisfies its thresholds and delegation, and does not conflict with its KEL's trunk. Those assertions would then be re-issued at MUST under new ids.

### K-G2. Refusing a conflicting event that is not a rotation has no keyword (lines 1799, 1810)

- **Text.** Line 1810, rule A2: "An interaction event may not supersede any event." Line 1799: "an event that may not supersede, according to the rules below, another event at the same location cannot be first seen at all by that KEL." Both are lowercase. The only keyworded sentence nearby is line 178, "there MUST be at most one valid KEL for any identifier or none at all", which limits how many KELs there are, not which event belongs on the trunk.
- **Effect.** A second interaction, a retrograde interaction signed by a rotated-out key, a second inception of a basic prefix, and a fully signed copy of an event that lost to a different version first seen are all graded not seen at SHOULD, inferred from line 1799 with rule A2 (`first-seen`), and the key state they leave is graded at the same level: KERI-0042, KERI-0044, KERI-0045, KERI-0050.
- **The specification should state** that a validator MUST NOT accept an event at a location already held on its KEL's trunk unless a superseding rule permits it, and that first seen means first accepted (line 1788 says so without a keyword).

### K-G3. Superseding recovery has no keyword (lines 1806-1819)

- **Text.** Rules A0 to B3 are lowercase ("may supersede", "may not supersede"). Only line 1823 is keyworded, and only for discarding.
- **Effect.** Accepting a rotation that rule A0 permits, and keeping the events it displaces as seen but off the trunk, are graded SHOULD, inferred (`recovery`), in cases that require `kel.recovery`: KERI-0046, KERI-0047.
- **The specification should state** whether a validator MUST accept a superseding rotation that A0 or B permits, and that the superseded events MUST NOT then contribute to key state.

### K-G4. Escrow other than for threshold shortfalls has no text (lines 1266, 1286, 1612)

- **Text.** The only escrow obligation is line 1266, for an event whose signatures do not satisfy its thresholds ("SHOULD escrow the event while waiting for other signatures to arrive"). Nothing says what a validator does with an event whose prior event it has not seen, or a delegated event whose delegating seal it has not seen (line 1612 says only that it must not be accepted before then). Line 1286 says a validator "can escrow" a receipt for an event it has not received, without a keyword.
- **Effect.** That such an event is not accepted on arrival is graded at MUST in `keri-1.0` (KERI-0016, KERI-0018, KERI-0031). That it is kept and accepted later is graded only in the non-normative `keri-escrow` profile, at INTEROP (KERI-0017, KERI-0019, KERI-0032). The generator checks every graded assertion under three keep policies (keep every not-yet-acceptable event, keep only threshold shortfalls, keep nothing) and refuses an assertion in `keri-1.0` that only an escrowing validator would satisfy. No case delivers a receipt before its event.
- **The specification should state** a level (SHOULD, or MAY given the DDoS warning at line 1286) for keeping out-of-order events, delegated events awaiting their seal, and early receipts.

### K-G5. A copy of an accepted event (line 1788)

- **Text.** Nothing says what a validator does with a second copy of an event it has accepted, or with extra signatures that arrive on such a copy.
- **Effect.** No case delivers one after acceptance. KERI-0005 delivers a second copy before acceptance, which line 1266 covers.
- **The specification should state** that a copy of an accepted event changes nothing, and whether newly verified signatures on it are kept.

### K-G6. Which code table a KERI stream's attachments use (CESR v1.0 lines 1129-1158; KERI line 265)

- **Text.** A 2.XX version string carries a CESR genus version (`Ggg`, line 265), but nothing says that it selects the table for the attachments after the body, and the CESR specification gives no default table for a stream without a genus/version code (`SPEC-ISSUES.md` G1 above).
- **Effect.** Every KERI case's stream starts with the genus/version code `-_AAACAA`, so its attachments are unambiguous under the CESR specification.
- **The specification should state** whether the version string's genus version governs the message's attachments.

### K-G7. A signer that meets a threshold through two encodings of one signature

- **Text.** L1258, L1262 and L1264 say "A set of controller-indexed signatures ... MUST at least satisfy the current signing threshold". A signature's index names its signer, so the threshold counts distinct indices. The CESR specification gives one signature more than one indexed encoding (for example code `A` and the big dual code `2A` at the same index), which are different bytes carrying the same raw signature.
- **Gap.** Nothing says a validator must collapse the two encodings to one signer before counting. A validator that counts distinct wire strings lets one key of a multi-signature group satisfy the whole threshold.
- **The specification should state** that threshold satisfaction counts distinct verified signer indices, independent of a signature's encoding.
- **Effect.** The duplicate-at-one-index cases KS-05b and KS-05d are published (KERI-0056, KERI-0058), because keripy counts them as one signer. The two-encoding case is held (allocated as a gap), because keripy counts it as two and accepts the event; see the private candidates note.

## Inferred or interpreted text

### K-I1. What a next-key digest digests (lines 340, 1325)

- **Text.** Line 340: the `n` field holds "a fully qualified digest of a public key". Line 1325: "each public key from the set of pre-rotated keypairs MUST be hidden as a qualified cryptographic digest of that public key."
- **Gap.** Neither keyworded sentence says whether the digest is over the public key's raw bytes or over its qualified (CESR text) form. The two give different digests, so validators that read it differently reject every rotation the other accepts.
- **Corroboration.** The `icp` example's next keys (L610-617) digest, as Blake3-256 over their qualified qb64 text, to exactly the example's `n` values (L577-582); the cases use the same convention. So the example pins the reading the keywords leave open. Under the "keyword governs" rule it stays inferred, but it is the specification's own convention, not only keripy's.
- **The specification should state** the digest's input in a keyworded sentence.

### K-I2. Line 1823 for a non-delegated KEL

- **Text.** Rule C1, line 1823: "The terminal case of the recursive application of C. will occur at the root KEL, which by definition MUST be non-delegated therefore either A. or B. MUST be satisfied, or else the superseding rotation MUST be discarded."
- **Reading the cases take.** A non-delegated KEL is its own root, so a rotation that tries to supersede outside rules A and B is discarded at MUST, graded `rejected` (design, "What MUST means here"). The sentence sits under rule C, about delegation chains, so a reader could take it to bind only delegated KELs.
- **The specification should state** the discard rule for every KEL, outside rule C.

### K-I3. A non-transferable identifier's key and prefix (lines 340, 353; catalogue G15)

- **Text.** Line 340 makes an inception with empty next keys non-transferable. Nothing states what code its prefix or its key must carry, or whether a basic prefix must equal its single key.
- **Effect.** KERI-0024 uses a basic non-transferable prefix whose key is qualified as non-transferable too; KERI-0025 uses a self-addressing prefix with empty next keys. Both must refuse a later rotation under line 340. keripy refuses the first while parsing, by its own basic-prefix rules (`DISAGREEMENTS.md`). The model derives a prefix's kind from its derivation code: any digest code (the master table's `E`, `F`, `0D` and the rest) is self-addressing and its `d` must equal `i`; a basic code (`D`, `B`) must equal the inception's only key; any other prefix code, or a basic prefix that is not the single key, is refused as not modelled rather than passed.
- **The specification should state** the rules for basic prefixes: which codes a prefix may carry, and that a basic prefix MUST equal the inception's single key.

### K-I4. Whether a non-canonical JSON body is valid

- **Text.** The CESR SAID protocol fixes the SAID over "the serialization" of the body. KERI message bodies are shown as compact JSON (no whitespace), for example at L596-607, but no keyworded sentence says a validator must reject a body that carries the right SAID over bytes that are not the compact serialization: extra whitespace, a `\u` escape, or a repeated label.
- **Gap.** A body that is self-consistent (its SAID is correct over its own bytes) but not compact has an unclear status. Duplicate top-level labels (CSR-F2) are the case with a safety consequence: two validators parsing `{...,"k":[A],...,"k":[B],...}` first-wins and last-wins derive different key states from one signed, same-SAID body, with no second KEL anyone can hold up as evidence of duplicity.
- **The specification should state** that a validator MUST reject a KERI body that is not the canonical (compact, unique-label) serialization its SAID is taken over.
- **Effect.** The generator's model refuses such a body as not modelled rather than grading it (`keri_model.intrinsic`), so no case depends on the reading, and no duplicate-label case is built. The duplicate-label divergence is a reason to rule L253's field-order obligation (K-I-field-order) a validator rule.

## The specification against itself

### K-C1. Receipts and the drop rule (line 1266 against lines 1266, 1286, 1782)

- **Text.** Line 1266: a validator that receives "a key event or non-key-event message that does not have attached at least one verifiable Controller signature MUST drop that message (i.e., not escrow or otherwise accept it)". A receipt (`rct`) is a non-key-event message (line 277) that carries witness signatures, not controller signatures.
- **Conflict.** Read literally, every witness receipt must be dropped, which contradicts the same paragraph's completion of a threshold "to a receipt of that event", line 1286 (receipt processing) and line 1782 ("can attach those signatures or seals to its copy of the event").
- **Effect.** The cases apply the drop rule to key events only and grade a receipt by its effect on its event. Every assertion about an event that receipts touch carries the conflict in `spec_conflicts` (`receipt-drop`): KERI-0038, KERI-0039, KERI-0040.
- **Correction.** Restrict line 1266's drop rule to key events and routed messages, or say "at least one verifiable signature from a party entitled to sign that message".

### K-C2. Dropping an unsigned key event: MAY at line 541, MUST at line 1266

- **Text.** Line 541: "A Validator MAY drop any provided key event message body that does not have at least one attached signature from the current controlling key state". Line 1266 makes the same drop a MUST.
- **Effect.** The cases follow line 1266, the later and more specific sentence, and record line 541 in `spec_conflicts` (`unsigned-may`): KERI-0006, KERI-0007, KERI-0020.
- **Correction.** Make line 541 a MUST, or delete it in favour of line 1266.

## Editorial (KERI)

- Line 1435 lists the nine keys of the nested weighted example as ending `A<sup>0</sup>`; it should be `A<sup>8</sup>`.
- Line 1462 says "for the first clause" where the second clause is meant.
- Line 1813 says "under either of the following conditions" and then lists three.
- Line 358 writes "MUST not" in lowercase.
- The commit tagged `v1.0.1` says "Specification Status: v1.1" in `spec/spec-head.md`.

# ACDC specification issues found while designing the conformance cases

Against the ACDC specification v1.0 (tag `v1.0`, commit `4a543c549fd9811c23bf97b0daaf48400f4005c2`, file `spec/spec-body.md`; line numbers are that file's). "KERI line" and "CESR line" refer to the pins above. The ACDC cases are designed but not yet generated, so no entry names a case id; each says what the cases will do. The grading rules are in `docs/design.md`, under ACDC, "How levels are derived". Entries are numbered A-G (gaps), A-B (bytes the text leaves open) and A-C (the specification against itself).

## Gaps the ACDC cases depend on

### A-G1. No sentence obliges a validator to refuse an ACDC its issuer never committed to (lines 1663, 1669, 1843)

- Text. Line 1663 says the issuer "must anchor an *issuance* proof digest seal", in lowercase. Line 1843, "The Issuer MUST provide a signature or seal on the SAID of the most compact form variant", binds the issuer and sits in the IPEX section, which line 1797 declares non-normative. Lines 1669 and 1922 bind the issuer to anchor registry events. Line 1671 says that "A verifiable presentation of the ACDC requires the validator to have knowledge of the ACDC state proof", without a keyword.
- Effect. Refusing an ACDC with no issuer commitment, with its only seal in another identifier's KEL or in an event that is not on its issuer's trunk, with an attached seal reference naming an event that does not carry the seal, or whose registry was incepted or updated without the issuer's seal, is graded SHOULD, inferred. A direct refusal cites line 95, which makes the issuer's key state the one KERI establishes, inferred through lines 1663 and 1673; a refusal through a registry cites line 1669. No refusal cites line 1843, because the IPEX section is non-normative (A-G4).
- The specification should state that a validator MUST NOT treat an ACDC as valid unless its most compact SAID is committed by a seal in its issuer's KEL, directly or through a registry chain, and that a validator MUST find the seal in the issuer's KEL rather than trust an attached reference to it. Those cases would then be re-issued at MUST.

### A-G2. Revocation has no normative meaning (lines 2041, 2092)

- Text. The transaction state values are examples: "the state values for an issuance/revocation registry may be `issued` or `revoked`".
- Effect. There is no `revoked` verdict. Registry state is graded as facts, and what a revocation means for validity is graded only in a non-normative profile.
- The specification should state the state values of an issuance and revocation registry, and that a validator MUST NOT treat as valid an ACDC whose verified registry head is revoked.

### A-G3. Whether a signature alone commits an issuer, and with which key state (line 1843; KERI line 1260)

- Text. Line 1843 allows "a signature or seal", in a non-normative section. Normative text says the opposite: "ACDCs are not directly signed by the Issuer and are bound to the Issuer's Key State" (line 1673). KERI line 1260 checks a signature against the establishment event its attachment names, "which MAY or MAY NOT be the current signing threshold".
- Gap. The two texts disagree on whether a signature alone commits an issuer, and if it does, nothing says which of the issuer's establishment events the signature must name.
- Effect. Signature-only issuance is not tested.
- The specification should state whether signature-only issuance is valid, and if it is, that the referenced establishment event must be the issuer's latest at a point the validator can establish.

### A-G4. The IPEX section is non-normative but contains keywords (line 1797)

- Text. "This section is non-normative" (line 1797) is followed by MUST and SHOULD sentences (lines 1807, 1822, 1828 and 1843). Line 1822, which says to verify a SAID against its content before trusting a signature on the SAID, is needed outside IPEX.
- Effect. No case cites the IPEX section. IPEX messages are graded as KERI exchange messages, in `keri-1.0`.
- The specification should say which of those sentences are normative, and move the ones that are out of the non-normative section.

### A-G5. Line 68's scope: what "support the old Version String format" covers

- Text. Line 68: "Compliant ACDC version 2.XX implementations MUST support the old ACDC version 1.x Version String format to properly verify Message bodies created with 1.x format events." Nothing defines a 1.x body: its field set (`ri` rather than `rd`), its SAID computation (over the expanded form) and its registry (`vcp`, `iss`, `rev`) have no keyword anywhere.
- Gap. The sentence could mean that an implementation must frame a body declared with a 1.x version string, or that it must also judge it. It does not say what a validator does with a 1.x version string over a body that carries 2.00 fields.
- Effect. Line 68 is graded as framing only: a case presents a 1.x version string over bytes on which the 1.x and 2.00 rules agree, and its MUST assertion is that the implementation answers rather than errs. Everything else about 1.x is in the non-normative `acdc-keripy-1x-interop` profile.
- The specification should define the 1.x body, or say that line 68 requires framing only, and say whether a version string that contradicts its body's field set makes the body invalid.

### A-G6. Registry duplicity (lines 2023, 2027)

- Text. Nothing says what a validator does with two anchored updates at one sequence number.
- Effect. Not graded in `acdc-1.0`.
- The specification should state it, as KERI's first-seen rule does for key events.

### A-G7. Whether an edge's failure propagates (lines 1114, 1116, 1211)

- Text. Line 1114: "When any node in a provenance chain is invalid, an Edge pointing to that node MAY also be invalid. If a node has an invalid Edge, then the node MAY also be invalid." The same paragraph continues: "Typically, in a given EGF (ecosystem governance framework), all links from the node at the head at one end of a chain to the tail at the other end MUST be valid in order for the node (head) to be valid." Line 1116 says the same of trees. Line 1211's `NOT` operator inverts a far node's validity.
- Gap. A MUST inside "Typically, in a given EGF" binds no one in particular, and the MAYs leave both propagations, from a far node to its edge and from an edge to its near node, to the reader.
- Effect. Each edge is graded at MUST on the checks lines 1174, 1178, 1199, 1201 and 1205 require of it. Propagation is informative in `acdc-1.0`, and the reading in which a chain must be wholly valid is graded in the non-normative profile `acdc-chain-strict`.
- The specification should state the default propagation a validator applies when no EGF says otherwise, with a keyword, and how `NOT` interacts with a far node that is invalid for a reason other than the edge's own checks.

### A-G8. A BLID is a SAID only by analogy (lines 2066, 2141)

- Text. Line 2066: "A BLID is effectively a type of SAID." Line 2141: "The BLID computation follows the SAID protocol, adapted for fixed-field representations." CESR line 1194 makes the SAID verification protocol a MUST.
- Gap. Whether a validator MUST verify a disclosed blinded state block against its own BLID, as it must verify a SAID, rests on the analogy.
- Effect. A blinded state block that does not hash to its own BLID, and a consistent block whose BLID is not the update's `b`, are both refused at SHOULD, inferred, in separate cases.
- The specification should state that the SAID verification protocol applies to a BLID.

### A-G9. The Annex's normative status is unstated (lines 1911, 2735)

- Text. The Annex holds keyworded sentences, including line 2735's requirement that every implementation support the minimal selective disclosure mechanism, while line 1911 calls the Annex's ACDC examples informative.
- Effect. The cases treat keyworded Annex sentences as normative and Annex examples as examples.
- The specification should say which parts of the Annex are normative.

## Bytes the text leaves open

### A-B1. The bytes the most compact SAID is computed over (lines 62, 134-147; CESR lines 1194, 1276, 1289; line 3395)

- Text. Lines 134 to 147 describe compaction. Nothing says what the version string's size field holds in the compact form, which is shorter than an expanded form presented on the wire, or which JSON form the compact serialization takes. Compact JSON (no whitespace, non-ASCII unescaped) appears only in worked examples (CESR lines 1276 and 1289; line 3395). CESR line 1194 says to replace the SAID "in the serialization", which a reader can take to mean the bytes received.
- Effect. The generator gives `v` the compact serialization's own size, following line 62's statement that the field gives the serialization's size, and serializes compact JSON in UTF-8. A refusal stays MUST only if it holds under every reading. Accepting an ACDC presented in an expanded or partially disclosed form depends on the choice and is graded SHOULD, naming it. First-batch attribute values are ASCII.
- The specification should state, with a keyword, the size field and the serialization of the most compact form.

### A-B2. The serialization a schema's SAID is taken over (lines 186, 248; CESR line 1194)

- Text. A schema's `$id` is its SAID by the CESR SAID protocol, applied to "the serialization". Schemas in use are often distributed pretty-printed, and their `$id` verifies over a compact re-serialization but not over the file's own bytes.
- Effect. Scenario schemas are delivered compact, so both readings agree. A case that delivers a schema in another form grades its SAID at SHOULD.
- The specification should state whether a schema's SAID is computed over its compact serialization or over the bytes as distributed.

### A-B3. The code of a blinded state block's `ts` (lines 2062, 2087)

- Text. The block's fields are serialized "as CESR primitives that are appropriate for" a state string (line 2062). Only the empty placeholder's code is fixed, `1AAP` (line 2087). Tag, StrB64 and Bytes codes are all appropriate, and each gives a different BLID.
- Effect. The generator uses the Tag codes. Verifying a BLID does not depend on the code, since it is computed over the bytes received; reporting `ts` does, and a `ts` fact is graded SHOULD, naming the choice.
- The specification should fix the codes of the state values.

### A-B4. A SAIDed block inside a list (lines 140-147)

- Text. The most compact form compacts "any field within the block whose value is" a SAIDed block (lines 145-147). It says nothing about a SAIDed block that is an element of a list, as in an edge group listing several edges.
- Effect. The generator leaves a SAIDed block inside a list uncompacted when computing the enclosing block's SAID, which is the literal reading and, in the cross-check, keripy's. A case whose expected SAID depends on the choice grades it at SHOULD, naming it, under the grading rule for bytes the text leaves open.
- The specification should say whether list elements are compacted.

## The specification against itself

### A-C1. The aggregate: a concatenation (line 110) or a serialized list (lines 714, 720, 745-746)

- Text. Line 110 calls the aggregate "a cryptographic digest of the concatenation of an ordered set of the SAIDs of blinded Attribute sub-blocks". Line 714 serializes the list, with a dummied first entry, "as a list in whatever serialization kind is used by the enclosing ACDC". Neither has a keyword, and the verification steps at lines 745 and 746 index the list to a<sub>N-1</sub> where the definition at line 720 runs to a<sub>N</sub>.
- Resolution in the text. The worked example at lines 951 to 956 settles the JSON case. Its pre-image is a compact JSON list of four entries for three blocks, the dummy first, and its Blake3-256 digest is the AGID the example states. A bare concatenation of the SAIDs gives a different digest.
- Effect. The cases follow line 714 and the example and record line 110 in `spec_conflicts`. Because the reading rests on an example, accepting a selectively disclosed ACDC is graded SHOULD, inferred from line 2735 and the example. For a CESR-native ACDC, a list whose first entry is `#` characters is not a parseable CESR group, since `#` is not Base64, and the text does not say what bytes it denotes.
- Correction. Make line 110 describe the list, put a keyword on the computation, fix the indexing at lines 745 and 746, and define the CESR form.

### A-C2. The update's transaction SAID field: `ta` or `td` (lines 1980, 1993, 2035, 2060)

- Text. Line 1993: the `upd` fields "MUST appear in the following order, `[v, t, d, rd, n, p, dt, ta, ts]`". The field table at line 1980 also has `ta`. The field's heading at line 2035 and the cross-reference at line 2060 call it `td`, as keripy does.
- Effect. Cases that use `upd` follow line 1993's `ta`, record the other lines in `spec_conflicts`, and expect keripy to be disputed. No first-batch case uses `upd`.
- Correction. Use one label throughout.

### A-C3. Verifying a SAID by expanding: block-level or full (line 136 against lines 134, 142, 147)

- Text. Line 136: "To verify the SAID, just reverse the process. First, expand a given block, verify its SAID". Lines 134 and 142 fix the SAID as the most compact form's, computed over each block's block-level expanded form (line 147).
- Gap. Read as "fully expand", line 136 verifies a top-level SAID computed over the fully expanded form, which is keripy 1.x's rule and not 2.00's.
- Effect. The cases follow the keyworded sentences: an ACDC whose top-level `d` is computed over its fully expanded form is not valid at MUST, with line 136 recorded in `spec_conflicts`.
- Correction. Say "block-level expanded" in line 136.

### A-C4. The registry inception's sequence number label (line 1985)

- Text. Line 1985 lists the `rip` fields as `[v, t, d, u, i, n, dt]` and then says "The value of the sequence number field, `s` MUST be the hex encoded string for the integer 0". Seals use `s` (line 1922).
- Correction. Use `n` in the sentence, or `s` in the list.

### A-C5. Blinded state block labels (lines 2087, 2457)

- Text. Line 2087 calls `ts` "the transaction ACDC SAID", which is `td`. Line 2457 describes a field `tn` in a block whose field list names it `bn`.
- Correction. Fix the labels.

### A-C6. Whether every ACDC has an issuee (line 318 against lines 126, 1201)

- Text. Line 318: "The ACDC MUST be "issued by" an Issuer and MUST be "issued to" an Issuee." Lines 126 and 1201 define untargeted ACDCs, which have none.
- Effect. The cases treat untargeted ACDCs as valid, as the edge rules at line 1201 require.
- Correction. Qualify line 318 to targeted ACDCs.

## Editorial (ACDC)

- Line 226 calls JSON Schema 2020-12 "The Schema dialect for ACDC 1.0", naming the specification version where the protocol version, 2.00, is meant. The profile `acdc-1.0` shares the hazard and says so.
- The example at line 1874 uses the version string `ACDC10JSON00011c_`.
- The accreditation schema in the worked examples requires a `score` attribute (line 3760) that its own example ACDC (line 3679 onwards) does not carry, and it uses `additionalProperties`, so the example ACDC does not validate against its own schema. The generator reproduces the example's SAIDs but does not use the pair as a schema-validity case.

## KERI issues the exchange-message cases raise

### K-G8. Which exchange message's signature counts (KERI lines 1260, 1266, 1737)

- Text. Line 1266 drops a message without "at least one verifiable Controller signature", and line 1737 has a verifier establish the controlling keys "for the AID of that event". Line 1260 checks a signature against "the establishment event indicated by the event reference in the attachment group".
- Gap. Nothing says in one place that the referenced establishment event must belong to the message's sender, the AID in its `i` field. A validator that verifies an attached signature against whatever establishment event it names accepts any identifier speaking as any other.
- Effect. An exchange message carrying only another AID's valid signature, naming that AID's establishment event, is refused at MUST, on lines 1266 and 1737 together.
- The specification should state in line 1260 that the establishment event must be one of the sender's.
