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
