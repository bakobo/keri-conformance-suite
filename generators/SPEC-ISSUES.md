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
