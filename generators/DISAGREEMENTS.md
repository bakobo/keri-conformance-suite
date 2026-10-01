# Disagreements between the CESR cases and keripy

The CESR cases take their expected values from the CESR specification, v1.0 (tag `v1.0`, commit `037129608b9e6960858b752019ac273d40d7386c`), through `generators/spec_tables`. keripy is used afterwards, only to cross-check. A disagreement is recorded here and never resolved by changing an expectation: the case is marked `disputed`, with a `dispute` record, until the specification working group settles the question.

How the cross-checks were run, from the repository root:

```
cd generators/keripy_check   && uv run python check.py --report /tmp/keripy-main-report.json
cd generators/keripy1x_check && uv run python check.py --report /tmp/keripy1x-report.json
```

- `generators/keripy_check` pins keripy main at `9a8b7aa70960f16fe7acffd8cf7901941ac912a1` (Python 3.14) and checks every case in profile `cesr-1.0`. keripy's `Parser` does not report decoded items, so the check walks each stream with keripy's own `sniff`, `smell`, `Counter`, `Matter` and `Indexer`; its module docstring says exactly what the walk decides itself.
- `generators/keripy1x_check` pins keripy 1.2.14 (`bab95c16e949b61398129a3e41a8f68bad84c94f`, Python 3.12) and checks every case in profile `keripy-1x-interop`, both by walking with keripy 1.2.14's classes and by re-emitting each count code with keripy's own `Counter`.

Last run: 2026-10-01, cases CESR-0001 to CESR-0050.

## Case disagreements

### CESR-0022: a current-only indexed code with a nonzero ondex

- **What the specification says.** The Annex table "Indexed code table for genus/version `--AAACAA` (KERI/ACDC protocol stack version 2.00)" gives `2B####`, "Ed25519 indexed sig big current only", an Index Length of 2 and an Ondex Length of 2, under the sentence "A compliant KERI/ACDC genus MUST have the following codes in its contextual indexed code table." No clause constrains the value of the ondex field of a current-only code. A stream carrying `2B` with index 70 and ondex 9 therefore decodes, on the table, to index 70 and ondex 9.
- **What keripy does.** keripy main rejects the stream: `Indexer` raises `ValueError: Invalid ondex=9 for code=2B.`, because keripy requires the ondex of every code in `IdxCrtSigDex` (current-only codes) to be zero (`src/keri/core/indexing.py`, the `IdxCrtSigDex` checks in `_exfil` and `_bexfil`). With ondex 0 (CESR-0021) keripy and the table agree.
- **Status.** CESR-0022 is `disputed`. This is keripy being stricter than the text, not keripy accepting something the text forbids, so it is not a security matter. The specification should either state that a current-only code's ondex must be zero, which would turn CESR-0022 into a must-reject case under a new id, or confirm that the field is unconstrained.

No other case disagrees. Every encoding (CESR-0001 to 0011), every decoded structure, and every must-reject case (CESR-0035 to 0046) agrees with keripy main, and every interop case (CESR-0047 to 0050) agrees with keripy 1.2.14, whose count codes also re-emit byte for byte.

## Rejections the walk decided from keripy's sizes

For four must-reject cases the rejection came from the cross-check's walk rather than from an exception keripy raised, because keripy's classes report sizes and leave the comparison with the stream to the parser. In each case keripy's own `Parser` stops in the same place, so these are recorded as agreement:

- CESR-0035 and CESR-0039: a `-J` group whose `Counter.byteCount` runs past the end of the stream. keripy's parser extracts a counted group only once `byteCount` bytes are present and raises `ShortageError` on an enclosed or framed stream that is short (for example `_ControllerIdxSigs2` in `src/keri/core/parsing.py`).
- CESR-0045: `sniff` reports a cold start of `ano` (annotated text) for the bare binary primitive; keripy's `_extractor` raises `ColdStartError` for any cold start other than text or binary.
- CESR-0046: `smell` declares a body longer than the stream.

## Code-table divergences that no case exercises yet

These came from comparing the specification's tables with keripy main's tables entry by entry (`table_differences()` in `generators/keripy_check/check.py`). None changes how a stream is framed, so none affects a current case, but each is a place where a future case would disagree:

- **`-N##` / `--N#####`.** The specification: "Transferable identifier receipt quadruples pre+snu+dig+sig". keripy main: `NonceSealSingles`. Both count quadlets, so framing agrees; what the group holds does not.
- **`--S#####`.** The specification's master table writes the large seal-source-couple row as `-S#####`, which reads as a small code with five size digits; the generator records it as an anomaly and leaves it out. keripy main has `--S` (`BigSealSourceCouples`).
- **Primitive codes in the specification but not in keripy main:** `0P`, `0Q`, `0R`, `0S` (Gram Head Neck, Gram Head, Gram Head AID Neck, Gram Head AID).
- **Primitive codes in keripy main but not in the specification:** `b`, `1__-`, `1___`, `2__-`, `2___`, `3__-`, `3___`.
- **Indexed codes in keripy main but not in the specification:** `E`, `F`, `2E`, `2F` (ECDSA secp256r1 indexed signatures), `0z`, `1z`, `4z`.

## Specification text issues noticed while building the cases

Not disagreements with keripy, and not marked disputed; recorded so the editorial questions are not lost.

- **What a count code's size counts.** "Count Code tables" (line 591) says "The size component MUST count the Quadlets/triplets in its following group." and "always counts the number of quadlets/triplets in the group not the number of primitives." The symbol legends under "Encoding Scheme Symbols Table" and the indexed-code "Encoding scheme format symbol table" say a `#` digit in a count code determines "the count of the following Primitives or groups of Primitives" (line 674) or "the count of following Primitives or groups of Primitives" (line 714). The cases follow the explicit rule.
- **Indexed code table, body versus Annex.** The table under "Indexed code table" in the body gives selector `3` a code size of 6, while its format `3$######&&&&` and the Annex give 8, and a 114-byte signature needs a code that is a multiple of four characters. The cases use the Annex.
- **Genus/version code in headings.** The Annex indexed table is headed "for genus/version `--AAACAA`"; everywhere else the code is `-_AAACAA`.
- **Encoding Scheme Table, "proto + genus" row.** Type Chars 1, but the format `**$$$###` has three type characters.
- **The genus/version code's size.** The universal table lists `-_AAA###` with a count length of 3; the KERI table lists `-_AAACAA` with no count length and a note that it is 0; "Protocol genus/version table" says the code "MUST NOT provide a count". The cases report it as a counter with size 0 and `group_end` equal to its own end, carrying `genus` and `gvrsn`; keripy stores the version as a count of 8192.
- **Version label.** The commit tagged `v1.0` carries "Specification Status: v1.1" in `spec/spec-head.md`.
