# Disagreements between the CESR cases and keripy

The CESR cases take their expected values from the CESR specification, v1.0 (tag `v1.0`, commit `037129608b9e6960858b752019ac273d40d7386c`), through `generators/spec_tables`. keripy is used afterwards, only to cross-check. A disagreement is recorded here and never resolved by changing an expectation: the case is marked `disputed`, with a `dispute` record, until the question is settled.

How the cross-checks were run, from the repository root:

```sh
cd generators/keripy_check   && uv run python check.py --report /tmp/keripy-main-report.json
cd generators/keripy1x_check && uv run python check.py --report /tmp/keripy1x-report.json
```

- `generators/keripy_check` pins keripy main at `9a8b7aa70960f16fe7acffd8cf7901941ac912a1` (Python 3.14). Every `cesr.parse` case goes through keripy's own `Parser.msgParsator`, framed, once per message: keripy handles the leading genus/version code, reaps and verifies each body with `Serdery` (so a body with a wrong SAID or field set is refused), and extracts the attachments. Every `cesr.encode` case goes through keripy's `Matter`.
- `generators/keripy1x_check` pins keripy 1.2.14 (`bab95c16e949b61398129a3e41a8f68bad84c94f`, Python 3.12) and runs the `keripy-1x-interop` cases through keripy 1.2.14's `Parser.msgParsator`, with a recording stand-in for the `Kevery` it dispatches to, so it sees what the Parser extracted and runs no KERI validation.

Last run: 2026-10-01, all cases in `cases/cesr/`.

## What keripy's Parser can and cannot report

keripy's Parser hands back message bodies and lists of extracted attachments (`sigers`, `wigers`, `cigars`, `tsgs`, `frcs`). It does not report byte offsets, count codes, their sizes, where each group ended, or genus/version codes. The cross-check therefore compares, for each message, its protocol, version, serialization and size, and then each attachment list in order with codes, index fields and raw values. **The parts of every case that keripy cannot report are not cross-checked at all:** the `start`, `end` and `group_end` of every item, every `counter` item's `code` and `size`, and every `genus` item. In particular the founding cases' assertion that `-K` ends 66 quadlets after its code is corroborated only indirectly: keripy extracted exactly the expected signatures and then the expected next group or message, which it could not have done had it read the size as a number of signatures.

Two further limits:

- **ondex on current-only codes.** keripy checks that a current-only code's ondex field is zero and then sets its `ondex` to `None`, so it cannot report the field's value. CESR-0021 (`2B`, ondex 0) agrees on everything else and is recorded as `agree-except-ondex-not-reported`. For a both-same code (`A#`) keripy sets `ondex` equal to `index`, which is inference, not wire content, so the check leaves it out, as the case does.
- **Signatures.** Keys, digests and signatures in the cases are fixed pseudo-random bytes. keripy main's `msgParsator` does not verify signatures, and the 1.2.14 check stops at the recording Kevery, so no signature is verified anywhere and none would verify.

## Case disagreements

### CESR-0022: a current-only indexed code with a nonzero ondex (disputed)

- **What the specification says.** The Annex table "Indexed code table for genus/version `--AAACAA` (KERI/ACDC protocol stack version 2.00)" gives `2B####`, "Ed25519 indexed sig big current only", an Index Length of 2 and an Ondex Length of 2, under "A compliant KERI/ACDC genus MUST have the following codes in its contextual indexed code table." No clause constrains the value of a current-only code's ondex, so a stream carrying `2B` with index 70 and ondex 9 decodes, on the table, to index 70 and ondex 9.
- **What keripy does.** keripy main's Parser rejects the stream: `ValueError: Invalid ondex=9 for code=2B.`, because keripy requires the ondex of every code in `IdxCrtSigDex` to be zero (`src/keri/core/indexing.py`, the `IdxCrtSigDex` checks in `_exfil` and `_bexfil`).
- **Security dimension** (review finding SEC-F4). Neither the CESR nor the KERI specification says what an ondex on a current-only signature means. keripy's rule exists only in its CESR layer, while its KERI-layer `exposeds()` indexes the prior next-key digests with whatever ondex a signature carries. An implementation that decodes the field as the table allows and reuses that KERI logic could count a current-only signature toward the prior-next threshold where keripy rejects the stream, so validators could disagree about one controller-signed event. The review's verifier judged this a controller-induced interop divergence rather than a way for an unauthorized key to gain weight.

### CESR-0031: an empty attachments group (disputed)

- **What the specification says.** A small count code's two size characters "provide counts from 0 to 4095", and "The size component MUST count the Quadlets/triplets in its following group." An attachments group of size 0 after a body is therefore well formed and ends at its own count code.
- **What keripy does.** keripy main rejects it with `SizedGroupError`. After taking the empty `-C`, `msgParsator` peeks for a genus/version code inside the group, and the empty substream raises `ShortageError` (`src/keri/core/parsing.py`, the "peek for version change" extraction after `AttachmentGroup`). keripy's own comment in the same method says a message with no attachments "MUST have at least empty AttachmentGroup", so this looks like a keripy defect rather than a reading of the text. It rejects a stream, so it is not a security matter.

No other `cesr-1.0` or `cesr-strict` case disagrees. Every encoding, every decoded structure (to the extent keripy can report it), and every must-reject case agrees with keripy main. Every `keripy-1x-interop` case agrees with keripy 1.2.14, including its must-reject cases (where keripy's Parser yields for more bytes on a framed stream, the check counts that as the rejection the adapter protocol's end-of-input rule makes it), apart from CESR-0048, which is skipped there because it is a genus 2.00 stream that 1.2.14 does not implement. CESR-0048 agrees with keripy main, which implements the 1.00 override inside `-C` and reverts after it.

## keripy main on keripy 1.x streams (not a case disagreement)

CESR-0045, 0046 and 0047 are interop cases with keripy 1.x and carry no genus/version code, as keripy 1.x streams do not. keripy main defaults to the 2.00 tables (`Parser(version=Vrsn_2_0)`) and does not re-derive the table from a 1.XX version string, so it refuses all three: 0045 and 0046 with `TopLevelStreamError: Got GenericGroup so revisit.` (the 1.00 `-A` read as the 2.00 generic group) and 0047 with `TypeError: attribute name must be string, not 'NoneType'`. This is the gap review finding SEC-F1 describes: the specification defines no default genus for a stream without a genus/version code, so the same bytes frame differently in keripy 1.2.14 and keripy main. The interop profile asserts keripy 1.x behaviour, so these are recorded here rather than disputed.

## Code-table divergences that no case exercises yet

These came from comparing the specification's tables with keripy main's entry by entry. None changes how a current case is framed:

- **`-N##` / `--N#####`.** The specification: "Transferable identifier receipt quadruples pre+snu+dig+sig". keripy main: `NonceSealSingles`.
- **`--S#####`.** The master table writes the large seal-source-couple row as `-S#####`; the generator records it as an anomaly and leaves it out. keripy main has `--S` (`BigSealSourceCouples`).
- **Primitive codes in the specification but not in keripy main:** `0P`, `0Q`, `0R`, `0S` (Gram heads).
- **Primitive codes in keripy main but not in the specification:** `b`, `1__-`, `1___`, `2__-`, `2___`, `3__-`, `3___`.
- **Indexed codes in keripy main but not in the specification:** `E`, `F`, `2E`, `2F` (ECDSA secp256r1 indexed signatures), `0z`, `1z`, `4z`.

## Specification text issues noticed while building the cases

Not disagreements with keripy. Under the suite's policy, assertions affected by the first three record the conflicting text in `spec_conflicts` and keep their clause's level; `generators/SPEC-ISSUES.md` is the full list for the working group, including the consumer obligations the cases infer and grade SHOULD.

- **What a count code's size counts.** "Count Code tables" (line 591) says "The size component MUST count the Quadlets/triplets in its following group." and that it "always counts the number of quadlets/triplets in the group not the number of primitives." The symbol legends say a `#` digit in a count code determines "the count of the following Primitives or groups of Primitives" (line 674) or "the count of following Primitives or groups of Primitives" (line 714), and the Examples (line 1103) speak of "the count of the number of complex groups". The cases follow line 591; the specification's own example `-XBf` (95 = 11 + 6 + 11 + 1 + 66 quadlets) and `-KBC` (66) agree with it.
- **Indexed code table, body versus Annex.** The body's table gives selector `3` a code size of 6 (line 702); its format and the Annex (line 1086) give 8. The cases use the Annex.
- **The genus/version code's count.** The universal table lists `-_AAA###` with a count length of 3 (line 806); the KERI table lists `-_AAACAA` with none and a note that it is 0; "Protocol genus/version table" says the code "MUST NOT provide a count" (line 609). The cases report it as a `genus` item with no size.
- **Genus/version code in headings.** The Annex indexed table is headed "for genus/version `--AAACAA`"; everywhere else the code is `-_AAACAA`.
- **Version rendering.** The version-string section renders `CAQ` as `2.16` (line 1142) and, for the genus version, as `1.16` (line 1144). The adapter protocol pins its own rendering.
- **Version label.** The commit tagged `v1.0` carries "Specification Status: v1.1" in `spec/spec-head.md`.

# Disagreements between the KERI cases and keripy

The KERI cases (`cases/keri/`) take their expected values from the decision procedure in `docs/design.md` ("KERI"), applied by `generators/spec_tables/keri_model.py` to the exact bytes each case delivers, and grade them against the KERI specification v1.0.1 (tag `v1.0.1`, commit `71cb54ebb445dd9d8cb33cd29a5f50894fafc569`). The event bytes are built by `generators/spec_tables/keri_events.py` from the specification's field rules with the standard library only (SAIDs by the CESR SAID protocol over Blake3-256, Ed25519 signatures per RFC 8032), so keripy is not in the provenance of any KERI case. It is used afterwards to cross-check, never as the authority.

How the cross-check was run, from the repository root:

```sh
cd generators/keripy_keri_check && uv run python check.py --report /tmp/keripy-main-keri-report.json
```

`generators/keripy_keri_check` pins keripy main at `9a8b7aa70960f16fe7acffd8cf7901941ac912a1` (Python 3.14), the same commit as the keripy adapter. It checks two things for every case in `cases/keri/`:

- **Bytes.** keripy's `SerderKERI(sad=..., makify=True)` rebuilds each key event from its field values, recomputing the version string, the SAID and any self-addressing prefix, and must produce the case's body byte for byte; a body whose SAID or prefix a scenario tampered with on purpose must not be reproduced. keripy's `Verfer` must verify every controller and witness signature the scenario made and refuse every one it forged.
- **Dispositions.** The messages go, in order, through keripy's `Parser` into a fresh `Kevery(lax=False, local=False)`, with `Kevery.processEscrows()` run after each delivery until keripy's tables stop changing. Each reading comes from keripy's state (first-seen ordinals, its escrow tables, the last event at each sequence number), and the case's assertions are evaluated with the runner's own evaluator. The check does not share code with the keripy adapter.

Last run: 2026-10-05, all cases in `cases/keri/`.

## Results

Every assertion of every KERI case agrees with keripy main, at every level, including the `keri-escrow` profile. keripy rebuilds every untampered body byte for byte, refuses to rebuild or parse the bodies whose SAID or prefix the scenarios tampered with, and verifies or refuses each signature exactly as the scenarios made it. No case is disputed.

Two conventions the cases share with keripy, which the specification does not pin down (both are in `generators/SPEC-ISSUES.md`): a next-key digest is the Blake3-256 digest of the qualified public key's text (K-I1), and each stream starts with the genus/version code `-_AAACAA` (K-G6). keripy main reads streams with or without that code the same way.

keripy 1.2.14 was not run. It implements KERI 1.x bodies only, and every case so far carries 2.XX bodies.

## Where keripy agrees for a different reason (not a case disagreement)

- **KERI-0024, a rotation after a non-transferable inception.** The decision procedure refuses the rotation at step 3, because line 340 allows no more key events after a non-transferable inception. keripy refuses it earlier, when it parses the body: `ValidationError: ... Non-transferable code = B with non-empty nxt`. keripy treats any event of a basic non-transferable prefix that carries next keys as malformed, a rule of its own about basic prefixes (catalogue gap G15), and for the same reason its `SerderKERI` will not build that rotation at all, so the byte check cannot reproduce it. Both readings are "not seen", which is all the case grades. KERI-0025 tests the same rule with a self-addressing prefix, which keripy refuses by state, as the procedure does.
- **Conflicting events that are not rotations** (KERI-0042, KERI-0044, KERI-0045 and KERI-0050). keripy reports the refused event as `duplicitous`. The cases grade only not seen there, at SHOULD, since the design treats duplicitous as informative for a validator.
- **Readings the cases do not grade.** keripy keeps an event whose pre-rotation commitment is broken (KERI-0021) or whose delegating seal is missing (KERI-0028, KERI-0033, KERI-0034) as pending. The specification says only that such an event is not accepted, so the cases grade only not seen.
