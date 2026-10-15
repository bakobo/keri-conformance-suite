# Disagreements between the CESR cases and keripy

The CESR cases take their expected values from the CESR specification, v1.0 (tag `v1.0`, commit `037129608b9e6960858b752019ac273d40d7386c`), through `generators/spec_tables`. keripy is used afterwards, only to cross-check. A disagreement is recorded here and never resolved by changing an expectation: the case is marked `disputed`, with a `dispute` record, until the question is settled.

How the cross-checks were run, from the repository root:

```sh
cd generators/keripy_check   && uv run python check.py --report /tmp/keripy-main-report.json
cd generators/keripy1x_check && uv run python check.py --report /tmp/keripy1x-report.json
```

- `generators/keripy_check` pins keripy main at `9a8b7aa70960f16fe7acffd8cf7901941ac912a1` (Python 3.14). Every `cesr.parse` case goes through keripy's own `Parser.msgParsator`, framed, once per message: keripy handles the leading genus/version code, reaps and verifies each body with `Serdery` (so a body with a wrong SAID or field set is refused), and extracts the attachments. Every `cesr.encode` case goes through keripy's `Matter`.
- `generators/keripy1x_check` pins keripy 1.2.14 (`bab95c16e949b61398129a3e41a8f68bad84c94f`, Python 3.12) and runs the `keripy-1x-interop` cases through keripy 1.2.14's `Parser.msgParsator`, with a recording stand-in for the `Kevery` it dispatches to, so it sees what the Parser extracted and runs no KERI validation.

Last run: 2026-10-15, all cases in `cases/cesr/`.

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

### CESR-0058 to CESR-0061: variable-size primitives in a generic list (draft)

- **What the specification says.** The master table, under "A compliant KERI/ACDC genus MUST have the following codes in its Primitive and Count code tables.", defines the Bytes codes `4B`, `5B` and `6B` (lead sizes 0, 1 and 2) and the universal count code `-J##`, "Generic list mixed types". Nothing in the text limits which groups an attachments group (`-C`) may hold, so these cases carry each variable-size value in a `-J` inside the `-C` after a KERI 2.0 inception, and the reference parser decodes them.
- **What keripy does.** keripy main's Parser rejects all four streams with `TypeError: attribute name must be string, not 'NoneType'`: its attachment dispatch table (`Parser.Methods` in `src/keri/core/parsing.py`) has no entry for a generic list inside an attachments group, so the lookup returns `None` and `getattr` fails. `Parser.allParsator` catches the exception and flushes the stream, so it is a rejection, not a crash. keripy therefore says nothing about how it reads the variable-size codes themselves.
- **Open question.** Whether an attachments group may carry a generic list is not stated either way. These cases are draft; if they are promoted they need either a `dispute` record (keripy contradicts the reading above) or a ruling that a generic list is not an attachment, in which case they are deprecated and the values move to a container keripy reads.

No other `cesr-v1.0` or `cesr-strict` case disagrees. Of the draft cases added on 2026-10-15, CESR-0062 and CESR-0063 (a genus/version code opening a `-K` and a `-X`, which do not allow an override) and CESR-0066 (a `=` pad character in a text-domain primitive) agree: keripy rejects each with `SizedGroupError`. Every encoding, every decoded structure (to the extent keripy can report it), and every must-reject case agrees with keripy main. Every `keripy-1x-interop` case agrees with keripy 1.2.14, including its must-reject cases (where keripy's Parser yields for more bytes on a framed stream, the check counts that as the rejection the adapter protocol's end-of-input rule makes it), apart from CESR-0048, which is skipped there because it is a genus 2.00 stream that 1.2.14 does not implement. CESR-0048 agrees with keripy main, which implements the 1.00 override inside `-C` and reverts after it.

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
- **Pad size of the `6` variable-size table.** Line 553 says both that the table encodes raw binaries with a pad size of 0 and that it encodes those with a pad size of 2. The cases follow the second, which agrees with the table's title and line 539 (C4 in `generators/SPEC-ISSUES.md`).
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

Last run: 2026-10-15 (with KERI-0084 to KERI-0090, KERI-0100 to KERI-0116 and KERI-0123 to KERI-0142), all cases in `cases/keri/`; the earlier key-event results are unchanged since 2026-10-05.

## Results

Every assertion of every KERI case except those of KERI-0108 and KERI-0123 to KERI-0126 agrees with keripy main, at every level, including the `keri-escrow` profile. keripy rebuilds every untampered body byte for byte, refuses to rebuild or parse the bodies whose SAID or prefix the scenarios tampered with, and verifies or refuses each signature exactly as the scenarios made it, including, for a signature made over another event, against that event's bytes. Five key-event cases are disputed, KERI-0108 and KERI-0123 to KERI-0126, below; the exchange-message cases, four of them disputed, are under "Exchange-message cases" below.

Two conventions the cases share with keripy, which the specification does not pin down (both are in `generators/SPEC-ISSUES.md`): a next-key digest is the Blake3-256 digest of the qualified public key's text (K-I1), and each stream starts with the genus/version code `-_AAACAA` (K-G6). keripy main reads streams with or without that code the same way.

keripy 1.2.14 was not run through the full cross-check. It implements KERI 1.x bodies only, and every case carries 2.XX bodies. It was probed by hand for this batch's published duplicate-signature cases and agrees with keripy main.

The second batch (KERI-0054 onward) adds companion safety cases, duplicate-signature and witness-threshold cases, delegated-rotation seal cases, a delegatee interaction, a corrupt-copy case and a post-recovery disputed-branch case. Every assertion of every published case agrees with keripy main. A few additional safety cases in this area are held out of the public tree under the embargo policy (`docs/design.md`, Security) and are not described here.

The third batch (KERI-0084 to KERI-0090, all draft) adds an interaction signed by a rotated-out key, three rotations signed by the current key instead of the exposed next keys, controller and witness signatures indexed past the end of their lists, and a delegating seal anchored in a KEL other than the named delegator's. Every assertion agrees with keripy main, and keripy's readings match the decision procedure's exactly: it rejects the out-of-range and wrongly keyed signatures, and keeps the rotations, the under-witnessed inception and the misanchored delegated inception as pending. The byte check counts a controller signature on an establishment event made with a key outside that event's key list, or a witness signature indexed past the witness list, as one that must fail, as it counts a forged one. It still does not verify interaction signatures, so KERI-0084's signature is checked only through keripy's dispositions.

The tamper batch (KERI-0100 to KERI-0116: sixteen draft and one disputed) adds signatures over another event's bytes, receipts whose SAID is not the event their signatures cover, witness lists that repeat a witness, name a transferable witness or set a threshold larger than the list, and bodies with extra, missing or reordered fields, an unknown type, a nonzero inception sequence number, a sequence number above the maximum or an empty key list. Every assertion agrees with keripy main except KERI-0108's. keripy refuses to rebuild or parse every body whose field set or order the scenario changed, as it refuses one whose SAID was tampered with; it refuses a repeated backer in its own event validation (`Kever`, "has duplicates" for an inception's backers and for a rotation's cuts and adds), so KERI-0106 and KERI-0107 agree for the reason the cases give; and it keeps the interactions whose witness signatures or receipts cover other events as pending, as the decision procedure does. Neither receipt case exercises ticks 43af or 57pv: both use witness-indexed signatures, not receipt couples or transferable receipts.

The model-rules batch (KERI-0123 to KERI-0142: sixteen draft and four disputed) adds rotations and a delegated rotation that carry an inception-only configuration trait (assessment gap 7); rotations whose signatures meet the prior next threshold but not their own and the reverse, a rotation signed only by a newly added key, a weighted next threshold met and missed, and the specification's reserve and custodial rotation examples replayed with each of their dual-threshold failures (gap 8); and weighted thresholds whose exact rational sum is one, three weights of 1/3 and ten of 1/10, with the 1/3 case's two-signature shortfall (gap 9). Every assertion of the gap 8 and gap 9 cases agrees with keripy main, including the zero weights of the reserve and custodial examples and the current-only signatures of their newly added keys. The four gap 7 cases are disputed, below.

### KERI-0108: an inception designating a transferable witness (disputed)

- **What the specification says.** Line 353: "When the Backers are Witnesses, then the AIDs themselves MUST be non-transferable, fully qualified public keys." Line 1252: "Witnesses MUST use only nontransferable identifiers". Both bind the producer (`SPEC-ISSUES.md`, K-I5), so refusing an inception whose witness list carries a transferable prefix (code `D`) is graded SHOULD, inferred.
- **What keripy does.** keripy main accepts the inception and verifies the witness signature with the key the prefix carries. It checks that a witness prefix is non-transferable only when it builds a receipt message (`src/keri/core/eventing.py`, the `NonTransDex` checks in `messagize`), not when it validates an event's witness list, where it takes each witness's verifier from the list as given.
- **Security dimension.** None found that a third party can use. The witness key keripy verifies with is the one the prefix carries, so an attacker gains nothing a non-transferable prefix with the same key would not give; the controller that designated the witness is the only party whose assurance is weakened, if the witness later rotates its key under a KEL of its own. The case is therefore published disputed rather than embargoed.

### KERI-0123 to KERI-0126: a rotation carrying an inception-only configuration trait (disputed)

- **What the specification says.** Line 367: "Some configuration traits MUST only appear in the Inception (delegated or not) for the KEL", and "A Validator of an event MUST invalidate, i.e., drop any events that do not satisfy the constraints imposed by their configuration traits." The table under it marks `EO`, `DND` and `DID` Inception Only (lines 371 to 373). A rotation, delegated or not, that carries one of them is therefore dropped, at MUST. The decision procedure refuses it at step 1, because the body alone shows it (`docs/design.md`, the decision procedure; `this.i`, "An inception-only trait in a rotation is an intrinsic failure that is dropped").
- **What keripy does.** keripy main reads configuration traits only when it creates an identifier's `Kever` from its inception (`Kever.config`, called from `Kever.__init__`); `Kever.update` never looks at a rotation's `c`. It accepts each rotation as if its traits were empty and applies it to the key state. In KERI-0123 and KERI-0124 it then holds the interaction the cases chain to the inception at the same sequence number as duplicitous, and in KERI-0124 the delegated inception that interaction anchors stays pending.
- **Security dimension.** None found that a third party can use. Only the controller can sign such a rotation, and keripy ignoring the trait gives the controller nothing it could not have by leaving the trait out. Validators that disagree on the rule do diverge about the same KEL, which is a controller-made inconsistency rather than a forgery. The cases are therefore published disputed rather than embargoed.

## Where keripy agrees for a different reason (not a case disagreement)

- **KERI-0024, a rotation after a non-transferable inception.** The decision procedure refuses the rotation at step 3, because line 340 allows no more key events after a non-transferable inception. keripy refuses it earlier, when it parses the body: `ValidationError: ... Non-transferable code = B with non-empty nxt`. keripy treats any event of a basic non-transferable prefix that carries next keys as malformed, a rule of its own about basic prefixes (catalogue gap G15), and for the same reason its `SerderKERI` will not build that rotation at all, so the byte check cannot reproduce it. Both readings are "not seen", which is all the case grades. KERI-0025 tests the same rule with a self-addressing prefix, which keripy refuses by state, as the procedure does.
- **Conflicting events that are not rotations** (KERI-0042, KERI-0044, KERI-0045 and KERI-0050). keripy reports the refused event as `duplicitous`. The cases grade only not seen there, at SHOULD, since the design treats duplicitous as informative for a validator.
- **Readings the cases do not grade.** keripy keeps an event whose pre-rotation commitment is broken (KERI-0021) or whose delegating seal is missing (KERI-0028, KERI-0033, KERI-0034) as pending. The specification says only that such an event is not accepted, so the cases grade only not seen.

## Exchange-message cases

The exchange-message cases (KERI-0068 to KERI-0083, `scenarios/keri/exchange.json`) run through `exn.verify`. Their bytes are built by `generators/spec_tables/exn_build.py` from the specification's `xip` and `exn` field rules (lines 1154 and 1197) with the same standard-library SAIDs and signatures as the key events, and their verdicts come from the exchange-message decision procedure in `docs/design.md` ("IPEX"), applied by the same module's model validator. The same `check.py` cross-checks them: keripy's `SerderKERI(makify=True)` rebuilds each body, keripy's `Verfer` checks each signature against the keys of the establishment event its signature group names, and the KELs and messages go through keripy's `Parser` into a fresh `Kevery` and an `Exchanger` with no route handlers, a message reading `accepted` when keripy logged it.

Last run: 2026-10-09.

- **Bytes.** keripy rebuilds every `xip` and `exn` body the scenarios did not alter, byte for byte, and refuses the two they altered on purpose: the `exn` with an extra top-level field (KERI-0071), which keripy's 2.00 field set does not allow, and the `exn` whose `dt` was changed after its SAID was computed (KERI-0075). Every signature verifies or fails as the scenario made it: the signature by another identifier's key placed in the sender's group (KERI-0070) fails against the sender's key, the other identifier's own signature group (KERI-0076) verifies against that identifier's key, and the signature a scenario forged at index 2 of a multi-key sender's group (KERI-0083) fails.
- **Verdicts that agree.** KERI-0069 (unsigned), KERI-0070, KERI-0071, KERI-0075 and KERI-0076 are rejected, and KERI-0077, a signed `exn` outside any transaction, is accepted. For multi-key senders keripy refuses one valid signature short of a two-of-three threshold (KERI-0078), two valid signatures whose weights sum to 1/2 (KERI-0080), one key's signature attached twice (KERI-0082) and a pair of which one signature does not verify (KERI-0083), and it accepts the threshold met by count (KERI-0079) and by weight (KERI-0081). keripy refuses KERI-0069 before its `Exchanger` sees it, because `Kevery.processMsg` requires an authentication attachment on an `exn`, and it refuses KERI-0076 because its `Exchanger` drops evidence not from the sender on a route with no evidence policy; both are the readings the cases grade.
- **Disputed: an exchange inception is never accepted** (KERI-0068, and the `xip` messages of KERI-0072 and KERI-0073). Line 979 says the first message of a transaction MUST be an `xip` and `x` MUST be its SAID. keripy main does not process one: `Kevery.processXip` is a stub ("no processing yet", `src/keri/core/eventing.py`). keripy's own IPEX opens an exchange with an `exn` whose `x` is the digest of a fresh nonce instead (`apply`, `offer` and `grant` in `src/keri/acdc/ipexing.py`). The `exn` of KERI-0068 is accepted, as the case expects.
- **Disputed: transaction links are not checked on a route with no handler** (KERI-0072, KERI-0073, KERI-0074). keripy's generic exchange processing (`Exchanger.processEvent`) reads neither `p` nor `x`, so it accepts a signed `exn` whose `p` names nothing (KERI-0072), whose `x` names an `exn` it accepted rather than an `xip` (KERI-0073), or whose `x` is not empty though no `xip` was delivered (KERI-0074). The cases grade those refusals at SHOULD, inferred from lines 975 and 979, which bind the sender. The keripy adapter's README already notes this behaviour.

No MUST assertion of an exchange-message case disagrees with keripy main. keripy 1.2.14 does not implement `exn.verify`, and every one of these cases is not-supported there.

# Disagreements between the ACDC generator's primitives and keripy

The generator's primitives (`generators/spec_tables/acdc_saids.py`, `acdc_build.py` and `json_schema_subset.py`) compute SAIDs, most compact SAIDs, schema SAIDs, AGIDs and BLIDs, and evaluate schemas, from the ACDC specification v1.0 (tag `v1.0`, commit `4a543c549fd9811c23bf97b0daaf48400f4005c2`) with the standard library only. keripy cross-checks them; it is not their source.

How the cross-check was run, from the repository root:

```sh
cd generators/keripy_acdc_check && uv run python check.py --report /tmp/keripy-main-acdc-report.json
```

`generators/keripy_acdc_check` pins keripy main at `9a8b7aa70960f16fe7acffd8cf7901941ac912a1` (Python 3.14), the same commit and lock as `keripy_keri_check`. Its fixtures are the pinned text's worked examples and bundles the generator builds; for each it compares the generator's value with keripy's (`SerderACDC`, `Compactor`, `Aggor`, `Blinder`, `Schemer`) and, where the text leaves bytes open (`acdc_saids.CANDIDATES`), reports which reading keripy follows on the fixtures that tell the readings apart.

Last run: 2026-10-09. Every primitive agrees on every fixture (13 registry SAIDs, 19 most compact SAIDs from compact, expanded, partially and selectively disclosed forms, 19 nested block SAIDs, 10 schema SAIDs, 2 AGIDs, 5 BLIDs, 9 schema verdicts). On every open choice keripy follows the design's reading: the most compact form's version string sized to itself (A-B1, now settled by line 134 and reported only as a diagnostic), JSON with non-ASCII unescaped (A-B1), a schema SAID over its compact re-serialization, so that a pretty-printed schema verifies (A-B2), Tag codes for `ts` (A-B3), the AGID over the serialized list (A-C1), and a SAIDed block inside a list left uncompacted, a choice the design does not name.

## The ACDC cases

The ACDC cases (`cases/acdc/`) take their expected values from the decision procedure in `docs/design.md` ("ACDC"), applied by `generators/spec_tables/acdc_model.py` to the exact bytes of each bundle; keripy is not in their provenance. The same run of `generators/keripy_acdc_check` replays every committed case, stream by stream, and compares five things with keripy main:

- whether each framed ACDC passes step 1 (field order, required fields, `a` and `A`, every SAID), against `SerderACDC(raw=..., verify=True)`: 116 ACDCs, all agree. keripy refuses the three bodies the cases refuse for their fields (ACDC-0006, 0007 and 0008) for the same field rule, not for their SAIDs;
- whether each schema's `$id` is the SAID of its bytes, against `Schemer(raw=...)`: 86 schemas, all agree, including the document ACDC-0014's bundle holds at a non-local reference's URI, which is not a SAD and which both sides find is not one;
- whether each ACDC validates against its verified schema, where the schema is inside the subset and names the 2020-12 dialect, against `Schemer.verify`: 110 verdicts, all agree;
- whether each registry event's SAID verifies, against `SerderACDC(raw=..., verify=True)`: 43 events, all agree;
- whether each disclosed blinded state block hashes to its own BLID, against the BLID `Blinder(crew=..., makify=True)` computes: 19 blocks, all agree, including the two the cases refuse.

Last run: 2026-10-09, over the 76 cases after the acdc-exn-cases review. No ACDC case disagrees with keripy, and none is disputed. keripy's adapter does not declare `acdc.version-2.x`, so no case's verdict, registry head or edge has been compared with keripy's own judgment; `adapters/keripy/README.md` ("acdc.verify") says why. That is why the batch is issued `draft` (docs/design.md, ACDC, The first batch). The replay does not cover the KELs, so the recovery rotations of ACDC-0020 and ACDC-0065 to 0067 are checked by the KERI model alone, and an ACDC whose version string declares the wrong size (ACDC-0064) does not frame, so step 1 is not compared for it.
