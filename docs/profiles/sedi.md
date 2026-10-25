# sedi-1, SEDI's deployment profile

sedi-1 is the State of Utah SEDI program's deployment profile for KERI, CESR and ACDC. It is a layered, non-normative profile: it adds nothing to the normative profiles it sits on (`cesr-v1.0`, `keri-v1.0.1`, `acdc-v1.0`), and settles each place where the specifications are silent or disagree and SEDI needs one reading in order to interoperate. Each such reading is a numbered choice, listed below with the reason for it and the specification text that would overturn it. The profile is a draft at version 1; its machine-readable source is [`scenarios/sedi/profile.json`](https://github.com/bakobo/keri-conformance-suite/blob/utah/next/scenarios/sedi/profile.json), from which `profiles/sedi-1.json` is built, and the plan it was built to is [the test plan](sedi-test-plan.md).

A choice is a profile decision, not a finding about the specification. The choices that read the specification where it is silent or contradicts itself are being drafted as questions for its working group, and a different answer from the working group produces a new profile version, never an edit to this one.

## Claiming sedi-1

An implementation claims sedi-1 by passing every sedi-1 case and its prerequisites' cases. It must offer the operations `cesr.parse`, `keri.process`, `exn.verify`, `acdc.verify`, `acdc.issue`, `acdc.present`, and declare the features `cesr.genus-2.00`, `cesr.serialization.json`, `crypto.ed25519`, `kel.basic`, `keri.version-2.x`, `acdc.version-2.x`, `acdc.edges`, `acdc.registry.bup`, `acdc.presentation`. A case that needs a feature the adapter does not declare is not run, so declaring fewer features cannot pass the profile: a claim needs them all.

## Verdicts

A sedi-1 verifier answers `valid`, `invalid` or `incomplete`:

- `invalid` means a check failed. Nothing more in the bundle could cure it.
- `incomplete` means something the verdict needs is absent or cannot be evaluated: a withheld registry event, an unknown operator, an undisclosed issuee. **`incomplete` is never an accept, provisional or otherwise.**
- When a bundle holds both a failed check and something unevaluable, the verdict is `invalid` (failure-precedence), so adding an unknown operator to a forged credential cannot turn a reject into a retry.
- `valid` holds only as of the registry head the verifier reports. A later revocation that the bundle does not carry is not reflected in it, which is why registry-evidence refuses a bundle whose issuer's KEL seals an event the bundle lacks.
- `valid` does not mean unexpired. sedi-1 does not check any expiry an ACDC's attributes carry; that is the relying party's check.

### The verdict cases

[`scenarios/sedi/verdicts.json`](https://github.com/bakobo/keri-conformance-suite/blob/utah/next/scenarios/sedi/verdicts.json) holds the cases that show the three verdicts apart (Utah's KERI-012; the test plan's item 8). Its first bundle, ACDC-0216, is a credential with two edges under `AND`, and is `valid`. Each cause of an unresolved verdict is then put on its first edge's side twice: once with the item absent or not evaluable (`incomplete`), and once with it present and failing a check (`invalid`). Each `incomplete` bundle is also combined with a broken SAID, a revocation and a failed `I2I`, and each of those is `invalid`:

| Cause | `incomplete` | `invalid` | With a definite failure |
|---|---|---|---|
| The far issuer's KEL | ACDC-0217 | ACDC-0218 | ACDC-0219 to ACDC-0221 |
| A registry event | ACDC-0222 | ACDC-0223 | ACDC-0224 to ACDC-0226 |
| The far node | ACDC-0227 | ACDC-0228 | ACDC-0229 to ACDC-0231 |
| The far node's schema | ACDC-0232 | ACDC-0233 | ACDC-0234 to ACDC-0236 |
| An unknown operator | ACDC-0237 | ACDC-0238 | ACDC-0239 to ACDC-0241 |
| An unsupported registry kind | ACDC-0242 | ACDC-0243 | ACDC-0244 to ACDC-0246 |
| An undecidable edge | ACDC-0247 | ACDC-0248 | ACDC-0249 to ACDC-0251 |

A KEL event whose signature fails is not part of the KEL, so a forged KEL reads as an absent one and is `incomplete`. The KEL's `invalid` case therefore corrupts what a correctly signed KEL says: its seal for the far node's registry update names the issuer instead of the registry. The KEL's other states are a gap before the anchors (ACDC-0252) and a KEL cut before an anchor (ACDC-0253), both `incomplete`. ACDC-0217 is the absent KEL.

The nested-edge cases, ACDC-0254 to ACDC-0281, each pair a defect with its positive twin: a SAID mismatch, a schema mismatch and a missing far node at depth 2; a far node that is a registry event rather than a credential; a diamond with one revoked branch under `AND` and under `OR`; an `OR` whose first alternative is unresolved; a cycle among claimed SAIDs; each of `I2I`, `NI2I`, `DI2I` and `E1E` in a nested edge-group; an aggregate far node whose issuee block is undisclosed; an edge at depth 2 under the default operator, to a far node issued to someone else; and the same edge to a far node whose attribute block is presented compact, which hides whether it has an issuee and so which operator the default appends. Edge-groups nested past the maximum depth are ACDC-0183, with ACDC-0182 at the maximum. A provenance chain longer than 8 edges cannot be a case, because the case format bounds every bundle's DAG.

The always-X self-test, `tests/test_verdict_self_test.py`, runs a verifier that answers `valid` to everything, one that answers `invalid` and one that answers `incomplete` over every ACDC verifier case, read as if active. Each fails sedi-1, and acdc-v1.0 finds the last two conformant at MUST.

## Maxima

A sedi-1 credential holds at most 64 events in its registry, 32 attribute blocks in an aggregate, edge groups nested 8 deep counting the edge section, 8 operators in one `o` list, 4096 bytes in one attribute value, and 44 characters in any `u`, the longest primitive one holds (choice `bounds`, this.i `7qx6tl5p`). Every maximum is checked on the whole credential, so no OR alternative can hide a breach. A credential past a maximum is never `valid`. A verifier may refuse it as `invalid` or decline to evaluate it as `incomplete`, and its cases accept either, but it must answer rather than hang.

## For relying parties

- **Source registry state from the issuer's witnesses or a watcher, not from the presenter.** A holder assembles the bundle, and the profile's registry rules (registry-evidence, registry-head) close the ways a holder can make withheld evidence read as good only for what the bundle shows. Registry state the presenter supplies is only as current as the presenter chose.
- **Untargeted credentials are bearer credentials** (bearer-untargeted). Anyone holding one may present it.
- **A presented credential is bound to its issuee** (presenter-binding): the sender of the grant must be the issuee, or for an aggregate the issuee named at `A[1].i`.
- **A credential is migrated from 1.x by revoking both forms.** sedi-1 never accepts a 1.x form (no-1x), but a verifier that reads 1.x may still accept a 1.x copy of a credential revoked only in its 2.00 registry, unless that verifier can be expected to see the 2.00 registry.

## Cross-role agreement

Passing the profile shows each implementation against the cases. `kcs agree` shows implementations against each other (this.i `3ptj8hu9`). It sends every `acdc.issue` and `acdc.present` case to each adapter named with `--adapter NAME=CMD`, turns what each one issued or presented into `acdc.verify` bundles built only from what it returned, and has every adapter judge every bundle, the producer included. A cell expects `valid` when the case expects an issuance or presentation and the producer's answer passed the case, and expects not valid when an issuer issued what its case says it must refuse. Every other cell is recorded without an expectation. The command exits 1 when any cell disagrees, and `--report` writes the matrix as JSON for the evidence pack. The matrix is evidence beside a claim, never part of the profile's verdict.

## The 1.x companion

`sedi-1x-interop` grades SEDI's credentials in keripy 1.x's forms: the 1.x field set, its SAID over the expanded form, and its `vcp`/`iss`/`rev` registry (this.i `9sgwng6m`). No specification defines those forms, so the profile is non-normative, every assertion is INTEROP, and its expected verdicts are keripy 1.2.14's, with one exception, its issuance cases, below. The suite builds every 1.x issuance it presents itself, and `generators/keripy1x_check/check_acdc.py` confirms each verdict against keripy 1.2.14. It is sedi-1's companion, not part of it: a 1.x result never enters a sedi-1 claim. It runs against keripy 1.2.14's adapter and against `adapters/signify-keria`: signify-ts has no ACDC verifier of its own and leaves validation to the KERIA agent it drives, so that adapter judges each bundle with released signify-ts and KERIA, which the adapter starts in Docker. KERIA 0.4.1 judges with keripy 1.2.14 itself, so the two adapters differ only in what KERIA adds around keripy.

Its cases turn the incompatibilities SEDI met moving a credential between 1.x wallets (`interop/two-wallets/RESULT.md`) into pairs: a 1.x credential under SEDI's published 2.0 schema shape, an `a.dt` that SEDI core's closed attribute section forbids, an `a.dt` a schema allows beside one with none, and the optional agent edge. One more is not in that list: keripy 1.x reads every label of an edge section except `d` and `o` as an edge, so the section's own `u`, which SEDI's schema requires, stops it verifying any SEDI credential that carries an edge section (ACDC-0205, and its pair ACDC-0207, which differs only in lacking that `u`). The cross-version case, ACDC-0206, is the 1.x copy of a claim whose 2.00 form is revoked: a 1.x verifier still finds it valid.

Two cases ask a 1.x issuer for SEDI core instead of presenting what the suite built (this.i `s6amsapq`). Their expected outcome is the one exception to keripy 1.2.14 as the basis: it is what SEDI core's 1.x schema allows (`interop/two-wallets/schemas/sedi-core-1x.schema.json`). keripy 1.x's issuer adds `a.dt` to every credential it makes, and signify-ts's `credentials().issue` inherits that, so taking keripy's behaviour as the answer would grade incompatibility 8 as correct. ACDC-0282 (SX-08) asks for SEDI core with its attributes and nothing else, and expects it issued; keripy 1.2.14 refuses its own credential against the schema, and KERIA refuses the one signify-ts built, so both fail it. ACDC-0283 (SX-09) asks for `a.dt` under a schema that names it, and both issue it, which shows SX-08 fails on `a.dt` alone. Each case states its basis in its assertion, and `check_acdc.py` prints keripy's own outcome beside each one without counting it. Each attribute is asked for whole, a nested block with its own SAID, because neither issuer makes nested blocks, so the other half of incompatibility 8, nested blocks left unsaidified, is not exercised.

## What sedi-1 does not add

sedi-1 adds to its prerequisites only what SEDI's ACDC use needs. In KERI and CESR it adds two kinds of case: an issuer key rotation between issuance and verification, and the parse of the attachment group codes SEDI uses (seal-couple-code, blind-state-code). Everything else in KERI and CESR is graded by `keri-v1.0.1` and `cesr-v1.0`. In IPEX it adds the grant that carries a presentation and the presenter check on it; the apply, offer and agree messages are out of scope for version 1, and a grant cannot carry a revocation chain (keri-sow tick `2dxo`).

## The choices

### Registries

#### `tel-sequence`

A registry event's sequence number n is its predecessor's plus one, and the inception's is 0.

Why: ACDC line 2135 says n MUST increment, which reads as plus one; line 2023 says only strictly monotonically increasing, which would allow gaps. keripy and heti both require plus one.

Overturned by: Specification text that allows a registry's sequence numbers to skip.

This choice is decided in this.i `8g9vtxvc`; tracked as keri-sow tick `57ud`.

#### `registry-head`

A registry's current state is its highest-n event that chain-verifies from the inception and is sealed in the issuer's KEL; two sealed events claiming one n are refused.

Why: No clause selects a registry's current event or says what two events at one n mean; heti pins this reading.

Overturned by: A specification rule for selecting the current registry event or for duplicitous registry events.

This choice is decided in this.i `8g9vtxvc`; tracked as keri-sow tick `5qcy`.

#### `registry-evidence`

Registry evidence the verdict did not account for makes it never valid: incomplete when a later event, its body or its disclosed state is absent, invalid when a later event fails a check.

Why: The bundle is the holder's; without this, withholding one event leaves a revoked credential's head at issued.

Overturned by: None from the specification.

This choice is decided in this.i `3g4le6js`; security-relevant: getting it wrong admits what should be refused.

#### `revoked`

A credential whose registry head records it revoked is invalid.

Why: The specification has no revoked verdict and names issued and revoked only as example states; SEDI needs one.

Overturned by: Specification text defining what a revoked state means for a verdict.

This choice is decided in this.i `8fh68wt6`; security-relevant: getting it wrong admits what should be refused.

#### `direct-issuance`

A credential without rd whose schema forbids one (its top level lists no rd and closes with additionalProperties false) is committed by the digest seal {d} of its SAID in the issuer's KEL, and cannot be revoked; a seal naming its SAID in another shape is refused, and no seal leaves it unresolved. A credential without rd whose schema would admit one is not committed.

Why: ACDC line 1667 describes direct issuance with no registry, by a digest seal of the ACDC's SAID. sedi-1 otherwise commits a credential only through its registry, but SEDI's identity assurance receipt schema closes its top level without an rd, so it can only be issued directly (this.i 947dh20t).

Overturned by: A SEDI schema change that gives the identity assurance receipt an rd, or specification text that limits direct issuance.

This choice is decided in this.i `947dh20t`; security-relevant: getting it wrong admits what should be refused.

A schema that merely does not list `rd` leaves its top level open and admits one, so a credential under it that leaves out its `rd` is not committed: otherwise an issuer could put a revocable credential beyond revocation by dropping a field. A directly issued credential has one state, so it stays valid until its issuer's keys are compromised; whether SEDI's identity assurance receipt should be revocable is a question for SEDI, not for this profile.

#### `blind-derivation`

A blinded state's u is keripy's Blinder derivation: Argon2id with the event's sequence number in lowercase hex without leading zeros as the password and the 128-bit shared salt as the salt, at opslimit 2 and memlimit 64 MiB, giving 32 bytes encoded with the 256-bit salt code. A salt shorter than 128 bits is refused.

Why: The text says only that the blind is derived from a shared salt and the event's sequence number (lines 2077, 2133 and 2135) and names no derivation; keripy and heti derive it this way. Line 2282 requires the shared salt to have about 128 bits of strength, and the blind's secrecy rests on that salt, not on the stretch: without the salt an observer cannot test both states, so the low stretch cost is not what protects it.

Overturned by: Specification text naming another derivation, path encoding or cost, or allowing a salt below 128 bits.

This choice is decided in this.i `8g9vtxvc`; tracked as keri-sow tick `3b5o`; security-relevant: getting it wrong admits what should be refused.

No case exercises it yet (this.i `2c8nsmr7`). Its cases wait for the answer to the spec question 3b5o tracks, and checking a blind needs Argon2id at 64 MiB, so the derivation will be checked by the generator and an optional evidence tool, never by the runner. Until then sedi-1 stays draft.

#### `blind-state-code`

The count code of a big blinded-state group is the 8-character code, keeping quadlet alignment.

Why: ACDC lines 2062, 2145 and 2367 give a 9-character code, which breaks quadlet alignment; keripy uses 8.

Overturned by: An ACDC correction that keeps a 9-character code.

This choice is decided in this.i `8g9vtxvc`; tracked as keri-sow tick `3nch`.

#### `bulk-defaults`

Bulk issuance derives each blinding factor v_k at path 'k.', and concatenates in the CESR qb64 text domain with Blake3-256 as H, as ACDC main commit 9d80942 (pull request 200) states. Every bulk case is draft until a tagged specification carries the text.

Why: Section 15.4 at the tag contradicts itself on the v_k path and leaves H and the concatenation domain open; pull request 200 pins them and is merged on main.

Overturned by: A tagged specification whose bulk issuance text differs.

This choice is decided in this.i `43rj9wfc`; tracked as keri-sow tick `4xwz`.

No case exercises it yet (this.i `2c8nsmr7`): its cases wait for a tagged specification that carries the bulk issuance text.

### Seals and attachments

#### `seal-shape`

A seal anchoring a registry event is the couple {s, d}, or the event seal {i, s, d} whose i is the registry's SAID; an i naming anything else, an extra field and a bare digest are refused.

Why: ACDC line 1922 shows the couple {s, d}; heti and keripy's SEDI tests anchor with the event seal {i, s, d}, so sedi-1 widens line 1922 to accept it (this.i 2082s6k4). heti also accepts a bare digest, which sedi-1 refuses, so heti is expected to record a divergence there.

Overturned by: Specification text that admits a bare digest as an issuance seal, or that refuses the event seal {i, s, d} in that position.

This choice is decided in this.i `2082s6k4`; tracked as keri-sow tick `3nch`.

This widens the ACDC specification. Line 1922 of the pinned v1.0 text says the transaction event seal's JSON representation MUST be the couple `{s, d}`; sedi-1 also accepts the event seal `{i, s, d}` when its `i` is the registry's SAID, because heti writes that shape and it names its registry where the couple cannot (this.i 2082s6k4). An implementation that refuses the event seal is stricter than sedi-1 and conforms to the text; one that accepts it conforms to sedi-1.

#### `seal-couple-code`

The count code of a seal couple group is -S##.

Why: CESR lines 933 to 936 and keripy's 2.00 count-code table give -S##; ACDC line 1931 says -T##.

Overturned by: An ACDC correction that keeps -T##, with the CESR table changed to match.

This choice is decided in this.i `8g9vtxvc`; tracked as keri-sow tick `3nch`.

### Edges and operators

#### `edge-said`

An edge block must carry its own SAID in d, first in the block; an edge without d, or whose d is not the SAID of its block, is not valid.

Why: ACDC line 1154 makes an edge block's d optional and, when present, the SAID of its block; Daniel's answer to the profile interview, Q2, makes it required.

Overturned by: Specification text that makes an edge's d optional.

This choice is decided in this.i `8g9vtxvc`; tracked as keri-sow tick `3nch`.

#### `unknown-operator`

An edge operator outside I2I, NI2I, DI2I, E1E, AND and OR, including NOT, cannot be evaluated: the verdict is incomplete, never valid.

Why: Every unary operator narrows what satisfies an edge, so skipping an unknown one would apply a more permissive rule than the issuer wrote. NOT waits for 67i2.

Overturned by: Specification text saying a validator skips operators it does not know.

This choice is decided in this.i `8g9vtxvc`; tracked as keri-sow tick `3qah`.

#### `default-operator`

When an edge's o is absent or names none of I2I, NI2I, DI2I or E1E, I2I is appended if the far node has an issuee and NI2I if it has none.

Why: ACDC v1.1 (branch v1.1, spec-body.md line 1209) states this rule with E1E among the operators that suppress the default; the tag's line 1197 lists only I2I, NI2I and DI2I, and keripy's two verifiers disagree.

Overturned by: A specification that replaces the rule, such as with per-group defaults (keripy #1556).

This choice is decided in this.i `8g9vtxvc`; tracked as keri-sow tick `7kev`.

#### `operator-list`

An edge's o is a string naming one operator or a list of them; both are evaluated as the list.

Why: Lines 1186, 1199 and 1201 treat o as an effective list; keripy's verifier reads only a string.

Overturned by: Specification text restricting o to one form.

This choice is decided in this.i `8g9vtxvc`; tracked as keri-sow tick `6ljr`.

#### `operator-shape`

An empty o reads as an absent one and gets the default operator; among conflicting unary operators the latest wins, so [I2I, NI2I] is NI2I. An empty AND or OR edge-group and a nested list such as [[I2I]] are invalid.

Why: ACDC lines 1197 and 1186 settle the empty o and the conflicting list; the text says nothing of an empty group or a nested list, which sedi-1 treats as malformed instructions, not unevaluable ones.

Overturned by: Specification text that gives an empty edge-group or a nested operator list a meaning.

This choice is decided in this.i `599d5f5f`; tracked as keri-sow tick `6ljr`.

A list of contradictory unary operators relaxes to its latest member: `[I2I, NI2I]` reads as `NI2I`, so an issuer who lists both gets the weaker rule. sedi-1 takes that reading from the specification's own wording rather than refusing the list (this.i 599d5f5f), and a verifier must not apply the stricter operator instead.

#### `chain-strict`

A far node satisfies an edge only when its own sedi-1 verdict is valid, so a failed check or an unresolved item anywhere in the provenance DAG reaches the presented ACDC through every edge-group that needs it; an OR group needs one valid alternative.

Why: ACDC lines 1114 and 1116 make a far node's invalidity a MAY for its edge and leave the logic to the ecosystem governance framework (line 1112); SEDI reads its edges as provenance chains, so a credential is no better than what it chains to.

Overturned by: A SEDI governance framework rule under which an edge holds to a far node that is not valid.

This choice is decided in this.i `43rj9wfc`; security-relevant: getting it wrong admits what should be refused.

Every operator applies on top of it: `NI2I` drops the issuer relation, never the far node's own verdict, so an `NI2I` edge to a revoked credential is not valid.

### Presentation

#### `presenter-binding`

A presented ACDC is valid only when its presenter, the sender of the presentation's last exchange message, is its issuee a.i, or for an aggregate the issuee at A[1].i.

Why: Lines 312 and 344 make presentation by the issuee a capability, and no clause obliges a validator to check it; without the check, anyone who has seen a credential can present it as theirs.

Overturned by: Specification text making presenter binding an obligation in another form.

This choice is decided in this.i `09snlyre`; tracked as keri-sow tick `5u4y`; security-relevant: getting it wrong admits what should be refused.

The presenter is the sender of the presentation's last exchange message, which a case delivers as a grant naming the presented ACDC (this.i 7krs5hfz). The issuer is not the issuee, so an issuer presenting its own credential to a third party is refused.

#### `aggregate-issuee`

An aggregate credential's issuee is at A[1].i; an aggregate whose issuee is not disclosed cannot be bound, and a presentation of it is incomplete.

Why: keripy reads the issuee there (iseaid), though no builder writes it and the text leaves the position open.

Overturned by: Specification text pinning, or rejecting, A[1].i as the aggregate issuee's home.

This choice is decided in this.i `09snlyre`; tracked as keri-sow tick `5oo6`.

#### `bearer-untargeted`

An ACDC with no issuee is a bearer credential: anyone holding it may present it, and the profile says so.

Why: The text defines untargeted ACDCs and no presenter they could be bound to.

Overturned by: A SEDI policy that forbids untargeted credentials in its schemas.

This choice is decided in this.i `09snlyre`; security-relevant: getting it wrong admits what should be refused.

An untargeted credential is a bearer credential: whoever holds it may present it, and no presenter check applies. A SEDI schema that must not be presented by just anyone has to name an issuee.

#### `issuer-issues`

An issuer issues exactly the credentials a request asks for, each under a blindable registry of its own, with its own keys, salts and clock; it refuses, and never issues something else, a request whose attributes a credential's schema does not allow once the issuer has added the block's d, u and i, or whose edges cannot hold as the request's roles issue the credentials.

Why: An issuance is the first link of every chain a verifier checks, and an issuer that issues what its schema refuses or an edge that cannot hold puts into circulation a credential no correct verifier accepts (test-plan item 4).

Overturned by: A SEDI decision to let an issuer amend a request it cannot issue as asked.

This choice is decided in this.i `2u2ps8mt`; security-relevant: getting it wrong admits what should be refused.

#### `holder-presents`

A holder presents exactly the disclosure asked for: the held ACDC's top-level SAID, each block the disclosure names expanded and every other block compacted to its SAID or, in an aggregate, left as its blinded SAID, and nothing the disclosure hides. It refuses, and never presents something else, when a verifier would refuse the ACDC or the ACDC cannot satisfy the disclosure: a path or label that names nothing, names a block held only compact, or is named twice, and an empty choice.

Why: Graduated and selective disclosure are the holder's side of ACDC's disclosure model, and the profile tests a holder as well as an issuer and a verifier (test-plan item 5); without a rule, a holder could present more than it was asked to, or a credential a verifier refuses.

Overturned by: A SEDI decision to let holders choose the disclosure form themselves.

This choice is decided in this.i `3lq4zrr3`; security-relevant: getting it wrong admits what should be refused.

### Grading

#### `unresolved-grading`

A verdict is graded three ways: invalid when a check failed, incomplete when something the verdict needs is absent or cannot be evaluated, and never valid in either case.

Why: Utah's KERI-012 asks for positive, negative and unresolved outcomes, which a relying party acts on as accept, reject and retry; acdc-v1.0 leaves the distinction informative.

Overturned by: None from the specification: this is how SEDI reads a verdict.

This choice is decided in this.i `8fh68wt6`.

`incomplete` is never an accept, provisional or otherwise. It says the verifier could not decide, and a relying party treats it as a refusal until it has the missing evidence.

#### `bounds`

A credential holds at most the profile's maxima: 64 events in its registry, 32 attribute blocks in an aggregate, edge groups nested 8 deep counting the edge section, 8 operators in one o list, 4096 bytes in one attribute value (a string's UTF-8, anything else's compact JSON), and 44 characters in any u, the longest primitive a u holds (a 256-bit blinding factor, code a), measured by its size whatever its type. Every maximum is checked on the whole credential, so no alternative an OR group did not need can hide one. A credential past a maximum is not a sedi-1 credential and is never valid; a verifier may refuse it as invalid or decline to evaluate it as incomplete, and must not hang on it.

Why: Without stated maxima a verifier's work on a hostile credential is unbounded, and two verifiers that pick different limits disagree about the same credential (test-plan item 13).

Overturned by: A SEDI credential that legitimately needs more than a maximum, which raises it in a new profile version.

This choice is decided in this.i `7qx6tl5p`; security-relevant: getting it wrong admits what should be refused.

#### `failure-precedence`

When a bundle holds both a failed check and something that cannot be evaluated, the verdict is invalid.

Why: Otherwise adding an unknown operator to a forged credential would turn a reject into a retry.

Overturned by: None from the specification.

This choice is decided in this.i `3g4le6js`; security-relevant: getting it wrong admits what should be refused.

#### `valid-is-interop`

Accepting a valid ACDC is graded at INTEROP, so an implementation that refuses everything fails the profile.

Why: acdc-v1.0 grades acceptance as an inferred SHOULD; without this, an adapter answering incomplete or invalid to everything would pass every sedi-1 refusal.

Overturned by: None from the specification.

This choice is decided in this.i `8fh68wt6`.

#### `no-1x`

Under sedi-1, a 1.x version string, a 1.x field set or a 1.x registry is never valid; sedi-1x-interop grades 1.x on its own.

Why: Otherwise a credential revoked in its 2.00 registry could be re-presented in its 1.x form.

Overturned by: A SEDI decision to accept 1.x credentials under sedi-1.

This choice is decided in this.i `3g4le6js`; security-relevant: getting it wrong admits what should be refused.
