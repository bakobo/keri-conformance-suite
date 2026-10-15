# sedi-1 test plan

This is the plan for building and testing `sedi-1`, SEDI's deployment profile, and the `sedi-1x-interop` companion. It answers Utah's KERI-001 (a versioned support profile for KERI, CESR, ACDC, registry events, seals and IPEX, with vectors agreed across issuer, holder and verifier) and KERI-012 (positive, negative and unresolved verification outcomes, and reproductions of nested-edge defects). The decisions it rests on are the goal "SEDI can claim interoperability under a versioned deployment profile" in `this.i` and its children: 8g9vtxvc (the profile picks where the spec is silent), 43rj9wfc (the 2.00 wire), 63v08x06 (one corpus read three ways), 8fh68wt6 (unresolved graded apart from invalid), 3g4le6js (a holder-assembled bundle never proves more than it carries), 09snlyre (the presentation context) and 3lq4zrr3 (the suite grades a holder, not the holder's verifier).

Every requirement below gets a failing test before the code that satisfies it. New runner and generator code is held to 100% branch coverage, and item 15 adds the evidence that coverage cannot give.

## Rules that apply to every item

- **Positive pairs.** Every refusal, `incomplete` or `invalid`, has a positive twin that differs from it only in the defect, as in the rest of the suite.
- **Grading.** sedi-1 grades `valid` at INTEROP on every positive. Otherwise an adapter that answers `incomplete` or `invalid` to everything passes, because acdc-v1.0 grades `valid` only as an inferred SHOULD.
- **Oracles.** A case whose output is deterministic declares `oracle: bytes`, and a generator check enforces it. A case may grade by verdict only when the bytes cannot be fixed, and then the verdict comes from the suite's own model (3lq4zrr3).
- **Determinism.** Every seed, salt, stamp and KDF parameter is fixed in the scenario. `regenerate --check` covers the cases, the profile manifest and `generators/DISAGREEMENTS.md`.
- **Embargo.** The suite's embargo rule (5cz9hck0) applies before anything reaches this public tree. Every sedi-1 and sedi-1x-interop case carries a triage line stating its security consequence. A case that has one is run first against every adapter in the private mirror. It moves to the public tree only when no released implementation fails it. heti counts as a released implementation, even though Bakobo builds it. The same gate covers `DISAGREEMENTS.md` entries, defect reproductions and spec-question drafts.

## 1. The profile manifest and the claim

- `profiles/sedi-1.json` is generated from a scenario file, and `regenerate --check` fails on drift. The manifest declares:
  - its version and its prerequisite profiles (`cesr-v1.0`, `keri-v1.0.1`, `acdc-v1.0`, whose `keri-v1.0.1` carries the exchange-message cases KERI-0068 to KERI-0083);
  - the suite version and each spec commit it pins, by full hash;
  - the features an adapter must declare, its choices, and its maxima (item 13).
- The runner refuses a sedi-1 claim unless the prerequisites' MUSTs passed in the same run. A table-driven test crosses each prerequisite outcome (pass, fail, incomplete, no-evidence, not run, or passed only in an earlier run) with each sedi-1 outcome. It asserts the exact claim text and exit code for every cell.
- The report prints the prerequisite verdicts and the sedi-1 verdict separately. A string test asserts that a sedi-1 verdict never prints as "conforms".
- The report prints the profile version. Beside every `valid` SEDI verdict it also prints the registry head (`n`, `d`), because a verdict on a holder's bundle holds only as of that head.
- A run that passes `sedi-1x-interop` but not `sedi-1` prints no sedi-1 claim, and one report never merges the two verdicts.
- `CODEOWNERS` covers `profiles/sedi-*.json` and `docs/profiles/sedi.md`, so a version change gets Daniel's ratification through review rather than memory.

## 2. Profile choices and versioning

- Every choice has an id, a reading, a basis, an overturning condition and the keri-sow tick that tracks the ambiguity.
- A generator test refuses any SEDI case whose assertion rests on neither a choice nor a clause.
- A choice-to-case matrix is generated from the scenario file. Every choice must name at least one positive case id and one negative case id. While the profile's version is draft, the generator lists every empty side; it refuses to make a version active with one (this.i 47yreej2), so the profile can land in steps without hiding the gap. The minimum per choice:
  - 57ud: n+1 accepted; a gap, a repeated n, and n+2 after a `bup`.
  - 5qcy: a single anchored head accepted. Neither a higher event that is not anchored nor a higher event whose chain is broken becomes the head, and neither leaves the verdict valid: under registry-evidence (3g4le6js) the first makes it `incomplete` and the second `invalid`. An unanchored event at the head's own n is ignored. Two events anchored at one n are refused.
  - 3b5o: the Blinder derivation accepted; a different path radix, an uppercase hex path and a wrong stretch tier are refused. The choice record states the KDF parameters, the entropy floor of the KDF's input and the reasoning for both. Its overturning condition includes a cost floor. The issuer refuses an empty salt, a salt below the floor, and one salt reused across two credentials. The spec-question draft for 3b5o argues strength as well as bytes.
  - 4xwz: a credential using the defaults accepted and one deviating refused. All of these cases are drafts.
  - 3nch: one pair each for `-S##` versus `-T##`, the 8-character group code, the seal shape (the `{s,d}` couple and the `{i,s,d}` event seal with `i` the issuer accepted, per 2082s6k4), and edge `d` required.
  - 3qah: an unknown operator gives `incomplete`.
  - 7kev: an absent `o` gives the v1.1 default. An explicit `o` that differs from the default changes the verdict.
  - 6ljr: `o` as a scalar, a one-element list, a multi-element list and an empty list.
  - 5u4y: presenter equals `a.i`; presenter differs; presenter equals `i` but not `a.i`.
  - The 3g4le6js and 09snlyre choices: their own cases, in items 5, 6 and 9.
- Changing a choice's reading without bumping the profile version fails CI.
- Version bumps get their own tests. A fixture defines `sedi-1` and a synthetic `sedi-2` that differs in one choice. The tests assert that `sedi-1.json` stays byte-identical, and that one adapter's verdicts change on exactly the cases tied to that choice.
- A released profile file is immutable: its hash is recorded, and any change outside a listed set of metadata fields fails CI.
- A claim naming an unknown profile version exits with its own error code, not 0 and not no-evidence.
- A pinned spec commit that disagrees with the clause commits of the profile's cases fails the profile build.

## 3. Adapter protocol for the new operations

- `schema/adapter-protocol.schema.json` gains `acdc.issue` and `acdc.present`, and an optional presentation context on `acdc.verify` (the grant exn stream and the verifier's AID, per 09snlyre). It also gains the holder's refusal result, `{"refused": {"reason": …}}`.
- Valid and invalid fixtures for every new request and result shape are run through the Python validator and one non-Python validator.
- The feature vocabulary gains `acdc.presentation` (this.i 4xw8k0hg), and `acdc.registry.upd`. The two new operations need no feature, because the runner sends a case only to an adapter that lists its operation. A case the adapter is not sent leaves its profile's share of a claim at best `incomplete`; it is never silently skipped.
- New `kcs check-adapter` probes:
  - Malformed `acdc.issue` and `acdc.present` requests, an unknown disclosure choice, and a malformed presentation context each get an error response, not a crash.
  - A mock adapter that crashes on a malformed request fails check-adapter.
  - Two identical `acdc.issue` requests return identical bytes.
  - `acdc.present` does not depend on an earlier `acdc.issue`.
  - The response id is echoed.

## 4. Issuer vectors (`acdc.issue`)

- **Positive cases.** IAR, Core, Residence, Age (`acg`) and Guardian under a `bup` registry, which is the only registry sedi-1 requires (8dgunr0e). A `upd` issuance is sent only to an adapter declaring `acdc.registry.upd`. The generator's bytes are cross-checked against Sam's `test_sedi.py` literals, pinned by full keripy commit and file digest.
- **DISAGREEMENTS.md** is tested in both directions: every literal is either equal or listed, and every listed literal still differs.
- **Negative cases**, each refused rather than issued:
  - `a.dt` emitted where SEDI forbids it (G17 #8);
  - unsaidified nested blocks;
  - a wrong registry n;
  - a seal in the wrong shape;
  - an empty salt;
  - a non-hex seed;
  - an attribute containing a NUL or non-ASCII where the schema forbids it;
  - an invalid stamp.
- **Signatures.** The runner checks them only against the keys of the case's stated establishment event. A stub adapter signs with a pre-rotation key, with a key not in the KEL, with the right key over a different body, and with an index past the key list; each must fail. `emitted_body` and `signatures_verify` are scheduled in this item, and until they land, issuer results are `incomplete`, never passing.

## 5. Holder vectors (`acdc.present`)

- **Coverage.** Each disclosure variant (compact, partial, selective, aggregate) of each SEDI credential is a case. A case is graded by bytes wherever disclosure is deterministic, and otherwise by the suite's model.
- **Binding.** Every presentation must carry the full form's top-level SAID, and its disclosed blocks must recompute to the SAIDs or AGID the case expects. A different SAID fails, whatever the verdict.
- **Leak canaries.** One case per variant per credential. The case lists every secret the disclosure hides: hidden attribute values, their salts `u`, undisclosed blinded state, and the issuee block when it is hidden. The runner fails the case if any of them appears in the response raw, as hex, Base64, Base64url or JSON-escaped.
- **Refusals.** A holder must refuse each of the following with the refusal shape, never with a partial presentation:
  - each negative verifier case;
  - a disclosure the schema does not permit, such as selective disclosure of a block that is not blinded;
  - a path that names no field;
  - a path into a block held only in compact form;
  - a field named twice;
  - an empty choice;
  - a revoked credential;
  - a bundle missing the issuer's KEL.
- **Self-test.** A stub whose `acdc.verify` always says `invalid` and whose `acdc.present` returns noise must fail.

## 6. Verifier, the SEDI layer

- **Registry**, per 3g4le6js. Each case has its positive pair, and none may grade `valid`:
  - n=2 withheld with a revoking n=3 present;
  - n=2 withheld, no n=3 present, but a third registry event sealed in the issuer's KEL;
  - an anchored blinded update whose state is undisclosed, after an `issued` state;
  - a revoking event anchored in an issuer event that a recovery rotation superseded, which counts neither as anchored nor as the second of two events at one n;
  - a revoking event anchored past the bundle's KEL cut;
  - a head that mixes `upd` and `bup`;
  - a `vcp` registry in a sedi-1 bundle, which is `incomplete` as an unsupported kind;
  - an adapter declaring `upd` but not `bup`, which fails the `bup` cases and is not skipped on them.
- **Revocation** is a profile choice: revoked is `invalid`, with its pair. A revoked middle node of a two-hop chain makes the head not valid under chain-strict propagation.
- **Seals.** Each refusal has its positive pair:
  - a bare digest is refused. heti accepts one, so its baseline is expected to record the divergence;
  - the `{s,d}` couple and the `{i,s,d}` event seal with `i` the issuer are both accepted, which widens ACDC line 1922 (2082s6k4);
  - an `{i,s,d}` seal whose `i` is not the issuer is refused;
  - a seal with an extra field is refused;
  - a seal whose `d` does not match is refused;
  - an `s` naming an absent event is `incomplete`;
  - an anchoring event of a type that may not anchor (7skf) is `invalid`.
- **Edges.** Each defect case has its positive pair:
  - edge `d` absent;
  - edge `d` present but wrong;
  - edge `d` equal to the far node's own SAID where it should not be.
- **Operators.** The SEDI set over one-hop and two-hop chains and diamonds, with AND and OR groups. Operator-shape cases, each with a positive pair:
  - unknown members are `incomplete`: `[I2I, XYZ]`, `[1]`, `o` as an object;
  - an empty AND, an empty OR and `[[I2I]]` are `invalid` (choice operator-shape, 599d5f5f);
  - `o: []` reads as an absent `o` and `[I2I, NI2I]` as `NI2I`, as ACDC lines 1197 and 1186 say, each with a case that fails only if the shape is graded otherwise.
- **Exclusions**, from 43rj9wfc, each with its JSON, Ed25519 or Blake3 twin:
  - a CBOR or MessagePack ACDC;
  - a non-Ed25519 signature;
  - a non-Blake3 SAID;
  - `NOT` in a schema (`incomplete`);
  - a Merkle batch seal (`incomplete`).
- **Bulk drafts.** A failing draft bulk case is reported but does not change the exit code.
- **1.x forms**, per 3g4le6js: the 1.x form of each SEDI credential; a 1.x version string over a 2.00 body; a 2.00 version string over a 1.x body; a 2.00 ACDC whose `rd` names a `vcp` registry. None is ever `valid` under sedi-1.
- **KERI and CESR.** sedi-1 adds two kinds of case beyond its prerequisites:
  - an issuer key rotation between issuance and verification, where the verdict uses the key state at the anchoring event, both ways;
  - a parse case for the SEDI attachment group code, with a wrong-count negative.
  Everything else in KERI and CESR is the prerequisites' job, and `docs/profiles/sedi.md` says so.
- **Importer.** The importer refuses a KEL whose next-key digest field holds a raw key (the `ndigs` defect in Sam's KELs) with a named error.

## 7. IPEX practice cases

The exchange-message cases in `keri-v1.0.1` are a sedi-1 prerequisite. On top of them, INTEROP cases with a cited basis, each with its positive pair:
- a grant embedding an ACDC with the issuer's KEL attached;
- a grant and admit pair whose `p` matches;
- an admit naming the wrong grant;
- a grant of a revoked credential, which is not valid;
- a grant whose sender is not `a.i` (5u4y, through the presentation context).

The apply, offer and agree messages are out of scope for sedi-1 v1, and `docs/profiles/sedi.md` says so. The case that a grant cannot carry a revocation chain (2dxo) is recorded as a known gap, citing its tick.

## 8. Verdict cases (the `verdict-cases` item)

- **Triples.** Each unresolved cause gets three cases: the complete bundle (`valid`), the same bundle with the one item removed (`incomplete`), and the same bundle with the item present but corrupted (`invalid`). The causes are a missing KEL, registry event, far node or schema; an unknown operator; an unsupported registry kind; and an undecidable edge.
- **Precedence**, per 3g4le6js. Each `incomplete` cause is combined with a broken SAID, a revocation and a failed `I2I`, and each combination expects `invalid`.
- **KEL state.** A KEL with a gap, a stale KEL (evaluation point before the anchor), and an absent KEL each map to their stated verdicts.
- **Always-X self-tests.** Three adapters, always-valid, always-invalid and always-incomplete, each fail sedi-1. The same test asserts that acdc-v1.0 passes always-invalid and always-incomplete at MUST, so the difference between the two profiles stays visible.
- **Nested-edge defects** are enumerated, each with its own case id and positive twin:
  - a far-node SAID mismatch at depth 2;
  - a schema mismatch at depth 2;
  - a missing far node at depth 2 (`incomplete`);
  - an edge `n` naming something that is not a credential;
  - a diamond with one invalid branch, under AND and under OR;
  - an OR whose first alternative is unresolved and whose second is valid;
  - a cycle;
  - the depth bound exceeded;
  - each of I2I, NI2I, DI2I and E1E on a nested edge group;
  - an aggregate far node whose issuee is blinded (5oo6).
  A case may name an implementation's test or ticket as the source of its defect. Its expected verdict comes from the operator rules and chain-strict propagation, never from what an implementation outputs.

## 9. Presenter binding and replay

These cases use the presentation context (09snlyre), and each has its pair:
- the grant sender is not `a.i` but signs validly;
- the grant is signed with `a.i`'s pre-rotation key after a rotation in the bundle;
- the grant comes from a delegate of `a.i`;
- the grant's `p` chains to a transaction begun by a different verifier AID;
- the same grant is delivered twice, with the expected outcome stated;
- an aggregate credential bound at `A[1].i`, and one whose issuee is undisclosed (`incomplete`);
- an untargeted credential, which is reported as a bearer credential.

## 10. Cross-role agreement

For each issue vector, the evidence pack verifies adapter A's `acdc.issue` output with every other adapter's `acdc.verify`. It does the same for each presentation. Every cell must be `valid` for a positive case, and every verifier must refuse an issuer negative case. This matrix is deterministic, offline and reported per cell. It belongs to the evidence pack and is not a graded profile assertion.

## 11. The 1x companion (`sedi-1x-interop`)

- Each G17 incompatibility recorded in `interop/two-wallets/RESULT.md` (7, 8, 10 and 11) becomes a case with a positive twin, at INTEROP, with basis sedi-1x. The companion runs against the keripy 1.x and signify-ts adapters.
- A cross-version revocation case covers one claim issued in both forms and revoked only in 2.00. `docs/profiles/sedi.md` states that migration requires revoking both forms, unless a 1x verifier can be expected to see the 2.00 registry.
- A runner test asserts that a `sedi-1x-interop` failure leaves the sedi-1 verdict unchanged.

## 12. The heti adapter (inline in `profile`, tick ~3c6x)

- The adapter lives in `adapters/heti/`. It is pinned to a heti commit by full hash, with a dependency lockfile, uses heti's public API only (93t4d880), and builds in the no-secrets CI tier.
- It implements `acdc.verify` (with the presentation context), `acdc.issue` and `acdc.present`. `kcs check-adapter` passes with the item-3 probes.
- Its expected sedi-1 baseline is a reviewed artifact, not a snapshot. It lists the cases heti fails by design (it accepts a bare digest as a seal, and it refuses operators outside its SEDI pins with `EDGE_BEARING`; it issues only `bup`, which sedi-1 no longer counts against it, per 8dgunr0e), with a tick for each. CI fails on a change to the baseline, not on a failure the baseline already lists.
- No baseline line is written until the embargo gate above has cleared its case, and the baseline tool refuses to write a line for a case on the embargo list.
- A commit-range check asserts that adapter commits touch nothing under `cases/`.

## 13. Bounds

- **Runner side.** Before any signature is verified, every new response field is checked for count and size. A stub that returns a maximum-size response stuffed with signature groups must be failed within a stated runner time.
- **Implementation side.** sedi-1 states maxima for:
  - registry events per registry;
  - attributes per aggregate;
  - edge-group nesting depth;
  - `o` list length;
  - attribute value and salt size.
  Cases sit at each maximum and just above it. The just-above cases are marked beyond-bound under a case-schema exemption that applies only to them. They expect a verdict other than `valid` and never a hang, and the anything-but-an-answer rule already fails a hang.

## 14. The prose profile

`docs/profiles/sedi.md` states every choice, and it says:
- that `incomplete` is never an accept, provisional or otherwise;
- that a `valid` verdict holds only as of the reported registry head;
- that relying parties should source registry state from the issuer's witnesses or a watcher, not from the presenter;
- that untargeted credentials are bearer credentials;
- that expiry is the relying party's check, so `valid` does not mean unexpired;
- what sedi-1 does not add to KERI, CESR and IPEX beyond its prerequisites.

## 15. Mutation acceptance

For each profile choice, a deliberately wrong variant of the reference model is run through the suite. Examples are n+2, accepting either seal shape, scalar-only `o`, and an unchecked presenter. Each variant must fail at least one case tied to its choice, and the choice-to-case matrix records which. Branch coverage shows that code ran. This step shows that the cases would catch a broken verifier.
