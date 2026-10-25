# G17 result: two wallets, one credential, one holder moving between them

Run of 2026-10-12, pins in [README.md](README.md). This is an observation of pinned implementations on one day, not a conformance claim.

## What was shown

A SEDI-shaped ACDC (the SAM core identity schema, reshaped at the top level for KERI 1.x and with its attribute section unchanged) was issued over KERIA by a signify-ts issuer and held by Veridian's own wallet core. The holder then moved to heti without the issuer doing anything. Both wallets presented the same credential to one verifier, from the same holder AID:

- The holder left Veridian through Veridian's own export: the recovery phrase, the bran recovered from it, the AID's sealed salt from Veridian's local metadata, and the credential stream from the holder's KERIA agent. heti's KERI 1.x bridge (heti `src/heti/anchored/interop/keri1.py`) re-derived the AID's keys exactly as signify-ts does. It adopted the AID only after checking that those keys incepted the KEL its witnesses serve. It then verified and held the credential and signed a 1.x `/ipex/grant`. The harness delivered heti's bytes unchanged. KERIA accepted the grant, and its admission was the verifier's first sight of the credential. KERIA then held the credential with `iss` status (`out/m3-heti.json`).
- Veridian then presented through its own apply, offer, agree and grant flow. KERIA logged the grant after verifying its signatures; the verifier checked its holder sender and embedded credential, admitted that grant, and verified that KERIA logged the admit exchange with `p` naming Veridian's grant (`out/m3-veridian.json`). Veridian's own KERIA agent then received that admit (`out/m3-veridian-admit-check.json`). M4 requires both for Veridian's presentation.
- There was no reissue. The issuer's registry lists one credential, and its TEL holds a single `iss` at sequence number 0 (`out/m4.json`).

heti's grant also verifies under stock keripy 1.x's `Exchanger` (heti `tests/interop/test_keri1_present.py`). That test's fixtures are the live run's bytes, not anything heti produced.

## What it does not show

The wallets are less independent than two names suggest. Veridian rests on signify-ts and KERIA, and KERIA is built on keripy. heti is built on a keripy fork. Both stacks therefore share keripy at the core, and agreement between them is weaker evidence than agreement between unrelated codebases would be. The only separately written KERI implementation available to Bakobo, affinidi-keri-rs, covers KERI and not ACDC, so it could not take part.

The migration is one-way and incomplete:
- heti can adopt an AID from Signify. KERIA has no way to adopt an AID that another wallet created, so the reverse move was not attempted.
- heti refuses an AID that has already rotated.
- After the move, both wallets hold live keys for the AID until one of them rotates it. heti cannot yet rotate an adopted AID.
- The AID's published endpoint still names Veridian's agent. heti can therefore present, but the verifier's admit receipt goes to Veridian and is refused there (incompatibility 14).
- KERIA delivered the admit for Veridian's own grant to Veridian's holder agent, but Veridian's core filters the `/exn/ipex/admit` route, so its notification store never surfaced the receipt (`out/m3-veridian-admit-check.json`, incompatibility 18). M4 shows the receipt reached Veridian's agent and makes no claim that Veridian's core processed it.

Some of Veridian's behaviour on a SEDI credential needed runtime workarounds, scoped to this one schema, in the headless driver (incompatibilities 10, 11 and 13). The claim is that Veridian's core holds and presents the credential *with those three assumptions bridged*. Veridian's source and the credential bytes were not changed.

## Incompatibilities between the stacks

These are the deliverable. Each one is filed where its owner tracks work. Entries in [INCOMPATIBILITIES.md](INCOMPATIBILITIES.md) carry the evidence.

| # | What | Owner | Filed |
|---|---|---|---|
| 7 | Every published SEDI schema is a KERI 2.0 shape (`t`, required `rd`, `e`, `r`), so a 1.x wallet cannot hold a SEDI credential without a 1.x profile of the schema | SEDI schema publication | this writeup; schema profile in `schemas/` |
| 8 | keripy 1.x's issuer always inserts `a.dt`, which a SEDI attribute section forbids, and signify-ts `credentials().issue` inherits the convention, so KERIA refuses the issuance. Both leave nested disclosable blocks unsaidified | keripy 1.x's issuer, inherited by signify-ts | `sedi-1x-interop` case ACDC-0282 (SX-08); a draft for Daniel addressed to signify-ts alone, not posted, which names the wrong owner |
| 10 | Veridian resolves every optional edge definition as a mandatory child schema, which SEDI's optional and group edges cannot satisfy | Veridian | bakobo/veridian-wallet tick `2pgd` |
| 11 | Veridian assumes every ACDC has `a.dt` and fails on admit without it | Veridian | tick `6dat` |
| 13 | Veridian's apply and agree handling looks for an indexer OOBI and fails when the counterparty has none | Veridian | tick `7g2n` |
| 14 | After migration the AID's only agent end role still names the old wallet's agent, so replies to the new wallet go to the old one | heti (publish an end role for an adopted AID) | heti tick `2flw` |
| 18 | Veridian's core filters `/exn/ipex/admit` notifications even when its KERIA agent receives one | Veridian | this writeup |
| 15 | No wallet export carries a credential's signed evidence, so moving it needs the old KERIA agent online | Veridian and KERIA | Veridian tick `3sms` |
| 3 | Veridian's notification pollers cannot be stopped | Veridian | tick `4wip` |
| — | Two wallets hold live keys for a migrated AID until it is rotated from the new one | heti | heti tick `3yi6` |
| — | keripy fork: a 1.x Hab rotates with a 2.0 event | bakobo/keripy | heti tick `7e4u` |
| — | keripy fork: `messagize(framed=False)` and `replay` frame 1.x events with 2.0 count codes | bakobo/keripy | heti tick `6b2k` |
| — | keripy fork: the 1.x parser drops a message it cannot read without raising, so a caller can take a truncated KEL or TEL for a complete one. heti's bridge guards against this; other 1.x consumers of the fork do not | bakobo/keripy | heti tick `6mrl` |
| — | heti's grant puts the recipient in `a.i` (keripy's `ipexGrantExn`), while signify-ts puts it in `rp`. KERIA delivered and admitted it regardless | none needed today | noted |

Entries 1, 2, 4, 5, 6, 9, 12, 16 and 17 in INCOMPATIBILITIES.md are seams in this harness (Docker mounts, Node shims, process lifecycle, call ordering), not disagreements between the wallets. They are recorded so that the run can be reproduced.
