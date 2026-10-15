# keri.process fixtures

Test inputs for `tests/process.rs`. They are not suite cases: no expected verdict here is normative, and the tests pin what keri-core 0.17.13 does with each one, including where that differs from keripy. Each file is KERI 1.0 JSON with CESR 1.00 attachments, one or more messages concatenated; the tests split them before each body.

| File | Made by | What it holds |
|---|---|---|
| `kel-basic.cesr`, `kel-nontrans.cesr`, `kel-partial-rotation-unsatisfied.cesr`, `kel-weighted-multisig.cesr`, `kel-delegator.cesr`, `kel-delegate.cesr`, `kel-delegated-replay.cesr`, `kel-witnessed-underreceipted.cesr`, `kel-duplicitous.cesr`, `kel-recovery.cesr`, `kel-bad-signature.cesr` | keripy 1.2.14 (commit `bab95c16`), from fixed salts | The KEL items of the 2026-09 Rust survey's interop corpus (`keri-sow/.ignored/rust-survey/interop/corpus/keripy-1.2.14/`, generator `interop/gen/gen_corpus.py`), copied unchanged |
| `validator-icp.cesr`, `vrc-basic-icp.cesr` | keripy 1.2.14, from fixed salts, with the survey's `kcompat` helpers | A second identifier's inception, and that identifier's transferable receipt (`rct` with a `-F` group) of the inception in `kel-basic.cesr` |
| `keriox-witnessed-rct.cesr` | keri-core 0.17.x builders and signers (survey artifact `gen-kel-witnessed-rct`) | A KEL with three witnesses and `bt` 2: each event carries only its controller signature and is followed by an `rct` with `-C` couples from all three witnesses. keripy 1.2.14, 1.3.6 and main accept it |
