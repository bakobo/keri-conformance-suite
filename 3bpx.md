# keriox (keri-core 0.17.13) accepts a delegated rotation without its delegator's anchoring seal: EventData is an untagged serde enum with Rot before Drt, so every drt body deserializes as a plain rot and EventValidator::validate_seal never runs for it (KERI v1.0.1 line 1612). Pinned by adapters/keriox/tests/process.rs keri_core_accepts_a_delegated_rotation_without_its_anchoring_seal. A 1.x keri.process case with a drt whose anchoring event is never delivered would show it as a MUST failure; worth reporting to THCLab.
kind: todo
created: 2026-10-15T05:37Z

