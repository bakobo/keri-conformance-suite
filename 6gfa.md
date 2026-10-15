# keriox (keri-core 0.17.13) takes a copy of an already-seen event whose controller signature does not verify: process returns Ok, the copy goes to the duplicitous escrow, and its bad signature is logged beside the event's genuine one, so get_event_at_sn returns both. KERI v1.0.1 line 1266 says a message without a verifiable controller signature MUST be dropped. The keriox adapter reads such a copy as seen because that is what keri-core holds; pinned by adapters/keriox/tests/process.rs keri_core_takes_a_copy_of_a_seen_event_with_a_bad_signature_as_the_event. Raised by codex's hostile pass on PR #39; worth reporting to THCLab with ~3bpx.
kind: todo
created: 2026-10-15T12:18Z

