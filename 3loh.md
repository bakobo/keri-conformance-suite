# maintainer-run provenance is vouched for only by pull-request review: nothing checks that the named maintainer ran the adapter or that the named commit produced the report. Options: CODEOWNERS on results/ so a maintainer-run change needs the maintainer's approval, a signed attestation per result, or a CI step that reruns a sample on demand. Raised by the codex hostile pass on the ci-split PR (#32).
kind: todo
created: 2026-10-15T06:31Z

- 2026-10-15T06:44Z Also covers: _missing (tools/reproduce.py) matches adapter and profile, not implementation version, so a hand-supplied result at another version can stand in for a deleted shipped one (codex fix pass and the ds seat on #32, both). refresh never produces that state, since it removes superseded versions; pinning each build's expected implementation identity in INSTANCES would close it at the cost of a second place to update pins.
