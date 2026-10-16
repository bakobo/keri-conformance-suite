# Decide whether a caught library exception counts as a crash for the embargo (Q-YSWY)
kind: todo
tags: disclosure
created: 2026-10-16T21:30Z

- 2026-10-16T21:30Z The disclosure text from PR #60 (docs/design.md Security, SECURITY.md) embargoes a crash, hang or memory-safety fault on hostile input and publishes everything else. It does not say whether an exception the caller catches is a crash. Live case: cesrixir raises an Elixir CaseClauseError on some CESR streams; the adapter reports it as a case failure and it is published (Q-SQV3). Answer 'failure' keeps the text and results as they are; answer 'crash' means amending both docs and pulling those cesrixir cells.
