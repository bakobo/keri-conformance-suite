# Submitted results

This directory holds conformance results that implementation maintainers have submitted by pull request. Each is a report written by `kcs run --report`, unchanged, inside a provenance envelope, at `<implementation>/<version>/<profile>.json`. The site shows every one of them as its submitter's claim, which the suite has not reproduced.

Results this repository's CI reproduces are not committed here: the Pages workflow runs the shipped adapters and writes them at build time. A file here that is labelled reproduced is refused.

How to submit a result, and what the checks are, is in [`docs/publishing-results.md`](../docs/publishing-results.md).
