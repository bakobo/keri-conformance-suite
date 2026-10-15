# Results

This directory holds the conformance results the suite's site publishes. Each is a report written by `kcs run --report`, unchanged, inside a provenance envelope, at `<implementation>/<version>/<profile>.json`. It holds two kinds:

- `maintainer-run`: the adapters shipped in `adapters/`, run at their pins by the suite's maintainer from the suite commit each result names. `scripts/reproduce-results refresh` writes them and `scripts/reproduce-results check` reruns and compares them; never edit one by hand.
- `submitted`: results that implementation maintainers sent by pull request. The site shows each as its submitter's claim, which the suite has not reproduced.

A file labelled `reproduced`, the label kept for a GitHub Actions run of this repository, is refused here.

How to submit a result, how the shipped adapters' results are kept current, and what the checks are, is in [`docs/publishing-results.md`](../docs/publishing-results.md).
