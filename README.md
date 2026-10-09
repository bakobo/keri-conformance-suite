# keri-conformance-suite

[![CI](https://github.com/bakobo/keri-conformance-suite/actions/workflows/ci.yml/badge.svg)](https://github.com/bakobo/keri-conformance-suite/actions/workflows/ci.yml)

A conformance suite for implementations of [CESR](https://github.com/trustoverip/kswg-cesr-specification), [KERI](https://github.com/trustoverip/kswg-keri-specification), [ACDC](https://github.com/trustoverip/kswg-acdc-specification) and IPEX.

Each test case is a fixed input together with assertions that do not depend on any implementation: for CESR, the decoded structure or a rejection; for KERI, what a validator does with each message (accepts it, holds it pending, rejects it, records it as duplicitous) and the resulting key state; for ACDC, whether a credential bundle is valid, revoked, invalid or incomplete; for IPEX, whether each exchange message is well-formed, signed and correctly referenced. Every assertion cites the specification clause it tests. An implementation shows conformance by running the cases through a small adapter and satisfying every MUST assertion.

**Status: incubating.** The case format, the adapter protocol and the first cases are being designed now. The suite is developed at [Bakobo](https://bakobo.com) with the intention of contributing it to the KERI Foundation.

## Who this is for

**If you maintain an implementation** and want to show it conforms, you will write an adapter: a small program that lets the runner drive your implementation. Start with [`docs/adapter-protocol.md`](docs/adapter-protocol.md). The runner's `run` and `check-adapter` commands and the first cases are still being built, so there is not yet a conformance run to point an adapter at.

**If you want to work on the suite itself** — the runner, the case generators, the documents — the runner is a Python package with no runtime dependencies, managed with [uv](https://docs.astral.sh/uv/):

```sh
uv sync --dev
uv run pytest
uv run kcs --version
```

## Results and documentation

The suite's documentation and its published conformance results are on its site, <https://bakobo.github.io/keri-conformance-suite/>. Each result there is labelled as either reproduced by this repository's CI or submitted by an implementation's maintainer; [`docs/publishing-results.md`](docs/publishing-results.md) explains the difference and how to submit one.

## Documents

- [`docs/design.md`](docs/design.md) — principles, verdicts, case format, versioning and CI.
- [`docs/adapter-protocol.md`](docs/adapter-protocol.md) — how an adapter talks to the runner.
- [`docs/publishing-results.md`](docs/publishing-results.md) — how results are produced, labelled and submitted, and how to build the site.

## License

Apache-2.0, for the code and the test vectors alike, so implementations can copy vectors into their own test trees. See [`LICENSE`](LICENSE).
