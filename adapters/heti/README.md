# heti adapter

Connects [heti](https://github.com/bakobo/heti) to the conformance runner over adapter protocol version 1 ([`docs/adapter-protocol.md`](../../docs/adapter-protocol.md)). It implements `acdc.verify` through heti's public verifier, `Lockbox.verify_acdc`, and `acdc.issue` through its public issuer, `OwnFacet.issue`, and uses heti's public API only, never patching it (this.i 93t4d880). It composes nothing: `composes` is empty, and every verdict is heti's.

The adapter does not read, reuse or import anything from `generators/`, so it never tests the suite's own model against itself.

## Building it

heti is pinned by full commit in `pyproject.toml` and requires Python 3.14. heti is private until it is published, so resolving the pin needs read access to `bakobo/heti` over SSH.

```sh
cd adapters/heti && uv sync

# from the repository root
uv run kcs check-adapter "$PWD/adapters/heti/.venv/bin/kcs-adapter-heti"
uv run kcs run --adapter "$PWD/adapters/heti/.venv/bin/kcs-adapter-heti" --profile sedi-1
```

Point the runner at the console script inside `.venv` rather than at `uv run`: the runner starts adapters with a scrubbed environment.

## acdc.verify

For each request the adapter builds a fresh lockbox in a temporary directory and gives heti the bundle in the forms its API takes:

- **KELs.** heti learns another identifier's key state only by resolving its OOBI. So the adapter starts a loopback HTTP server for the request, serves each KEL in the bundle under the prefix its events name, and resolves one OOBI per prefix. The server answers only with the bundle's own bytes and stops when the request ends, so the bundle stays the whole world: nothing outside it is served or fetched.
- **Schemas** are learned one by one; one heti refuses is left out.
- **Registry events** are grouped by registry. heti takes a registry's chain as one genus/version code followed by the events' bodies, and the disclosed blinded state blocks separately, as each block's fields without its group code. The adapter finds those blocks by reading the attachment groups by their counts.
- **ACDCs** go to heti as their genus/version code and body. heti reads an ACDC with nothing after it and finds the issuer's seal in the KEL itself, so attachments that only point at the sealing event are left off; a disclosure attached to an ACDC goes with its registry's.
- **Far nodes** are passed with their own registries, so heti walks the edges itself.

heti answers a verified ACDC with a verdict and refuses everything else by raising an error with a code. The adapter maps:
- a retryable code, a missing input (`e.input.missing…`) or an unsupported feature (`e.feature.unsupported…`) to `incomplete`;
- any other code to `invalid`.

heti bounds the age of its own key-state observation by a `recency` it is given. The adapter consults no clock, so it passes ten years, which makes the bound inert.

`registry` reports heti's judged head for a verified ACDC. `edges` is empty, because heti reports which far nodes it walked, not a result per edge.

## acdc.issue

For each request the adapter builds a fresh lockbox, learns the request's schemas, mints one facet per role with no witnesses, and issues each credential with `OwnFacet.issue`, far nodes first, so an edge names its far credential by SAID and schema. heti issues with its own keys, salts, registry nonces and clock, which is why the runner grades an issuance by verifying it rather than by its bytes (this.i 2u2ps8mt). The result is each facet's KEL and each credential's ACDC, registry chain and head disclosure, as heti returns them. heti refuses an issuance by raising a coded error, which the adapter answers as `refused`.

## Declared features

`acdc.version-2.x`, `acdc.edges`, `acdc.registry.bup`, `cesr.genus-2.00`, `cesr.serialization.json`, `crypto.ed25519`, `kel.basic`, `kel.delegation` and `keri.version-2.x`: what heti does itself inside `acdc.verify`. heti refuses `upd` registries by name, so `acdc.registry.upd` is not declared.

## Tests

```sh
cd adapters/heti && uv run pytest --cov=kcs_adapter_heti --cov-branch
```

The tests drive heti itself, over bundles in `tests/fixtures/bundles.json`, which are data the suite's generator once produced; the adapter imports nothing from `generators/`. Branch coverage is 100%.
