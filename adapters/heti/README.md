# heti adapter

Connects [heti](https://github.com/bakobo/heti) to the conformance runner over adapter protocol version 1 ([`docs/adapter-protocol.md`](../../docs/adapter-protocol.md)). It implements `acdc.verify` through heti's public verifier, `Lockbox.verify_acdc`, and uses heti's public API only, never patching it (this.i 93t4d880). It composes nothing: `composes` is empty, and every verdict is heti's.

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
- **Registry events** are grouped by registry. heti takes a registry's chain as one genus/version code followed by the events' bodies, and the disclosed blinded state blocks separately.
- **Far nodes** are passed with their own registries, so heti walks the edges itself.

heti answers a verified ACDC with a verdict and refuses everything else by raising an error with a code. The adapter maps:
- a retryable code, a missing input (`e.input.missing…`) or an unsupported feature (`e.feature.unsupported…`) to `incomplete`;
- any other code to `invalid`.

heti bounds the age of its own key-state observation by a `recency` it is given. The adapter consults no clock, so it passes ten years, which makes the bound inert.

`registry` reports heti's judged head for a verified ACDC. `edges` is empty, because heti reports which far nodes it walked, not a result per edge.

## Declared features

`acdc.version-2.x`, `acdc.edges`, `acdc.registry.bup`, `cesr.genus-2.00`, `cesr.serialization.json`, `crypto.ed25519`, `kel.basic`, `kel.delegation` and `keri.version-2.x`: what heti does itself inside `acdc.verify`. heti refuses `upd` registries by name, so `acdc.registry.upd` is not declared.
