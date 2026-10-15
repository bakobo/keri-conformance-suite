# heti adapter

Connects [heti](https://github.com/bakobo/heti) to the conformance runner over adapter protocol version 1 ([`docs/adapter-protocol.md`](../../docs/adapter-protocol.md)). It implements `acdc.verify` through heti's public verifier, `Lockbox.verify_acdc`, `acdc.issue` through its public issuer, `OwnFacet.issue`, and `keri.process` through its public key-state resolver, `heti.anchored.consume.resolve_key_state`, and uses heti's public API only, never patching it (this.i 93t4d880). It composes nothing: `composes` is empty, and every verdict is heti's.

The adapter does not read, reuse or import anything from `generators/`, so it never tests the suite's own model against itself.

## Building it

heti is pinned by full commit in `pyproject.toml` and requires Python 3.14. heti is private until it is published, so resolving the pin needs read access to `bakobo/heti` over SSH.

```sh
cd adapters/heti && uv sync

# from the repository root
uv run kcs check-adapter "$PWD/adapters/heti/.venv/bin/kcs-adapter-heti"
uv run kcs run --adapter "$PWD/adapters/heti/.venv/bin/kcs-adapter-heti" --profile sedi-1
uv run kcs run --adapter "$PWD/adapters/heti/.venv/bin/kcs-adapter-heti" --profile keri-v1.0.1
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

heti's API takes no expected schema, so the request's optional `expect_schema` is not passed on, and the cases that send it (a SHOULD, ACDC line 250) are graded on heti's verdict alone. An element of the bundle the adapter cannot pass on whole (a stream without its genus/version code, or with anything after its body but one well-formed attachments group of seal source couples and disclosures) is left out, as the protocol says for an element that cannot be read. A presented ACDC in that state goes to heti as it came, for heti to refuse.

`registry` reports heti's judged head for a verified ACDC. `edges` is empty, because heti reports which far nodes it walked, not a result per edge.

## acdc.issue

For each request the adapter builds a fresh lockbox, learns the request's schemas, mints one facet per role with no witnesses, and issues each credential with `OwnFacet.issue`, far nodes first, so an edge names its far credential by SAID and schema. heti issues with its own keys, salts, registry nonces and clock, which is why the runner grades an issuance by verifying it rather than by its bytes (this.i 2u2ps8mt). The result is each facet's KEL and each credential's ACDC, registry chain and head disclosure, as heti returns them. heti refuses an issuance by raising a coded error, which the adapter answers as `refused`.

## keri.process

heti has no per-message KEL processor in its public API (this.i 8uucj49z). Its public KEL verification surface is `resolve_key_state(aid, evidence, as_of)`, a pure function: it replays the evidence into a scratch keripy database with `lax=False`, drives keripy's escrows until a pass accepts nothing more, refuses an identifier with a fork anywhere in its delegation chain, and answers a key state or raises a coded error. For each request the adapter makes each message one unattributed segment, in delivery order, and asks heti about the message's own event by the SAID in its `d` field (`as_of=d`): with the messages delivered so far for the initial reading, and with all of them for the final one. Every call is a fresh replay, so nothing carries over between readings or requests.

- heti answers: `seen`. heti checks for duplicity only after it has found the event, so a duplicity refusal also means `seen`.
- heti refuses with a retryable code (the event is held in an escrow, or the evidence does not reach it yet): `pending`.
- heti refuses with any other code, or refuses an identifier it cannot parse: `rejected`. The reason is heti's code and message.

A message's `d` is only what it claims. When the messages carry more than one body under one event's SAID, heti is asked about each body with the copies carrying another body left out, so a corrupt copy is not reported seen because a valid copy of its SAID was, while copies with one body still combine their signatures.

heti refuses all of the evidence when any segment does not begin with a genus/version code. So a message that does not, or whose body names no event, is offered to heti only in the question about itself, and is left out of every other. A request may carry at most 64 messages (`process.MAX_MESSAGES`), because every message costs two replays of up to all of them; a longer one gets an `unsupported` error (`e.feature.unsupported.message-count.f`).

`key_states` is heti's answer for each identifier a key event names, with every message as evidence. heti refuses to report a key state for a duplicitous identifier, so such an identifier is left out, and the cases that expect the state of the first-seen branch fail on it.

What the adapter cannot get from heti, and so does not claim:

- **Receipts.** heti reports no reading of a receipt or of any message that is not a key event, so such a message is reported `rejected` and `keri.routing` is not declared.
- **The trunk.** heti reports where a KEL ends, but not which events a superseding rotation displaced, so `trunk` is whether the message is finally `seen`, and `kel.recovery` is not declared.
- **Non-transferable identifiers.** heti refuses them by name, so `kel.nontransferable` is not declared.
- **1.x bodies.** heti requires every stream to begin with a genus/version code, which the 1.x interoperability cases do not carry, so `keri.version-1.x` is not declared.

Where heti adds nothing over keripy. The checks on each event (signatures and thresholds, pre-rotation commitments, delegating seals, witness thresholds, sequence and prior-digest chaining) and the escrows are keripy's `Kevery`, from the bakobo/keripy fork heti pins, so a `keri.process` result for those is keripy's. heti adds four things: it refuses a stream that does not state its genus, it settles escrows to a fixpoint rather than once, it refuses to report a key state for an identifier whose evidence shows a fork when replayed in either order (so a lawful recovery delivered in the other order is not taken for one), and it refuses non-transferable identifiers.

## Declared features

`acdc.version-2.x`, `acdc.edges`, `acdc.registry.bup`, `cesr.genus-2.00`, `cesr.serialization.json`, `crypto.ed25519`, `kel.basic`, `kel.delegation` and `keri.version-2.x`: what heti does itself inside `acdc.verify`. heti refuses `upd` registries by name, so `acdc.registry.upd` is not declared. For `keri.process` also `kel.multisig.numeric`, `kel.multisig.weighted`, `kel.partial-rotation`, `kel.witness` and `keri.escrow`, which heti's resolver does through keripy; "keri.process" above says what is not declared and why.

## Tests

```sh
cd adapters/heti && uv run pytest --cov=kcs_adapter_heti --cov-branch
```

The tests drive heti itself, over bundles in `tests/fixtures/bundles.json` and message sequences in `tests/fixtures/kels.json`, which are data the suite's generator once produced; the adapter imports nothing from `generators/`. Branch coverage is 100%.
