# signify-ts and KERIA adapter

Connects released signify-ts, and the KERIA agent it drives, to the conformance runner over adapter protocol version 1 ([`docs/adapter-protocol.md`](../../docs/adapter-protocol.md)). It implements `acdc.verify` for ACDC 1.x credentials in keripy 1.x's forms, the `sedi-1x-interop` companion profile, and declares only that operation. It composes nothing: `composes` is empty, and every verdict is KERIA's. The decision and its tradeoffs are in `this.i`, "The signify-ts-keria adapter judges a 1.x bundle with the KERIA agent signify-ts drives".

## What it tests, pinned

signify-ts is a KERIA client. It has no ACDC verifier of its own and leaves the validation of key events, registry events and credentials to the KERIA agent it controls. A wallet built on signify-ts, as the deployed 1.x wallets are, accepts a credential exactly when its KERIA agent does. So the implementation this adapter reports, `signify-ts-keria`, is the pair:

| Component | Pin | Source |
|---|---|---|
| `signify-ts` | commit `5a174b5456c2d256493f9991ac4ae73857ff4fce`, the `0.4.1` release tag | a git dependency in `package.json`, locked in `package-lock.json`; npm builds it with its own `prepare` script, which is why `allowScripts` names that commit |
| KERIA | `weboftrust/keria@sha256:4f728aed7e608cb5fae778682d8286a02353f310c628e145a36c31cefb1c9faf`, the `0.4.1` image's multi-architecture index | `KERIA_IMAGE` in `src/keria.ts` |

KERIA 0.4.1 judges credentials with keripy 1.2.14, the version `sedi-1x-interop` takes its expected verdicts from. A verdict here can therefore differ from the keripy 1.2.14 adapter's only through what KERIA adds around keripy: how it takes delivery of a stream, its agent's parser and escrow loop, and how it reports a credential through its API. A difference between the two is traced to delivery before it is reported as KERIA's judgement.

`hello` reports `implementation` as `{"name": "signify-ts-keria", "version": "0.4.1 with KERIA 0.4.1 (keripy 1.2.14)", "commit": "5a174b54…"}`, where the commit is signify-ts's. The signify-ts version comes from the installed package's `package.json` and its commit from npm's record of how it resolved the package (`node_modules/.package-lock.json`); the KERIA and keripy versions are read from the installed Python packages inside the running container. None of them is a constant in the adapter, so a stale install cannot report the pin. If npm recorded no commit, `hello` fails (`e.env.dependency.signify-commit.f`). The image digest is not in `version`, because a published result's path is built from it and is at most 64 characters; the digest is the one above, and the adapter writes it to standard error when it starts the container.

## Build, test, run

The adapter needs Linux, Node 24 and Docker, and the image pulled or pullable. Node runs the TypeScript sources directly, so there is no build step. `.node-version` names the version CI uses.

```sh
docker pull weboftrust/keria@sha256:4f728aed7e608cb5fae778682d8286a02353f310c628e145a36c31cefb1c9faf
cd adapters/signify-keria && npm ci && npm run typecheck && npm run coverage
KCS_KERIA_LIVE=1 npx vitest run tests/stdio.test.ts   # also starts the real image

# from the repository root
uv run kcs check-adapter "$PWD/adapters/signify-keria/bin/kcs-adapter-signify-keria"
uv run kcs run --adapter "$PWD/adapters/signify-keria/bin/kcs-adapter-signify-keria" --profile sedi-1x-interop
```

The unit tests replace Docker, KERIA and signify-ts's client with fakes, so `npm run coverage` needs neither Docker nor a network. `bin/kcs-adapter-signify-keria` starts Node with `--disable-wasm-trap-handler`, for the reason the signify-ts adapter's README gives: libsodium's WebAssembly cannot reserve memory under the runner's 4 GiB address-space limit otherwise.

## KERIA's container

The adapter starts the pinned image itself, once per session, on the first request that needs it (in practice `hello`), and removes it with `docker rm -f` when the process exits, including on SIGINT, SIGTERM or SIGHUP. A SIGKILL leaves it running; every container the adapter starts carries the label `kcs.adapter=signify-keria`, so `docker ps --filter label=kcs.adapter=signify-keria` finds one left behind. Starting it takes a few seconds. If Docker cannot start it, or KERIA does not answer within 45 seconds, `hello` fails with `e.env.dependency.keria-start.t`, whose trailing `t` says a later session may succeed.

Every port the container publishes is on the host's loopback interface. KERIA listens on every interface inside its container, and host networking would put its admin API on the host's network.

KERIA learns a schema only by resolving a data OOBI, a URL ending `/oobi/<SAID>`. A container commonly cannot reach a server on the host, because host firewalls drop that traffic, so the adapter runs a small standard-library Python server inside KERIA's own container, using the image's own Python (`SCHEMA_SERVER` in `src/keria.ts`). KERIA reaches it at `127.0.0.1:7700` in its own network namespace, and the adapter replaces its whole set of schemas before each request through a published port. The server serves only bytes the request carried.

## How a bundle is judged

For each `acdc.verify` request:

1. The adapter reads the presented ACDC's SAID, `d`, from its 1.x version string. If the stream does not begin with an ACDC 1.x body it can read that way, the verdict is `invalid` and nothing is delivered.
2. It offers KERIA the request's schemas. A schema that is not JSON, has no `$id` usable as a path segment, or refers to anything outside itself (a remote reference, a local reference that resolves to nothing, or a nested base URI) is withheld, the rule the keripy adapter applies: KERIA validates with keripy's schema validator, which follows a reference wherever it points, and the bundle is the whole world.
3. signify-ts boots a fresh agent with a random passcode, so nothing one request delivers is seen by another, and asks KERIA to resolve each offered schema's data OOBI. A schema KERIA will not take, because its `$id` is not its SAID, is one the bundle does not have.
4. The adapter delivers `kels`, `registry`, `acdcs` and then `presented`, each stream unchanged, by `PUT` to KERIA's CESR endpoint addressed to the agent (`CESR-DESTINATION`), which appends the bytes to that agent's own parser's input. A far node with the presented credential's own SAID is not delivered, as in the keripy adapter: KERIA's databases are keyed by SAID, so it would stand in for what was presented.
5. After each stream it waits for quiescence: it delivers a signed inception of a fresh identifier that nothing else names and waits until KERIA reports that identifier's key state, which it can do only once its parser has passed every byte delivered before. After the last stream it does this a second time, because KERIA runs its escrow pass once per loop: when the second marker is seen, that pass has run after everything delivered. A marker not seen within 10 seconds means KERIA's parser stalled on a stream it cannot finish; nothing after that is parsed, so the adapter stops waiting.
6. It asks signify-ts for the credential by its SAID.

The bundle never reaches the network through the adapter, and the adapter consults no clock. KERIA's verifier compares a registry event's `dt` with the current time, but treats an issuance as stale only after 36,000,000,000 seconds, so no stamp a case carries is affected; its escrows time out by arrival time, not by any stamp.

## Where each value comes from

| Reported value | Source |
|---|---|
| `verdict` | `valid` when signify-ts's `credentials().get` returns the credential, which KERIA does only once its verifier has saved it; `invalid` otherwise, and when step 1 cannot read the presented stream |
| `reason` | Which of those happened, including whether KERIA's parser stalled |
| `registry` | The `status` KERIA returns with a saved credential: `rd` is its `ri`, `n` its `s` read as hex, `d` its `d`, `td` the credential's SAID and `ts` `revoked` for `rev` or `brv` and otherwise `issued`. `null` when no credential was saved or its status lacks one of these |
| `edges` | Always empty. KERIA reports no result for any single edge, and the protocol lets an adapter report only what it evaluated |

The verdict is never `incomplete`. KERIA's API reports a credential only once it is saved and exposes no credential escrow, so the adapter cannot tell a credential KERIA refused from one it holds for something the bundle lacks. It reports the not-valid it can observe. A case that expects `incomplete` therefore fails here, which is a limit of what KERIA's API shows, not a verdict that KERIA judged the credential invalid. When a request carries `expect_schema` and the saved credential names another schema, the verdict is `invalid`, as in the keripy adapter.

## Declared features

Declared: `acdc.keripy-1x`, `acdc.ptel-1x`, `cesr.genus-1.00`, `cesr.serialization.json`, `crypto.ed25519`, `kel.basic` and `keri.version-1.x`, the features the `sedi-1x-interop` cases require. KERIA reads KERI 1.x and ACDC 1.x JSON with CESR 1.00 attachments and Ed25519 signatures.

Not declared: any ACDC 2.00 feature, because KERIA 0.4.1 issues and holds 1.x credentials only; `cesr.parse`, `keri.process` and `exn.verify`, which this adapter was not built for (the signify-ts adapter tests signify-ts's parser); and `acdc.issue`, which is not built yet.

## Errors

`hello` negotiates from the request's `supported` list (or `[protocol]` when the list is absent) and answers with protocol 1, or with an `unsupported` error when the number 1 is not offered. Request fields the adapter does not know are ignored. A request line may be at most 64 MiB; a longer one gets an error whose `id` is null (`e.input.range.request-size.f`). A line that is blank, not UTF-8, not a JSON object, or has no usable `id` gets an error whose `id` is null (`e.input.format.request.f`), and so does a malformed `acdc.verify` field, with the request's `id`. Operations the adapter does not declare get an `unsupported` error (`e.feature.unsupported.undeclared-op.f`). A failure inside KERIA or the schema server while judging a request is a harness error, `e.env.dependency.keria.t`, never a verdict. Any other exception becomes a harness error (`e.self.unknown.exception.f`). `tests/schema.test.ts` checks every kind of response against `schema/adapter-protocol.schema.json`.

## The baseline

`baseline-sedi-1x-interop.json` is the committed result of `sedi-1x-interop`, written with the keripy adapter's standard-library comparison tool. All seven cases, ACDC-0201 to ACDC-0207, pass: KERIA saves the credentials keripy 1.2.14 finds valid and refuses ACDC-0202 (a 1.x credential under SEDI's published 2.0 schema shape), ACDC-0203 (an `a.dt` that SEDI core's closed attribute section forbids) and ACDC-0205 (an edge section with its own `u`).

```sh
uv run kcs run --adapter "$PWD/adapters/signify-keria/bin/kcs-adapter-signify-keria" --profile sedi-1x-interop --report /tmp/s.json
PYTHONPATH=adapters/keripy/src uv run python -m kcs_adapter_keripy.baseline write adapters/signify-keria/baseline-sedi-1x-interop.json /tmp/s.json
```
