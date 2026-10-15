# cesrixir adapter

Connects vLEIDA's [cesrixir](https://github.com/vLEIDA/cesrixir), an Elixir CESR library, to the conformance runner over adapter protocol version 1 ([`docs/adapter-protocol.md`](../../docs/adapter-protocol.md)). cesrixir encodes and decodes CESR with the genus 1.00 and 2.00 code tables, in the text and binary domains, with JSON, CBOR and MessagePack field maps. It has no KERI layer, so the adapter implements `cesr.parse` and `cesr.encode` and declares only those operations. It composes nothing: `composes` is empty, and every value it reports comes from cesrixir's decoder or from cesrixir's own encoding of what it decoded. The tables below say which, value by value. The decision and its tradeoffs are in `this.i`, "The cesrixir adapter runs in a pinned Elixir container and reports what cesrixir decoded".

## What it tests, pinned

| Package | Pin | Commit | Why |
|---|---|---|---|
| `cesrixir` | `1.0.1` on hex.pm, outer checksum `3a4e2ee0…f58c3` in `mix.lock` | `1e4944a25a7f1aa6c00db1192afb930a88aa444e` | The newest release. Its `lib/` and `mix.exs` are identical to that commit, and to `fc3fdef` (the head of `main` on 2026-10-15), whose two later commits change only CI |
| `jason` | `1.4.4` | | The version cesrixir's own `mix.lock` pins; the adapter also uses it for the protocol's JSON |
| `msgpack`, `ord_map`, `cbor_ordmap` | `0.8.1`, `0.1.0`, `1.0.1` | | cesrixir's dependencies, at the versions its own `mix.lock` pins |
| Elixir | `elixir:1.19.5-otp-28-slim@sha256:597474ac81f0d0bfa4d67546c2591a033315a2b9e6ab2f1a22824af9c913066a` | | cesrixir's `mix.exs` requires Elixir `~> 1.19`. Tag 1.19.5 was pushed on 2026-09-02 |

Every hex package is resolved in `mix.lock` and checked against its checksums when the image is built (`mix deps.get --check-locked`). hex.pm records no commit, so `hello` takes the version from the cesrixir application that is actually loaded and the commit from a table in `lib/kcs_adapter_cesrixir/identity.ex`, checked by hand against the repository; a version missing from the table fails `hello` (`e.env.dependency.cesrixir-commit.f`) rather than report a guess. `test/identity_test.exs` checks that `mix.lock`, the table and the loaded application agree. `hello` reports `implementation` as `{"name": "cesrixir", "version": "1.0.1", "commit": "1e4944a2…"}`.

The build fetches `hex` and `rebar3` with `mix local.hex` and `mix local.rebar`, which install the newest of each. They are build tools, not code the adapter runs, and every package they fetch is still checked against `mix.lock`.

## Licence

The adapter's own source is Apache-2.0, like the rest of this repository. cesrixir is MIT, as are ord_map and cbor_ordmap; jason is Apache-2.0, and msgpack declares "Apache" on hex.pm. Each is as its hex.pm metadata states. This repository distributes no built image; `bin/build` builds one locally and CI builds one, uses it, and discards it.

## Build, test, run

Docker is the only thing a reader needs on the host. Nothing is installed system-wide, and the host needs no Elixir.

```sh
adapters/cesrixir/bin/build              # builds the image, running the tests on the way

uv run kcs check-adapter "$PWD/adapters/cesrixir/bin/kcs-adapter-cesrixir"
uv run kcs run --adapter "$PWD/adapters/cesrixir/bin/kcs-adapter-cesrixir" --profile cesr-v1.0
uv run kcs run --adapter "$PWD/adapters/cesrixir/bin/kcs-adapter-cesrixir" --profile keripy-1x-interop
```

`bin/build` runs `docker build` twice on the `Dockerfile` here, which names the base image by digest in each `FROM` rather than through a build argument, with the repository root as a second build context (`--build-context suite=…`) for the protocol schema and the feature vocabulary. The first build stops at the `test` stage: it fetches the dependencies, compiles with warnings as errors, builds the escript, and runs `mix test --cover`, which fails below 100% coverage of the adapter's modules. Erlang's `cover` measures lines, not branches, so that is the gate here; no branch-coverage tool exists for the BEAM. The second build produces the `adapter` stage: the slim Elixir image with the escript in it, running as the `nobody` user. The image is tagged `kcs-adapter-cesrixir:src-<digest>`, where the digest covers every file the image is built from (`bin/image-tag`), so a stale image is never run by mistake: `bin/kcs-adapter-cesrixir` refuses to start (`e.env.dependency.image.f`) until the image for the current sources is built. The build needs the network, to fetch from hex.pm; running the image needs none.

`test/stdio_test.exs` runs the built escript as the runner does: requests on standard input, responses on standard output, and exit status 0 at end of input. It runs only where `KCS_ESCRIPT` names the escript, which the `test` stage sets. `test/schema_test.exs` checks a response of every kind against `schema/adapter-protocol.schema.json`, with the JSV library.

## Running in a container

`bin/kcs-adapter-cesrixir` is a launcher: it runs `docker run --rm -i` on the image, so the runner talks to the adapter over the docker client's standard input and output. The runner's address-space and CPU limits and its kill of the adapter's process group ([`docs/design.md`](../../docs/design.md), The runner) reach only that docker client, not the container, so the launcher gives the container limits of its own: `--network none`, `--cap-drop ALL`, `--security-opt no-new-privileges`, a read-only root filesystem, 2 GiB of memory with no swap, and at most 256 processes.

The adapter reads standard input through a port on file descriptor 0, owned by a reader process that splits it into request lines as the chunks arrive, so it never holds more of any one line than the protocol's 64 MiB limit; the bytes of a longer line are dropped as they come. When standard input closes, the adapter answers the complete lines it already holds and exits with status 0, but the reader exits it five seconds after end of input whatever it is doing. The runner sends one request at a time and closes standard input only after the last answer, unless it is abandoning the adapter: when a request hangs, it kills the docker client, the container's standard input closes, and the five seconds are what stop the container. A caller that pipes in a batch of requests and closes standard input at once gets answers only for what the adapter finishes in those five seconds.

The BEAM runs with two schedulers, two dirty CPU schedulers and two dirty I/O schedulers (`emu_args` in `mix.exs`), whatever the host's CPU count, so its threads stay far below `--pids-limit`, which counts threads.

## Declared features

Declared: `cesr.domain.binary`, `cesr.genus-1.00`, `cesr.genus-2.00`, `cesr.item-extents`, `cesr.serialization.cbor`, `cesr.serialization.json`, `cesr.serialization.mgpk`, `keri.version-1.x` and `keri.version-2.x`. They are what cesrixir claims and implements: both code tables, both domains, version strings of both versions, and all three field-map serializations. A feature cesrixir implements badly is still declared, so that the cases measure it rather than skip it; see "What the results show".

`cesr.item-extents` is declared because the adapter reports items for every stream cesrixir accepts, except one whose groups cesrixir's encoder does not reproduce byte for byte (see "How a stream is parsed"). That exception is the adapter declining to vouch for offsets, not cesrixir declining to give them, and it fails a case that expects items, as the protocol says a summary must.

Not declared, and why:

- `cesr.native`. cesrixir's stream encoder leaves a native CESR body (`kind: :cesr`) not implemented, and no case yet has one.
- `crypto.*`, `kel.*`, `keri.*` behaviours, `acdc.*`. cesrixir verifies no signature and has no KERI or ACDC layer.

**CBOR and MessagePack (assessment gap 12).** cesrixir frames CBOR and MessagePack field maps by their version strings and decodes them, with the `cbor_ordmap` and `msgpack` packages, so the adapter declares both serializations and reports such a body as a `message` item with `serialization` `CBOR` or `MGPK`. That makes cesrixir the first implementation here that could take cases for gap 12 of [`docs/coverage/assessment-2026-10.md`](../../docs/coverage/assessment-2026-10.md); no such case exists yet, so nothing has tested the claim beyond the adapter's own tests.

## How a stream is parsed

The verdict is cesrixir's: the adapter hands the whole stream to `Cesr.consume_stream/1`, with no options, so cesrixir starts with its default, the genus 1.00 table, and switches table only when the stream carries a genus/version code. An `{:error, message}` result is a rejection with class `error`; cesrixir's errors are free text, so the message goes to standard error instead of into the class. Because cesrixir parses only the bytes it is given and never waits for more, the protocol's end-of-input rule needs nothing further.

cesrixir returns decoded structs, not offsets. To say where each item lay, the adapter walks the stream with `Cesr.consume_element/2`, the call `consume_stream` itself makes for each top-level element, carrying the genus forward as `consume_stream` does, and checks that the walk produced exactly the elements `consume_stream` returned; if not, it answers a `harness` error (`e.self.unknown.replay-mismatch.f`). A top-level element's extent is what `consume_element` consumed.

cesrixir keeps no offsets inside a group, and the loops that consume a group's members are private to it. So the adapter re-encodes each top-level group with cesrixir's own encoder (`Cesr.CesrElement.to_b64/1` in the text domain, `to_binary/1` in the binary domain) and compares the result with the stream's bytes over the group's extent, and then reads each member back with cesrixir's decoder: from where the encoding lengths place the member, the public code-table reader that cesrixir's group consumers call (`KeriCodeTableV1`, `KeriCodeTableV2` or, for an indexed signature, `KeriIndexCodeTable`, with `get_T/1` or `get_B/1`) must return exactly that member and consume exactly its encoding, and a nested group's members are checked the same way. When both checks hold, every offset the adapter reports is one cesrixir's decoder consumed. When either fails, or cesrixir cannot re-encode what it decoded, the adapter answers the whole stream with the protocol's summary, `{"accepted": {"consumed": n}}`, rather than report offsets it cannot vouch for. A summary still fails a case that requires the stream to be rejected, because cesrixir accepted it, and it fails a case that expects items as malformed. Streams that get a summary include one with non-zero pad bits, which cesrixir accepts and re-encodes as zero, one with a genus 1.00 signature group whose members cesrixir returns in reverse order, and one with a group holding a field map, which cesrixir's group encoder cannot encode.

An exception raised inside cesrixir's decoder is a `harness` error (`e.self.unknown.exception.f`), never a rejection: cesrixir documents that failures return `{:error, reason}`, so a raise is a failure to answer, and the protocol counts it against every assertion in the case. An exception from cesrixir's encoder is different: the adapter calls the encoder only to measure a stream cesrixir has already accepted, so it means only that the adapter cannot vouch for offsets, and the answer is the summary. The exception and its stack go to standard error. Each request runs in a fresh process whose standard output is redirected to standard error, because cesrixir prints with `IO.inspect` on some paths and standard output is reserved for responses. cesrixir holds no state between calls, so a fresh process is also a fresh validator.

## Where each value comes from

| Reported value | Source |
|---|---|
| Accept or reject | `Cesr.consume_stream/1`: a list, or `{:error, message}` |
| `start`, `end` of a top-level item | Where `Cesr.consume_element/2` began, and where the remainder it returned begins |
| Genus item `code`, `genus`, `version` | The genus atom `consume_element` returned (`:keri_aaabaa`, `:keri_aaacaa`), mapped to the code that cesrixir's `UniversalProtocolGenusTable.get_T/1` maps to it; the version is decoded from that code's version characters with cesrixir's `Base64Indicies` |
| Message `proto`, `version`, `serialization`, `size` | The version-string struct cesrixir put in the field map's `v`: `proto`, `major`.`minor` (1.x) or `proto_major`.`proto_minor` (2.x), `kind`, `size` |
| Counter `code` | `"-"` followed by the `code` from cesrixir's `properties/0` for the group's module |
| Counter `size` | The size digits of cesrixir's text encoding of the group, decoded with cesrixir's `Base64Indicies`. The round trip has already shown that the encoding is the stream's bytes |
| Counter `end`, `group_end` | The group's start plus the length of its header, which is the length of cesrixir's encoding of the group less its members' encodings; and the group's start plus the length of cesrixir's encoding of the group |
| `start`, `end` of an item inside a group | The previous item's end, and that plus the length of cesrixir's encoding of the item, which cesrixir's code-table reader must consume exactly when it reads the item back from that start |
| Primitive `code`, `raw` | The struct's `code` and `payload` |
| Indexed `code`, `raw`, `index` | The struct's `code`, `payload` and `index` |
| Indexed `ondex` | Reported only when cesrixir's indexed code table (`OneCharIndexedPrimitiveGenerator`, `TwoCharIndexedPrimitiveGenerator`) gives the code a nonzero ondex size. The value is read back from cesrixir's text encoding of the signature at the offsets that table gives, because for current-only codes cesrixir's struct holds the index in `ondex` while its encoder writes zero |
| `cesr.encode` refusal | No module in cesrixir's code tables for the code (`unknown-code`), or `{:error, _}` from the module's constructor (`refused`) |
| `cesr.encode` | `new/1` of the primitive module that cesrixir's fixed-size code tables name for the code, or `new/2` of the variable-size module that keeps the code, then `to_b64/1` or `to_binary/1` |

## Errors

`hello` negotiates from the request's `supported` list, or `[protocol]` when the list is absent, and answers with protocol 1, or with an `unsupported` error (`e.feature.unsupported.protocol-version.f`) when the integer 1 is not offered (`true` and `1.0` are not 1). Request fields the adapter does not know are ignored. A request line may be at most 64 MiB, not counting its newline; the adapter holds at most that much of a line, answers a longer one with an error whose `id` is null (`e.input.range.request-size.f`), drops the rest of it, and answers the next request. A line that is not a JSON object, including a blank line, or whose `id` is not an integer from 0 to 2^53 − 1, gets an error whose `id` is null (`e.input.format.request.f`). A request without a string `op` or with a malformed field (`stream`, `code`, `raw`, `domain`) is a `harness` error carrying its id (`e.input.format.request.f`), and an unknown `op` is too (`e.input.range.unknown-op.f`). `keri.process`, `keri.emit`, `acdc.verify` and `exn.verify` are `unsupported` (`e.feature.unsupported.undeclared-op.f`). `cesr.encode` with a code cesrixir has no primitive for is a refusal, answered as a rejection with class `unknown-code`, and so is one whose raw value cesrixir's constructor refuses, with class `refused`; cesrixir's message goes to standard error. Every code ends in `f`: the same request gives the same answer.

## Results

<!-- BEGIN generated results: scripts/reproduce-results writes this table from results/; do not edit it -->

| Implementation | Profile | Verdict | Active MUST pass / fail | Active SHOULD pass / fail | Active INTEROP pass / fail | Active cases not supported | Result |
| --- | --- | --- | --- | --- | --- | --- | --- |
| cesrixir 1.0.1 | `cesr-v1.0` | not-conformant | 11 / 18 | 5 / 5 | 0 / 0 | 0 | [2026-10-15, suite bce12f8d](../../results/cesrixir/1.0.1/cesr-v1.0.json) |
| cesrixir 1.0.1 | `keripy-1x-interop` | not-interoperable | 0 / 0 | 0 / 0 | 4 / 5 | 0 | [2026-10-15, suite bce12f8d](../../results/cesrixir/1.0.1/keripy-1x-interop.json) |

<!-- END generated results -->

What follows explains the failures behind the table; every one traces to cesrixir, through the stack trace each harness error leaves in the committed result. It was written from runs against the cases on `main` at `9f92ff2`.

- Most `cesr-v1.0` failures are one defect: cesrixir's genus 2.00 table has no indexed signature codes, so `CountCodeConsumptionUtilities.trivial/2` gets `:notfound` reading a signature group, or reads a signature's first 44 characters as another primitive and then gets `:notfound`, and raises `CaseClauseError`. CESR-0012 to CESR-0023, CESR-0025, CESR-0026, CESR-0030, CESR-0031, CESR-0033 and CESR-0041 fail this way, and CESR-0044 in `cesr-strict` on a `-M` receipt-couples group.
- `Cesr.process_T_cnt_code/2` has no clause for an `{:error, _}` from the code that reads a group, so a group cesrixir cannot read raises `CaseClauseError` instead of being rejected. CESR-0029 and CESR-0048 fail this way on a genus/version code inside an attachments group, which cesrixir's text-domain group reader looks for with its binary-domain matcher; so do CESR-0038, CESR-0049 and CESR-0054, which must be rejected, and CESR-0043. CESR-0032 and CESR-0052, which must be rejected, raise `MatchError` because a group's size runs past the stream.
- CESR-0024 and CESR-0027 are rejected where items are expected. cesrixir's binary-domain count-code patterns match a code's size characters as bytes rather than bits, so they can never match a byte-aligned stream and no binary-domain group is ever read.
- CESR-0028 gets a summary: cesrixir reads the 88-character signature in its `--C` group as two 44-character primitives, and their re-encoding differs from the stream. CESR-0045 gets one because cesrixir returns the two signatures of its `-A` group in reverse order.
- CESR-0039 is accepted although it must be rejected: cesrixir ignores the pad bits of a primitive, so non-zero ones pass.

All `cesr.encode` cases pass in both domains, CESR-0046 and CESR-0047 decode to exactly the expected items, and the must-reject cases CESR-0034, CESR-0035, CESR-0037, CESR-0040, CESR-0042, CESR-0050 and CESR-0057 are rejected.

## CI and the committed results

The `cesrixir-adapter` job in `.github/workflows/ci.yml` runs `bin/build`, which fetches the hex packages `mix.lock` pins, compiles with warnings as errors, runs the adapter's tests with the 100% line gate inside the image and builds the adapter image, and then runs `kcs check-adapter` through the launcher. It does not run a profile: the table under Results is generated from this adapter's committed results for `cesr-v1.0` and `keripy-1x-interop`, under `results/cesrixir/`, which the suite's maintainer refreshes and checks locally (`docs/design.md`, Continuous integration). The tool builds the adapter itself with `bin/build` before it runs it:

```sh
uv run python scripts/reproduce-results check --adapter cesrixir
uv run python scripts/reproduce-results refresh --adapter cesrixir
```
