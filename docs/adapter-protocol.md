# Adapter protocol

**Protocol version: 1 (draft).** Until the first suite release this protocol may still change; from that release on, it changes only as [`design.md`](design.md) describes under Versioning.

An adapter is a program that connects one implementation to the runner. The runner starts it as a child process and talks to it over its standard input and output. This document is everything an adapter author needs.

Two things will check an adapter without running a single case: message schemas in `schema/adapter-protocol.schema.json`, which you can run in your own tests in any language, and `kcs check-adapter <command>`, which probes a running adapter. Neither exists yet; both are being built next, and are described under "Checking an adapter" in [`design.md`](design.md).

## Transport

- The runner writes requests to the adapter's standard input, one JSON object per line, UTF-8, terminated by `\n`.
- The adapter writes exactly one response per request to its standard output, one JSON object per line, in the same order.
- Anything the adapter writes to standard error is captured into the conformance report as diagnostics and otherwise ignored. Logging belongs there, never on standard output.
- Every stream travels as raw bytes, hex-encoded, whatever domain or serialization it contains. The adapter must hand those bytes to its implementation unchanged, so that the implementation does its own domain sniffing and framing. Other binary values, such as raw primitive values, are also hex.
- The runner sends one request at a time and waits for its response. An adapter never has to handle concurrent requests.
- Each request is independent. An adapter must start every request from empty state — no identifiers, keys or events left over from an earlier request. That is the most common way for an adapter to produce results that depend on case order.
- The runner bounds every response's size and every request's duration. An adapter that exceeds either, exits, or writes something that is not a valid response fails every assertion in that case, and is restarted before the next case. A parser that panics or loops on a hostile stream is therefore a failure, not a gap in the results.
- The runner ends a session by closing the adapter's standard input. The adapter should exit with status 0 when it reads end of file.

## Messages

Every request has an `op` naming the operation and an `id` the response must echo. If a request cannot be read at all — it is not valid JSON, or has no usable `id` — the adapter answers with an error response whose `id` is `null`, and keeps running. Every response is either a result or an error:

```json
{"id": 7, "result": { ... }}
{"id": 7, "error": {"kind": "harness", "message": "..."}}
```

An error response means the adapter could not perform the operation. It is recorded with its message for diagnosis, and it **fails every assertion in the case**, whatever its `kind`. The runner cannot tell an exception in adapter glue from an exception in the implementation, and a must-reject case answered with an exception has not been answered. `kind` is one of:

- `harness` — the adapter or the implementation raised an unexpected error.
- `unsupported` — the implementation cannot perform this operation for this input. The runner never sends a case that needs a feature the adapter did not declare, so the way to avoid this outcome is an accurate feature declaration.

The only outcomes that are not scored are faults on the runner's side, such as failing to start the adapter at all.

A rejection is not an error. If a stream must be rejected and the implementation rejects it, that is a result with a rejection verdict.

## `hello`

The first request of every session.

```json
{"id": 0, "op": "hello", "protocol": 1}
```

The adapter answers with its protocol version and what it is:

```json
{"id": 0, "result": {
  "protocol": 1,
  "adapter": {"name": "keriox-adapter", "version": "0.17.13-1"},
  "implementation": {"name": "keriox", "version": "0.17.13", "commit": "ddcd2aba..."},
  "operations": ["cesr.parse", "keri.process"],
  "features": ["cesr.genus-2.00", "keri.version-1.x", "kel.basic", "kel.delegation", "kel.multisig.weighted", "keri.escrow"],
  "composes": ["keri.escrow"]
}}
```

`features` is drawn from the feature vocabulary in `profiles/features.json`. `features` lists everything the implementation and adapter together can do, and is what the runner uses to decide which cases to send. `composes` is a subset of `features`: it marks the behaviours that the adapter supplies itself rather than delegating to the implementation — for example, escrow and routing on top of a library that only verifies events. It is reported in every conformance report and every conformance claim, so that nobody credits the implementation with what the adapter did. The runner refuses to run an adapter whose protocol version it does not support, whose `hello` is missing or malformed, or whose features or composed behaviours are not in the vocabulary. In each case it prints which field was wrong and what it expected, exits with a non-zero status, and runs no cases. These are runner-side refusals, not test failures, because no case was attempted.

## `cesr.parse`

Decode a stream.

```json
{"id": 1, "op": "cesr.parse", "stream": "7b2276223a..."}
```

The stream is hex-encoded bytes and may be in either domain or mix them. The result is either the decoded items or a rejection:

```json
{"id": 1, "result": {"items": [
  {"kind": "message", "start": 0, "end": 343, "proto": "KERI", "version": "2.0", "serialization": "JSON", "size": 343},
  {"kind": "counter", "start": 343, "end": 347, "code": "-K", "size": 22, "group_end": 435},
  {"kind": "indexed", "start": 347, "end": 435, "code": "A", "index": 0, "raw": "9c1f..."}
]}}
{"id": 1, "result": {"reject": {"class": "truncated"}}}
```

`start` and `end` are byte offsets into the stream. Report what is on the wire, not what your implementation infers: an indexed item has exactly the index fields its code's table entry defines; a counter's `size` is the value of its size field as encoded, its `group_end` is the offset at which the implementation ended the group the counter introduces, and it carries its genus and version where the code carries them; a message item is reported only for a body framed by a version string, and a native CESR body is reported as its count code and primitives. The runner checks framing from the offsets, so a group whose size was misread ends in the wrong place.

## `cesr.encode`

Encode a primitive.

```json
{"id": 2, "op": "cesr.encode", "code": "E", "raw": "4b2a...", "domain": "text"}
{"id": 2, "result": {"encoded": "4545737..."}}
```

`encoded` is the encoding as hex bytes, like every other binary value: for the text domain those are the bytes of the Base64 characters, and for the binary domain they are the raw encoded bytes.

## `keri.process`

Deliver a sequence of messages, in order, to a fresh validator, and report what happened.

```json
{"id": 3, "op": "keri.process", "perspective": {"role": "validator"}, "messages": [
  {"stream": "7b2276223a...", "source": "controller"},
  {"stream": "...", "source": "witness-1"}
]}
```

Each message is a hex-encoded stream: a serialized message with its attachments, in whatever domain and serialization the case uses. `source` is a label for diagnostics and for cases about multiple sources, such as duplicity; it has no protocol meaning. `perspective` states who the validator is. Protocol version 1 defines only `{"role": "validator"}`, an ordinary validator with no special relationship to the identifiers involved; further roles will be added as cases need them.

After delivering each message, the adapter must drive its implementation to quiescence: process everything it can, including anything held in escrow that the new message unblocks, until nothing further changes. A message's `initial` disposition is its state at quiescence after its own delivery; its `final` disposition is its state at quiescence after the last message. If an implementation's escrow processing is timer-driven, the adapter must trigger it directly rather than wait.

```json
{"id": 3, "result": {
  "dispositions": [
    {"initial": "accepted", "final": "accepted"},
    {"initial": "pending", "final": "accepted", "reason": "out-of-order"}
  ],
  "key_states": {
    "EAbc...": {
      "sn": 2, "said": "EDef...",
      "keys": ["DAbc..."], "kt": "1",
      "ndigs": ["EGhi..."], "nt": "1",
      "wits": [], "bt": "0",
      "delegator": null
    }
  }
}}
```

`dispositions` has one entry per message, in order. Each disposition is `accepted`, `pending`, `rejected`, `duplicitous` or, for a final disposition only, `superseded`, as defined in [`design.md`](design.md). Report the most specific one your implementation knows; an implementation that does not distinguish pending from rejected may report `rejected` for both, and is graded accordingly. `reason` is optional and informative. `key_states` has one entry for every identifier the validator ends up holding accepted state for. Report thresholds as your implementation holds them, as a string or as nested lists of fraction strings; the runner normalizes both sides before comparing.

## `keri.emit`

Build and sign an event from raw keys and parameters.

```json
{"id": 4, "op": "keri.emit", "event": {"t": "icp", "...": "..."}, "seeds": {"DAbc...": "a1b2..."}}
{"id": 4, "result": {"stream": "7b2276223a224b45..."}}
```

The exact shape of `event` for each event type is defined by the case schema, `schema/case.schema.json`, which is added with the first KERI cases. The runner checks the event body byte for byte, checks that every signature verifies, and parses the attachments to check that they carry the right signatures with the right indexes. How the attachments are grouped is up to the implementation.

## `acdc.verify` and IPEX

`acdc.verify` will be specified with the first ACDC cases: a bundle and an evaluation point in, a verdict of `valid`, `revoked`, `invalid` or `incomplete` out, with an informative reason. IPEX operations will follow once there is normative text for them to test.

## Writing an adapter

Keep it small, and keep it outside the implementation. An adapter builds against a released or pinned version of its implementation and uses only that implementation's public API, so it keeps working whether or not the implementation's maintainers ever host it. Where the implementation lacks an entry point — for example, a library that verifies events but does not route or escrow them — the adapter composes the missing piece on top, declares it in `composes`, and explains it in its README.

Report what the implementation did, not what the case expects. An adapter must never read a case's expected value; the runner never sends it one.
