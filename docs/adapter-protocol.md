# Adapter protocol

**Protocol version: 1 (draft).** Until the first suite release this protocol may still change; from that release on, it changes only as [`design.md`](design.md) describes under Versioning.

An adapter is a program that connects one implementation to the runner. The runner starts it as a child process and talks to it over its standard input and output. This document is everything an adapter author needs.

## Transport

- The runner writes requests to the adapter's standard input, one JSON object per line, UTF-8, terminated by `\n`.
- The adapter writes exactly one response per request to its standard output, one JSON object per line, in the same order.
- Anything the adapter writes to standard error is captured into the result record as diagnostics and otherwise ignored. Logging belongs there, never on standard output.
- Binary data travels as lowercase hex strings. CESR text-domain streams travel as ordinary JSON strings.
- The runner sends one request at a time and waits for its response. An adapter never has to handle concurrent requests.
- Each request is independent. An adapter must start every request from empty state — no identifiers, keys or events left over from an earlier request. That is the most common way for an adapter to produce results that depend on case order.
- The runner bounds every response's size and every request's duration. An adapter that exceeds either is recorded as a timeout or a harness error for that case, never as a pass or a fail, and is restarted before the next case.
- The runner ends a session by closing the adapter's standard input. The adapter should exit with status 0 when it reads end of file.

## Messages

Every request has an `op` naming the operation and an `id` the response must echo. Every response is either a result or an error:

```json
{"id": 7, "result": { ... }}
{"id": 7, "error": {"kind": "harness", "message": "..."}}
```

An error response means the adapter could not perform the operation at all — it is the adapter's way of saying "this is my fault, not a verdict". Its `kind` is one of:

- `harness` — the adapter itself failed, for example by hitting an unexpected exception in its glue code.
- `unsupported` — the implementation cannot perform this operation for this input. The runner never sends a case whose declared features the adapter does not support, so receiving `unsupported` for a case it did send counts as a **failure**, not as not-supported. Use it only when the implementation genuinely lacks something the handshake could not express, and expect it to be read that way.

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
  "features": ["cesr-1.0", "keri-1.0", "kel.delegation", "kel.multisig.weighted"]
}}
```

`features` is drawn from the feature vocabulary in `profiles/features.json`. The runner refuses to run an adapter whose protocol version it does not support.

## `cesr.parse`

Decode a stream.

```json
{"id": 1, "op": "cesr.parse", "domain": "text", "stream": "-AAB..."}
```

`domain` is `text` (the stream is a JSON string) or `binary` (the stream is hex). The result is either the decoded items or a rejection:

```json
{"id": 1, "result": {"items": [
  {"kind": "counter", "code": "-A", "count": 1},
  {"kind": "indexed", "code": "A", "index": 0, "raw": "9c1f..."},
  {"kind": "primitive", "code": "E", "raw": "4b2a..."},
  {"kind": "message", "proto": "KERI", "version": "1.0", "serialization": "JSON", "size": 343, "said": "EAbc..."}
]}}
{"id": 1, "result": {"reject": {"class": "truncated"}}}
```

An indexed item includes `ondex` when the code carries a second index. A counter includes `genus` and `gvrsn` when it carries them. A message item describes the serialized body; its attachments follow it as further items.

## `cesr.encode`

Encode a primitive.

```json
{"id": 2, "op": "cesr.encode", "code": "E", "raw": "4b2a...", "domain": "text"}
{"id": 2, "result": {"encoded": "EEsq..."}}
```

## `keri.process`

Deliver a sequence of messages, in order, to a fresh validator, and report what happened.

```json
{"id": 3, "op": "keri.process", "messages": [
  {"stream": "{\"v\":\"KERI10JSON...\"}-AAB...", "source": "controller"},
  {"stream": "...", "source": "witness-1"}
]}
```

Each message is a complete CESR text-domain stream: a serialized message with its attachments. `source` is a label for diagnostics and for cases about multiple sources, such as duplicity; it has no protocol meaning.

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

`dispositions` has one entry per message, in order. Each disposition is `accepted`, `pending`, `rejected` or `duplicitous`, as defined in [`design.md`](design.md). `reason` is optional and informative. `key_states` has one entry for every identifier the validator ends up holding accepted state for. Thresholds are strings in their wire form, so that weighted thresholds compare exactly.

## `keri.emit`

Build and sign an event from raw keys and parameters.

```json
{"id": 4, "op": "keri.emit", "event": {"t": "icp", "...": "..."}, "seeds": {"DAbc...": "a1b2..."}}
{"id": 4, "result": {"stream": "{\"v\":\"KERI10JSON...\"}-AAB..."}}
```

The exact shape of `event` for each event type is defined by the case schema, `schema/case.schema.json`.

## `acdc.verify` and `ipex.observe`

These operations will be specified with the first ACDC and IPEX cases. Their shape follows the same pattern: a bundle of inputs in, a verdict per item out, with informative reasons.

## Writing an adapter

Keep it small, and keep it outside the implementation. An adapter builds against a released or pinned version of its implementation and uses only that implementation's public API, so it keeps working whether or not the implementation's maintainers ever host it. Where the implementation lacks an entry point — for example, a library that verifies events but does not route or escrow them — the adapter composes the missing piece on top and says so in its README.

Report what the implementation did, not what the case expects. An adapter must never read a case's expected value; the runner never sends it one.
