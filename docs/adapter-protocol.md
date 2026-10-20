# Adapter protocol

**Protocol version: 1 (draft).** Until the first suite release this protocol may still change; from that release on, it changes only as [`design.md`](design.md) describes under Versioning.

An adapter is a program that connects one implementation to the runner. The runner starts it as a child process and talks to it over its standard input and output. This document is everything an adapter author needs.

Two things check an adapter without running a single case: message schemas in `schema/adapter-protocol.schema.json`, which you can run in your own tests in any language, and `kcs check-adapter <command>`, which probes a running adapter. Both are described under "Checking an adapter" in [`design.md`](design.md). The schemas cover every operation below. `kcs check-adapter` has probes specific to `acdc.issue` and `acdc.present`, run when an adapter lists them, and none yet for `acdc.verify` or `exn.verify`.

## Transport

- The runner writes requests to the adapter's standard input, one JSON object per line, UTF-8, terminated by `\n`.
- The adapter writes exactly one response per request to its standard output, one JSON object per line, in the same order.
- Anything the adapter writes to standard error is drained continuously, so the adapter never blocks on a full pipe, and only the last 64 KiB per case is kept for the conformance report as diagnostics; the rest is discarded. Logging belongs there, never on standard output.
- Every stream travels as raw bytes, hex-encoded, whatever domain or serialization it contains. The adapter must hand those bytes to its implementation unchanged, so that the implementation does its own domain sniffing and framing. Other binary values, such as raw primitive values, are also hex.
- The runner sends one request at a time and waits for its response. An adapter never has to handle concurrent requests.
- Each request is independent. An adapter must start every request from empty state — no identifiers, keys or events left over from an earlier request. That is the most common way for an adapter to produce results that depend on case order.
- The runner bounds every response's size and every request's duration. An adapter that exceeds either, exits, or writes something that is not a valid response fails every assertion in that case, and is restarted before the next case. A parser that panics or loops on a hostile stream is therefore a failure, not a gap in the results.
- The runner ends a session by closing the adapter's standard input. The adapter should exit with status 0 when it reads end of file.

## Messages

Every request has an `op` naming the operation and an `id` the response must echo. A request the runner sends for a case also carries `profile`, the name of the profile that case belongs to (its own, so a layered run of `sedi-1` sends its `acdc-v1.0` prerequisite cases with `"profile": "acdc-v1.0"`); `hello` and the probes of `kcs check-adapter` carry none. A profile may make a choice the specifications leave open, more strictly than the text, so an implementation may offer an option for it: an adapter may use `profile` to set such an option, and nothing else, and with no `profile`, or one it does not know, the implementation's default applies (this.i 9d1qrqge). An adapter never computes any part of a verdict from `profile`. If a request cannot be read at all — it is not valid JSON, or has no usable `id` — the adapter answers with an error response whose `id` is `null`, and keeps running. Every response is either a result or an error:

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
{"id": 0, "op": "hello", "protocol": 1, "supported": [1]}
```

`supported` lists every protocol version the runner can speak, and `protocol` is the highest of them. The adapter chooses the highest version in `supported` that it also implements, and answers with that version in `protocol`; the rest of the session uses it. An adapter that implements none of them answers with an `error` response, and the runner stops. Two rules, binding from version 1 on, are what make that work: an adapter ignores any request field it does not recognise, and it never rejects a `hello` because `protocol` is higher than the versions it implements — it negotiates from `supported` instead. Together they let a version-1 adapter keep working with a runner that has moved on to version 2.

The adapter answers with the protocol version it chose and what it is:

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

`features` is drawn from the feature vocabulary in `profiles/features.json`. `features` lists everything the implementation and adapter together can do, and is what the runner uses to decide which cases to send. `composes` is a subset of `features`: it marks the behaviours that the adapter supplies itself rather than delegating to the implementation — for example, escrow and routing on top of a library that only verifies events. It is reported in every conformance report and every conformance claim, so that nobody credits the implementation with what the adapter did. The runner refuses to run an adapter that answers with a protocol version outside `supported`, whose `hello` is missing or malformed, or whose features or composed behaviours are not in the vocabulary. In each case it prints which field was wrong and what it expected, exits with a non-zero status, and runs no cases. These are runner-side refusals, not test failures, because no case was attempted.

## `cesr.parse`

Decode a stream.

```json
{"id": 1, "op": "cesr.parse", "stream": "7b2276223a..."}
```

The stream is hex-encoded bytes and may be in either domain or mix them. The result is the decoded items, a rejection, or a summary of an accepted stream:

```json
{"id": 1, "result": {"items": [
  {"kind": "genus", "start": 0, "end": 8, "code": "-_AAACAA", "genus": "AAA", "version": "2.00"},
  {"kind": "message", "start": 8, "end": 351, "proto": "KERI", "version": "2.0", "serialization": "JSON", "size": 343},
  {"kind": "counter", "start": 351, "end": 355, "code": "-C", "size": 23, "group_end": 447},
  {"kind": "counter", "start": 355, "end": 359, "code": "-K", "size": 22, "group_end": 447},
  {"kind": "indexed", "start": 359, "end": 447, "code": "A", "index": 0, "raw": "9c1f..."}
]}}
{"id": 1, "result": {"reject": {"class": "truncated"}}}
{"id": 1, "result": {"accepted": {"consumed": 447}}}
```

**Items, or a summary.** Reporting items needs to know where each one starts and ends, and some implementations parse a stream correctly without ever saying where anything was. An adapter must not work the offsets out itself — from counts, code tables or a parser of its own — because then the adapter's parser is what gets tested. So the protocol separates the two:

- An adapter that declares the feature `cesr.item-extents` reports the decoded items of every stream its implementation accepts. Only such an adapter is sent a case with a `decoded` assertion.
- Any adapter may instead answer an accepted stream with a summary: `{"accepted": {"consumed": n}}`, where `n` is the number of bytes the implementation consumed, a non-negative integer no larger than the stream. An adapter that cannot report items should answer this way rather than with an `unsupported` error, because a summary is evidence and an error is not.

A case whose assertions are all rejections does not need `cesr.item-extents`, so it is sent to every adapter that declares the case's other features. A rejection passes it; a summary fails it, because the implementation accepted a stream it must reject. A summary given to a case with a `decoded` assertion fails the whole case as malformed, as does a summary whose `consumed` is larger than the stream.

`start` and `end` are byte offsets into the stream, and `end` is where the item's own encoding ends. Report what is on the wire, not what your implementation infers. Items are reported in stream order, and a group's members follow its count code. There are five kinds:

- **`genus`**: a genus/version code such as `-_AAACAA`. `code` is the whole eight-character code, `genus` its three genus characters, and `version` the version it selects. It has no size and introduces no group: the specification says such a code "MUST NOT provide a count".
- **`counter`**: any other count code. `code` is its hard part (`-K`, `--C`), `size` the value of its size digits as encoded, and `group_end` the offset at which your implementation ended the group the code introduces. The runner compares `group_end` with the case, so a size read as a number of items rather than quadlets or triplets ends the group in the wrong place even when `size` is right.
- **`primitive`**: `code` is the hard part of the code (for a variable-size code, without its size digits, e.g. `6B`) and `raw` the raw value in hex, without lead bytes.
- **`indexed`**: an indexed signature with `code`, `raw`, and exactly the index fields its row of the indexed code table defines: `index` always, and `ondex` only when the row gives it a nonzero ondex length, reported as encoded.
- **`message`**: a body framed by a version string. A native CESR body is reported as its count code and primitives.

Versions are rendered in decimal as major, a full stop, and minor. A message's `version` is the protocol version from its version string with the minor unpadded (`CAA` is `2.0`, `CAQ` is `2.16`, legacy `10` is `1.0`). A genus item's `version` is the code table version with the minor as at least two digits (`CAA` is `2.00`, `BAA` is `1.00`, `CAQ` is `2.16`), the form the specification uses for code tables ("Version 2.00").

The runner compares the reported items with the expected items exactly: the same items in the same order, each with exactly the fields this section gives it and the same values.

**End of input.** The stream in a `cesr.parse` request is complete. This is a rule of this protocol, not of the CESR specification, which also describes live streams where a parser waits for more bytes. An adapter must treat the end of the stream as final: an item, count code, group or body that the stream ends inside is a rejection, never a reason to wait, and a summary's `consumed` never counts bytes beyond the stream. An adapter that waits fails the case by timing out.

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

After delivering each message, the adapter must drive its implementation to quiescence: process everything it can, including anything held in escrow that the new message unblocks, until nothing further changes. If an implementation's escrow processing is timer-driven, the adapter must trigger it directly rather than wait.

```json
{"id": 3, "result": {
  "dispositions": [
    {"initial": "seen", "final": "seen", "trunk": true},
    {"initial": "seen", "final": "seen", "trunk": false},
    {"initial": "pending", "final": "seen", "trunk": true, "reason": "partially signed"},
    {"initial": "rejected", "final": "rejected", "trunk": false, "reason": "no verified signature"}
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

`dispositions` has one entry per message, in order, and each entry gives three readings, defined in [`design.md`](design.md) under KERI:

- `initial` is the message's state at quiescence after its own delivery, and `final` its state at quiescence after the last message. Each is `seen` if the implementation has accepted the message into its copy of the KEL ("first seen"). Otherwise it is the most specific of `pending` (held, to be accepted later if what it waits for arrives), `rejected` (dropped) and `duplicitous` (recorded as conflicting with an event already seen) that your implementation knows. An implementation that does not distinguish these may report `rejected` for any message it has not accepted, and is graded accordingly.
- `trunk` is `true` if, at quiescence after the last message, the message is a key event on the trunk of its KEL, the undisputed path. It can be `true` only when `final` is `seen`. An event that a superseding rotation displaced is reported with `final` `seen` and `trunk` `false`: it is still in the KEL, but off the trunk. For a key event, an implementation without superseding recovery reports `trunk` equal to whether `final` is `seen`; a receipt is never on the trunk, as the next paragraph says.

A receipt is reported in the same terms: `seen` if the implementation attached its signatures to its copy of the event, `pending` if it holds the receipt, `rejected` if it dropped it, and `trunk` always `false`, because a receipt is not a key event. `reason` is optional and informative. Report what the implementation holds, even where it contradicts an earlier reading; the cases grade it. Because a seen message is always seen (KERI spec line 1788), a message reported `seen` on arrival cannot shed that by a later contradictory reading: a final `not-seen` assertion still fails it, and a key-state assertion conditioned on it still applies. This is a safety rule, not a liveness one — it closes the escape from a MUST, and does not run the other way. A `final seen` assertion is still graded against the reported final reading, so an adapter that reports the message finally dropped earns no acceptance credit from the earlier `seen`.

`key_states` has one entry for every identifier the implementation ends up holding seen events for, describing the key state at the end of its trunk. Report thresholds as your implementation holds them, as a string or as nested lists of fraction strings; the runner normalizes both sides before comparing.

## `keri.emit`

Build and sign an event from raw keys and parameters.

```json
{"id": 4, "op": "keri.emit", "event": {"t": "icp", "...": "..."}, "seeds": {"DAbc...": "a1b2..."}}
{"id": 4, "result": {"stream": "7b2276223a224b45..."}}
```

The exact shape of `event` for each event type is defined by the case schema, `schema/case.schema.json`, which is added with the first KERI cases. The runner checks the event body byte for byte, checks that every signature verifies, and parses the attachments to check that they carry the right signatures with the right indexes. How the attachments are grouped is up to the implementation.

## `acdc.verify`

Judge one ACDC against a bundle of everything it depends on. This operation and `exn.verify` are specified ahead of the first ACDC and exchange-message cases, so that their design can be reviewed before any case exists. The message schemas and the runner accept both.

```json
{"id": 5, "op": "acdc.verify", "perspective": {"role": "validator"},
 "kels": [
   {"stream": "2d5f4141414341417b2276223a224b455249...", "source": "issuer"},
   {"stream": "2d5f414141434141...", "source": "upstream issuer"}
 ],
 "registry": [{"stream": "2d5f4141414341417b2276223a2241434443..."}, {"stream": "..."}],
 "schemas": ["7b2224696422..."],
 "acdcs": [{"stream": "2d5f414141434141..."}, {"stream": "..."}],
 "presented": {"stream": "2d5f4141414341417b2276223a2241434443..."}}
```

Every stream is hex-encoded, and the adapter hands each to its implementation unchanged, as it does for `cesr.parse`. Every stream in `kels`, `registry`, `acdcs` and `presented` begins with the genus/version code of the CESR table its attachments use: `-_AAACAA` (hex `2d5f414141434141`) in the normative profile, as every KERI case's stream does, so that no case depends on a parser's default table. A stream in the keripy 1.x interop profile carries no genus/version code, because keripy 1.x cannot read one, and so depends on that default openly (`generators/SPEC-ISSUES.md`, G1).

- `kels` holds the KERI messages of every KEL involved, in delivery order: those of the issuer of every ACDC in the bundle, and of any delegator or issuee the case needs. The adapter delivers them as `keri.process` would, driving the implementation to quiescence after each one. `source` is a label for diagnostics.
- `registry` holds the registry events (`rip`, `bup`) of every registry an ACDC in the bundle names, each with its attachments, such as the reference to the key event that seals it and any disclosed blinded state block. It may be empty.
- `schemas` holds JSON Schema documents, each the hex encoding of a compact JSON document. They are not CESR streams and carry no version string or genus code. The list may hold schemas no ACDC uses, and it may lack one that an ACDC or an edge names.
- `acdcs` holds every ACDC in the presented ACDC's provenance DAG: the far nodes its edges point to, their far nodes, and so on to the leaves, each once however many edges point to it, each with its attachments and in the variant the case chooses. It may be empty. The DAG holds at most 16 ACDCs, the presented ACDC included, so `acdcs` has at most 15 entries, and its longest path from the presented ACDC has at most 8 edges.
- `presented` is the ACDC to judge, in whatever variant the case uses, with the attachments that carry or point to its issuer's commitment.
- An optional `expect_schema` names, by SAID, the schema the validator expects this kind of ACDC to have. Cases that test that expectation (ACDC specification line 250, a SHOULD) send it; the rest do not.

- An optional `presentation` gives the context the ACDC was presented in: `messages`, the exchange messages that delivered it, each with its attachments and in order, ending with the message that carries or names the presented ACDC (an IPEX grant, for example), and `verifier`, the AID of the verifier it was presented to. The adapter delivers `messages` after `kels`, as `exn.verify` delivers its messages, and its implementation judges the ACDC as presented by the sender of the last message to that verifier. A case sends `presentation` only to an adapter that declares the feature `acdc.presentation`, because an adapter ignores a field it does not recognise, and an implementation that ignored the context would answer as if nobody in particular had presented the ACDC. Without `presentation`, `acdc.verify` behaves exactly as described here.

The bundle is the whole world. An adapter must not fetch anything, follow a URL or an OOBI, or consult a clock: whatever the bundle lacks does not exist for this request, and a `dt` field or an expiry attribute is never compared with the current time. If an implementation reads the clock, the adapter must fix it.

```json
{"id": 5, "result": {
  "verdict": "valid",
  "reason": "sealed in issuer ixn 1",
  "registry": {"rd": "EKa1...", "n": 1, "d": "EBc4...", "td": "EAcd...", "ts": "issued"},
  "edges": [
    {"near": "EAcd...", "path": "e.le", "n": "EFar...", "valid": true},
    {"near": "EFar...", "path": "e.qvi", "n": "EQvi...", "valid": true}
  ]
}}
```

`verdict` is one of three values, defined in [`design.md`](design.md) under ACDC:

- `valid`: the ACDC verified against the bundle.
- `invalid`: something in the ACDC, or in something it depends on, failed to verify.
- `incomplete`: something the ACDC needs is absent from the bundle.

Cases in the normative profiles grade valid against not valid. `invalid` and `incomplete` both count as not valid there, and which of them an adapter reports is recorded but never decides a normative assertion. A layered profile may grade the difference: `sedi-1` does, at INTEROP, because a relying party rejects an invalid ACDC and retries an incomplete one. There is no `revoked` verdict: a revocation is reported in `registry`, and what it means for the verdict is outside the normative cases.

An input the implementation cannot parse or frame, whether the presented ACDC or anything else in the bundle, is a verdict, never an error: `invalid` if the presented ACDC itself cannot be parsed, and otherwise whatever the implementation concludes without the element it could not read. An implementation that cannot evaluate part of a bundle, such as a kind of registry, an edge operator or a kind of commitment, must answer `incomplete`, never `valid`. That is failing closed, and it is also what lets a case that checks a refusal run against every adapter: such a case requires no feature that an adapter can decline, as [`design.md`](design.md) explains under ACDC. An `unsupported` error is never the right answer to an `acdc.verify` case the runner sent, and it fails every assertion in the case, as any error does.

`reason` is optional and informative.

`registry` describes the verified head of the registry that the presented ACDC's top-level `rd` field names, or is `null` when the ACDC has no top-level `rd` or the implementation holds no verified inception for it. Its fields are the registry's SAID `rd`; the sequence number `n`, as an integer, and SAID `d` of the last event in the verified chain; and that event's transaction ACDC SAID `td` and state `ts`, which are reported under these names whatever labels the event carries on the wire. For a blindable update whose blinded block was not disclosed, `td` and `ts` are `null`. The verified chain starts at the registry's inception and ends at the last event before the first one that fails a check, as step 5 of the decision procedure in [`design.md`](design.md) describes. A registry-state assertion applies only when `registry` is not `null`, as a KERI key-state assertion applies only when its message was seen.

`edges` lists every edge the implementation evaluated anywhere in the provenance DAG, each once. An edge is identified by `near`, the SAID of the ACDC it belongs to, and `path`, the chain of field labels from that ACDC's top-level `e` field joined by full stops. Each entry also carries `n`, the value of the edge's own `n` field (the far node SAID the near node claims, not one the implementation recomputed), and whether the edge is `valid`; `n` is informative and no assertion grades it. An adapter that did not reach the edges, because an earlier step failed, or that stopped at the first failing edge, reports only what it evaluated. An edge assertion applies only when the edge it names is reported, except that a `valid` verdict commits the adapter to a failing edge whose check is a MUST, and whether an edge is reported is graded separately at SHOULD, as [`design.md`](design.md) explains under Edges.

The features these cases require are `acdc.version-2.x`, which every ACDC case requires together with the KERI base features, and the declinable features `acdc.edges` and `acdc.registry.bup`, which only liveness assertions and the assertions that an edge or a registry is reported require. `acdc.registry.upd` is added with the first cases that use non-blindable registry updates. `acdc.presentation` marks an implementation that judges an ACDC in its presentation context; only cases that send `presentation` require it, and the `sedi-1` profile requires it of any adapter that claims the profile. The non-normative profile `acdc-keripy-1x-interop` adds `acdc.keripy-1x`, keripy 1.x's ACDC field set and SAID computation, and `acdc.ptel-1x`, keripy 1.x's issuance and revocation registry. These names are in the feature vocabulary, `profiles/features.json`.

## `acdc.issue`

Issue credentials, as an implementation issues them: with its own keys, salts, registry nonces and clock (this.i 2u2ps8mt). The request asks for an issuance, not for bytes, and the runner grades the result by verifying it. The message schemas and `kcs check-adapter` accept this operation and `acdc.present`; sedi-1's holder cases are the first `acdc.present` cases.

```json
{"id": 7, "op": "acdc.issue",
 "roles": ["issuer", "holder"],
 "schemas": ["7b2224696422..."],
 "credentials": [
   {"name": "core", "issuer": "issuer", "issuee": "holder", "schema": "EBdX...",
    "attributes": {"givenName": "Guy"}, "registry": "bup"},
   {"name": "guardian", "issuer": "holder", "schema": "EBdX...", "attributes": {"role": "parent"},
    "registry": "bup", "edges": {"core": {"credential": "core", "o": "I2I"}}}
 ]}
```

- `roles` names the identifiers the implementation creates for the request, each a new transferable identifier with no witnesses and no delegator. Nothing about them is given: the implementation makes its own keys.
- `schemas` holds the JSON Schema documents the credentials name, each the hex encoding of a compact JSON document whose `$id` is its SAID, as in `acdc.verify`.
- Each entry of `credentials` asks for one credential: its `name` in the request, the role that issues it, the role it is issued to (`issuee`, absent for an untargeted credential), its schema's SAID, its attribute values by label, and its registry kind: `bup`, a blindable registry of its own, or `none`, which asks for a direct issuance with no registry, the ACDC carrying no `rd` and committed by the digest seal `{d}` of its SAID in the issuer's KEL (ACDC line 1667; this.i 92zkyy59). The implementation adds the attribute block's `d`, `u` and `i` as its rules say, and nothing else.
- `edges`, when present, is the edge section asked for. Each label names another credential in the request by `name`, with the operators asked for in `o` (a string or a list), or is a group of such labels with its own `o` (`AND` or `OR`). A credential's edges name only credentials the request also issues, so the request is issued far nodes first.

```json
{"id": 7, "result": {
  "kels": {"issuer": "2d5f414141434141...", "holder": "2d5f414141434141..."},
  "credentials": {
    "core": {"acdc": "2d5f4141414341417b2276223a2241434443...",
             "registry": "2d5f4141414341417b2276223a2241434443...",
             "disclosure": "EG61F_et0sn-CbHLZrbm..."},
    "guardian": {"acdc": "...", "registry": "...", "disclosure": "..."}}}}
{"id": 7, "result": {"refused": {"reason": "an attribute the schema forbids"}}}
```

`kels` holds each role's KEL as a hex stream, every event with its attachments. Each entry of `credentials` holds the ACDC, fully expanded, as a genus-pinned hex stream with no attachments; the credential's registry as one genus/version code followed by its events' bodies, in order; and the head update's blinded state block as qb64 text, with or without its group code, when the registry is blindable. A credential asked for with registry kind `none` has neither a registry nor a disclosure. The result has one KEL per role and one entry per credential, and nothing else.

The runner grades the result by verifying it, and never by comparing its bytes with a case's:

- every KEL event's SAID, sequence number and prior, an inception's self-addressing prefix and its commitment to next keys (each role must be transferable), and every event's Ed25519 indexed controller signatures against the key state it is signed under, to its threshold, with a rotation's new keys against the prior next-key digests. A witnessed or delegated KEL, a weighted threshold or a signature code other than `A` or `B` is beyond what the runner verifies, and a result that uses one fails the check rather than passing unverified;
- every registry event's SAID, sequence number and prior, each anchored on the issuer's verified KEL by a seal the case's profile accepts, and the head's disclosure, which must hash to the head update's BLID and record the credential as issued; for a credential asked for with no registry, that none was returned, that the ACDC names none, and that the digest seal `{d}` of its SAID is on the issuer's verified KEL;
- each ACDC's genus/version code, type (`acm`), version string, field order (ACDC line 32), most compact SAID and every nested SAIDed block's own SAID, issuer, schema (one the request carries, whose SAID verifies) and registry, its attribute block (exactly the attributes asked for, with their values, the issuee asked for, and a 128-bit salt where it has one), and each edge asked for: its own SAID in `d`, the far credential's SAID, the operators asked for (or, where none were, absent or the default), and whether they hold between the two credentials as issued.

What legitimately varies (SAIDs, salts, nonces, stamps, keys and prefixes) is checked for what it must be, never for what it is. The runner checks every count and size before it hashes or verifies anything, so its work is bounded by its own limits, not by what the adapter returned.

An implementation that refuses an issuance, because an attribute breaks its schema or an edge asks for something its rules forbid, answers `refused` with an informative `reason`. A refusal is a result, not an error, so a case can require one: a case that must be refused fails when the adapter issues anything, and a case that must be issued fails when the adapter refuses.

## `acdc.present`

Present one held ACDC in a chosen disclosure form. The runner grades the presentation itself, never by asking the same adapter to verify it (this.i 37ehqmh4). The body is fixed by the held ACDC and the disclosure in every form below, so a case's `presented` check compares it byte for byte, which also checks that it carries the held ACDC's top-level SAID and the SAIDs of its disclosed blocks. The attachments after the body are not fixed, since a holder may or may not point to its issuer's commitment, so they need only be nothing or one attachments group holding one group of seal source couples at `-S`, each a sequence number and a digest; a presentation carries no other group. The stream is at most 1 MiB. A `secrets_absent` check lists every string of the held ACDC that the disclosure hides and fails if any appears in the response raw, as hex in either case, Base64, Base64url, JSON-escaped or as `\uXXXX` escapes; a `present_refused` check passes on a refusal.

```json
{"id": 8, "op": "acdc.present", "perspective": {"role": "holder"},
 "kels": [{"stream": "2d5f414141434141...", "source": "issuer"}],
 "registry": [{"stream": "..."}], "schemas": ["7b2224696422..."], "acdcs": [],
 "held": {"stream": "2d5f4141414341417b2276223a2241434443..."},
 "disclosure": {"form": "partial", "expand": ["a", "e.le"]}}
```

The bundle is `acdc.verify`'s, with `held`, the ACDC fully expanded as its holder holds it, in place of `presented`, and with the same rule that nothing outside it exists. `disclosure` says what to present:

- `{"form": "compact"}`: every block compacted to its SAID.
- `{"form": "expanded"}`: every block expanded.
- `{"form": "partial", "expand": [...]}`: blocks compacted except those named, each by its label path from the top level (`a`, `e`, `e.le`, `r`). A path that names no block of the held ACDC is refused.
- `{"form": "selective", "disclose": [...]}`: the selectively disclosable attribute aggregate `A` with only the named attribute blocks disclosed, each by the label of its attribute, and every other block left as its blinded SAID. A label that names no block, a label named twice, or an empty list is refused, and so is a selective form of an ACDC with no aggregate.

```json
{"id": 8, "result": {"presented": {"stream": "2d5f4141414341417b2276223a2241434443..."}}}
{"id": 8, "result": {"refused": {"reason": "e.le names no block"}}}
```

`presented` is the presentation as `acdc.verify` takes its `presented`: the ACDC in the chosen form with the attachments that carry or point to its issuer's commitment, beginning with the genus/version code. It must contain nothing the form hides: no hidden attribute value, no salt of a hidden block, no undisclosed blinded state and no hidden issuee block, in any encoding. A holder refuses to present an ACDC that a verifier would refuse, with `refused`, and refuses a disclosure that the ACDC or its schema cannot satisfy. It never answers with a presentation other than the one asked for.

A refusal judges the inputs, so it is only for a request the adapter could read. An `acdc.issue` request without its templates, or an `acdc.present` request whose `form` this protocol does not define, cannot be read, and gets an error response, never `refused`. So does an `acdc.verify` request whose `presentation` names no message or no verifier. `kcs check-adapter` probes all three.

## `exn.verify`

Deliver KERI exchange messages and report whether each was accepted. Its cases belong to the KERI layer and the `keri-v1.0.1` profile, and IPEX is tested through it, because the only normative text about an IPEX message is KERI's text about exchange messages; [`design.md`](design.md) explains why under IPEX.

```json
{"id": 6, "op": "exn.verify", "perspective": {"role": "validator"},
 "kels": [
   {"stream": "2d5f414141434141...", "source": "issuer"},
   {"stream": "2d5f414141434141...", "source": "holder"}
 ],
 "messages": [
   {"stream": "2d5f4141414341417b2276223a224b455249...", "source": "issuer"},
   {"stream": "2d5f414141434141...", "source": "holder"}
 ]}
```

Every stream begins with a genus/version code, as in `acdc.verify`. The adapter first delivers `kels` as `acdc.verify` does, driving the implementation to quiescence after each message, and then delivers `messages` in order: `xip` and `exn` messages, each with its attachments. It drives the implementation to quiescence after each message, and reports each message's state twice: at quiescence after its own delivery, and at quiescence after the last message. The first reading is what catches an implementation that accepts a forged message on arrival, acts on it, and later retracts it, as `keri.process` reads each event as seen after its own delivery.

```json
{"id": 6, "result": {"verdicts": [
  {"on_delivery": "accepted", "verdict": "accepted"},
  {"on_delivery": "rejected", "verdict": "rejected", "reason": "prior SAID does not match"}
]}}
```

`verdicts` has one entry per message in `messages`, in order. `on_delivery` is the message's state at quiescence after its own delivery and `verdict` its state after the last message; each is `accepted` if the implementation accepted the message as valid, and `rejected` otherwise. An assertion that a message must be dropped is checked against both readings, so a message accepted on delivery fails it even if it is later rejected; a message the implementation cannot parse or frame is `rejected`, never an error. `reason` is optional and informative. The messages in `kels` get no entry; they are graded by `keri.process` cases, not here.

A reading describes the delivery: the message together with the attachments it arrived with. A second delivery of the same body is read on its own, so a copy whose own attachments do not verify is `rejected` even after an earlier delivery of that body was accepted.

An exchange message may name an ACDC in its `a` field, as an IPEX grant does. `exn.verify` does not judge that ACDC; a case that needs it judged is an `acdc.verify` case. Exchange-message cases name ACDCs by SAID, so that accepting an exchange message never depends on judging the ACDC it names.

`exn.verify` adds no feature. An adapter that lists the operation receives every exchange-message case whose other features it declares.

## Writing an adapter

Keep it small, and keep it outside the implementation. An adapter builds against a released or pinned version of its implementation and uses only that implementation's public API, so it keeps working whether or not the implementation's maintainers ever host it. Where the implementation lacks an entry point — for example, a library that verifies events but does not route or escrow them — the adapter composes the missing piece on top, declares it in `composes`, and explains it in its README.

The adapters in this repository are working examples, each a small program in its implementation's own language:

- [`adapters/keripy`](../adapters/keripy), in Python, for keripy, with a second instance for keripy 1.2.14 in [`adapters/keripy/keripy-1.2.14`](../adapters/keripy/keripy-1.2.14).
- [`adapters/keriox`](../adapters/keriox), in Rust, for keriox.
- [`adapters/affinidi`](../adapters/affinidi), in Rust, for Affinidi's keri-core and cesr crates.
- [`adapters/signify-ts`](../adapters/signify-ts), in TypeScript, for signify-ts.

Report what the implementation did, not what the case expects. An adapter must never read a case's expected value; the runner never sends it one.
