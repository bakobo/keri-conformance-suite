# Verdicts

A run's verdict is its one-word summary. It is decided by the assertions of the run's active cases, and it is always shown beside the SHOULD results, because a verdict is never the whole claim ([Reading a result](reading-a-result.md)).

## Conformance verdicts

A run of a normative profile gets one of five verdicts, decided by the MUST assertions of its active cases alone:

- `conformant`: every active MUST assertion that was evaluated passed, and at least one did.
- `not-conformant`: at least one active MUST assertion failed.
- `incomplete`: none failed, but at least one uses a check this runner version cannot evaluate.
- `no-evidence`: no active MUST assertion passed or failed, so the run shows nothing. This is what a run gets when the adapter declared none of the features the profile's cases need, so the runner sent it none of them.
- `aborted`: the run stopped part way, because a restarted adapter refused the handshake or changed it. The page gives the reason, and the report holds the cases completed before it stopped.

## Interoperability verdicts

A run of a non-normative profile, such as `keripy-1x-interop`, gets an interoperability verdict instead, by the same rule applied to its INTEROP assertions: `interoperable`, `not-interoperable`, `incomplete` or `no-evidence`. It is never a conformance claim ([Practice in the design](design.md#practice)).

Every verdict is scoped to the cases the runner sent, which are the ones whose features the adapter declared.
