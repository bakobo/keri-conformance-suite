# Reading a result

The [results page](https://bakobo.github.io/keri-conformance-suite/results/) has a row for each implementation version and a column for each profile it was run against. Each cell gives the run's [verdict](verdicts.md) and its active MUST and SHOULD assertions that passed and failed, because a conformance claim is never the verdict alone. Results are grouped by the suite version they ran against, and no table compares results from different suite versions, because a later suite version can add cases that an earlier pass never faced (Versioning in [the design](design.md#versioning)).

A cell links to the result's own page, which states the claim field by field and lists every case with its outcome. Every case id links to the case file the run used: for a reproduced result, the file at the suite commit CI ran; for a submitted result, which names no suite commit, the file on `main`. The fields that need explaining are below.

## Who produced it

Every result carries one of two labels, and the site shows the label on every row and every page.

A result labelled *Reproduced by CI* was produced by this repository's own CI, from an adapter in this repository built against a pinned implementation. Its page links the CI run and names the suite commit it ran. The suite vouches for these results because it performed them.

A result labelled *Submitted claim, not reproduced* was sent by an implementation's maintainer through a pull request. The suite checks that it is well formed and that it agrees with itself, but it did not run it and cannot vouch for it, so the site presents it as its submitter's claim. Submitted results exist because the suite cannot build every implementation, and leaving those implementations out would make the results page say less than is known.

Reproduced results are not committed. The Pages workflow (`.github/workflows/pages.yml`) builds the adapters in `adapters/` at their pins, runs each against the profiles it is meant for, and writes the results while it builds the site, so they are always from the suite as it stands on `main`. The committed `results/` directory therefore holds only submitted results, and a file there that is labelled reproduced is refused. That rule is what keeps the label honest: a pull request cannot claim that CI ran something.

How to submit a result is in [Publishing a result](publishing-results.md).

## Pass and fail counts

Each case makes several assertions, each at a requirement level: MUST, SHOULD, or INTEROP for an assertion that rests on common practice rather than a clause. A page counts the assertions of active cases at each level by outcome: `pass`, `fail`, `not-applicable` (a conditional assertion whose condition did not hold), `not-implemented` (this runner version cannot evaluate it) and `not-supported` (its case was not sent). Draft and disputed cases are run and deprecated cases skipped, and all three are listed but never counted. SHOULD results are always shown beside the verdict, because in the KERI layer a validator that accepts nothing passes every MUST assertion, and only its SHOULD failures give it away.

## Composes

The behaviours the adapter supplies itself rather than delegating to the implementation, such as escrowing out-of-order events on top of a library that only verifies them. A result that composes something is a claim about the implementation and the adapter together, never about the implementation alone. `nothing` means every behaviour tested is the implementation's own. The adapter declares these in its handshake ([the `hello` message](adapter-protocol.md#hello)).

## Self-agreement

A pass where keripy both produced the case's expected value and is the implementation under test. It shows only that keripy agrees with itself, so the page counts such passes separately. Most cases' expected values are computed from the specification, not by keripy, and those passes are never self-agreement.

## Cases not supported

Active cases the runner did not send, because they need a feature or an operation the adapter did not declare. They count neither for nor against the verdict, which is why a verdict is scoped to the features the adapter declared. The Notes column of the page's case table names what each one was missing.
