# Publishing results

The suite publishes conformance results on its site, at <https://bakobo.github.io/keri-conformance-suite/results/>, so that a claim of conformance is something anyone can read and check rather than a private assertion. This page says what a published result is, where each one comes from, and how an implementation's maintainer submits one.

## What a result is

A result is the JSON report that `kcs run --report` writes, unchanged, inside a small envelope that says who produced it. Nothing new is invented between a run and its publication: the page for a result is generated from the report, and the report itself is published beside the page so a reader can check one against the other. The envelope's format is `schema/result.schema.json`.

Each result is one implementation version run against one profile, and its place follows from its content: `results/<implementation>/<version>/<profile>.json`. The first two segments are the implementation name and version that the adapter reported in its hello, lowercased, with every run of characters other than letters, digits and `. + _ -` replaced by a hyphen, so `0.1.8 (said 0.4.3)` becomes `0.1.8-said-0.4.3`. A report is published only if it was run with `--profile`.

## Two kinds of result

Every result carries one of two labels, and the site shows the label on every row and every page.

A result labelled *Reproduced by CI* was produced by this repository's own CI, from an adapter in this repository built against a pinned implementation. Its page links the CI run and names the suite commit it ran. The suite vouches for these results because it performed them.

A result labelled *Submitted claim, not reproduced* was sent by an implementation's maintainer through a pull request. The suite checks that it is well formed and that it agrees with itself, but it did not run it and cannot vouch for it, so the site presents it as its submitter's claim. Submitted results exist because the suite cannot build every implementation, and leaving those implementations out would make the results page say less than is known.

Reproduced results are not committed. The Pages workflow (`.github/workflows/pages.yml`) builds the adapters in `adapters/` at their pins, runs each against the profiles it is meant for, and writes the results while it builds the site, so they are always from the suite as it stands on `main`. The committed `results/` directory therefore holds only submitted results, and a file there that is labelled reproduced is refused. That rule is what keeps the label honest: a pull request cannot claim that CI ran something.

## What the checks refuse

Results are read through one function, `load_results` in `tools/results.py`, which treats every file as untrusted. In order, it refuses:

- more than 2,000 result files, more than 128 MiB of them in total, or any one file over 16 MiB, each judged before the file is parsed;
- anything in `results/` other than its README and files in the layout above, and any symbolic link;
- a file that is not UTF-8 JSON or does not satisfy `schema/result.schema.json`;
- a result whose path is not the one its report implies, or whose label the directory may not hold;
- a report that does not agree with itself: a case outside the profile it names, a case outcome its assertions do not imply, or a summary or verdict different from the one the runner computes from its cases.

CI runs the same checks on every pull request (`scripts/results check results`), so a submission that would break the site is caught before it merges. Text from a result is escaped before it reaches a page.

## Submitting a result

1. Run the suite against your adapter, for one profile, and keep the report:

    ```sh
    uv run kcs run --adapter /path/to/your-adapter --profile cesr-1.0 --report report.json
    ```

2. Open a pull request against this repository that says what you ran: the implementation, its version and commit, the adapter and where its source is, and the profile. Note the pull request's URL.

3. Put the report into its envelope. This writes it at the path its content implies and refuses if the report does not pass the checks above:

    ```sh
    uv run python scripts/results wrap report.json --into results --date 2026-10-09 \
      --submitted --submitter "Your Name" --pull-request https://github.com/bakobo/keri-conformance-suite/pull/NN
    ```

4. Commit the new file under `results/` to the pull request's branch and push. CI checks it, and a maintainer reviews it.

A result for an implementation version and profile that is already published is replaced by deleting the old file in the same pull request, so the history keeps both. A report is published as it is; do not edit it, because an edited verdict or summary no longer matches the cases and is refused.

## Reading a result

Results are grouped by the suite version they ran against, and no table compares results from different suite versions, because a later suite version can add cases that an earlier pass never faced. Each cell gives the verdict and the active MUST and SHOULD assertions that passed and failed, because a conformance claim is never the MUST verdict alone (see Versioning in [the design](design.md)). Each result's page also lists the behaviours its adapter composes, the passes that are only keripy agreeing with cases it generated (self-agreement), and every case with its outcome.

The terms a result's page uses are explained below. Each case id on a page links to the case file the run used: for a reproduced result, the file at the suite commit CI ran; for a submitted result, which names no suite commit, the file on `main`.

### Verdict

A run of a normative profile gets one of five verdicts, decided by the MUST assertions of its active cases alone:

- `conformant`: every active MUST assertion that was evaluated passed, and at least one did.
- `not-conformant`: at least one active MUST assertion failed.
- `incomplete`: none failed, but at least one uses a check this runner version cannot evaluate.
- `no-evidence`: no active MUST assertion passed or failed, so the run shows nothing. This is what a run gets when the adapter declared none of the features the profile's cases need, so the runner sent it none of them.
- `aborted`: the run stopped part way, because a restarted adapter refused the handshake or changed it. The page gives the reason, and the report holds the cases completed before it stopped.

A run of a non-normative profile, such as `keripy-1x-interop`, gets an interoperability verdict instead, by the same rule applied to its INTEROP assertions: `interoperable`, `not-interoperable`, `incomplete` or `no-evidence`. It is never a conformance claim ([Practice in the design](design.md#practice)).

Every verdict is scoped to the cases the runner sent, which are the ones whose features the adapter declared.

### Assertion counts

Each case makes several assertions, each at a requirement level: MUST, SHOULD, or INTEROP for an assertion that rests on common practice rather than a clause. A page counts the assertions of active cases at each level by outcome: `pass`, `fail`, `not-applicable` (a conditional assertion whose condition did not hold), `not-implemented` (this runner version cannot evaluate it) and `not-supported` (its case was not sent). Draft and disputed cases are run and deprecated cases skipped, and all three are listed but never counted. SHOULD results are always shown beside the verdict, because in the KERI layer a validator that accepts nothing passes every MUST assertion, and only its SHOULD failures give it away.

### Composes

The behaviours the adapter supplies itself rather than delegating to the implementation, such as escrowing out-of-order events on top of a library that only verifies them. A result that composes something is a claim about the implementation and the adapter together, never about the implementation alone. `nothing` means every behaviour tested is the implementation's own. The adapter declares these in its handshake ([the `hello` message](adapter-protocol.md#hello)).

### Self-agreement

A pass where keripy both produced the case's expected value and is the implementation under test. It shows only that keripy agrees with itself, so the page counts such passes separately. Most cases' expected values are computed from the specification, not by keripy, and those passes are never self-agreement.

### Cases not supported

Active cases the runner did not send, because they need a feature or an operation the adapter did not declare. They count neither for nor against the verdict, which is why a verdict is scoped to the features the adapter declared. The Notes column of the page's case table names what each one was missing.

## Building the site locally

The site is built by [Zensical](https://zensical.org), pinned exactly in `pyproject.toml`'s `site` dependency group because it is still before its first major release. Its input is plain markdown, assembled by `scripts/site-source` from the README, `docs/` and the results, so the generator can be replaced without touching the content.

```sh
uv sync --locked --group site
uv run python scripts/site-source
uv run zensical build --clean --strict
```

The site is then in `_site/html`. To include reproduced results in a local build, run the adapters, wrap each report with `scripts/results wrap --reproduced` into a directory of their own, and pass that directory to `scripts/site-source --reproduced`; `scripts/reproduce-results` does all of this for the adapters it finds built.
