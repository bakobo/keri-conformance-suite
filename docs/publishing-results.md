# Publishing a result

The suite publishes conformance results on its site, at <https://bakobo.github.io/keri-conformance-suite/results/>, so that a claim of conformance is something anyone can read and check rather than a private assertion. This page says what a published result is and how an implementation's maintainer submits one. What a result's page shows, and who may vouch for it, is in [Reading a result](reading-a-result.md).

## What a result is

A result is the JSON report that `kcs run --report` writes, unchanged, inside a small envelope that says who produced it. Nothing new is invented between a run and its publication: the page for a result is generated from the report, and the report itself is published beside the page so a reader can check one against the other. The envelope's format is `schema/result.schema.json`.

Each result is one implementation version run against one profile, and its place follows from its content: `results/<implementation>/<version>/<profile>.json`. The first two segments are the implementation name and version that the adapter reported in its hello, lowercased, with every run of characters other than letters, digits and `. + _ -` replaced by a hyphen, so `0.1.8 (said 0.4.3)` becomes `0.1.8-said-0.4.3`. A report is published only if it was run with `--profile`.

## What the checks refuse

Results are read through one function, `load_results` in `tools/results.py`, which treats every file as untrusted. In order, it refuses:

- more than 2,000 result files, more than 128 MiB of them in total, or any one file over 16 MiB, each judged before the file is parsed;
- anything in `results/` other than its README and files in the layout above, and any symbolic link;
- a file that is not UTF-8 JSON or does not satisfy `schema/result.schema.json`;
- a result whose path is not the one its report implies, or whose label the directory may not hold;
- a report that does not agree with itself: a case outside the profile it names, a case outcome its assertions do not imply, or a summary or verdict different from the one the runner computes from its cases.

CI runs the same checks on every pull request (`scripts/results check results`), so a submission that would break the site is caught before it merges. Text from a result is escaped before it reaches a page.

## Results of the shipped adapters

The adapters in `adapters/` have their results committed here too, labelled `maintainer-run`, one file per implementation version and profile. Nothing regenerates them at build time: the Pages workflow publishes exactly what is committed, so a push of markdown or result JSON to `main` republishes the site without running any adapter. They are kept current with one local tool, which needs every adapter it runs built at its pin as that adapter's README says:

```sh
uv run python scripts/reproduce-results check     # rerun and compare with the committed results
uv run python scripts/reproduce-results refresh   # rerun and replace them (needs a clean tree)
```

Both take `--adapter NAME` (repeatable) to run only some of the builds: `keripy`, `keripy-1.2.14`, `keriox`, `affinidi`, `signify-ts`. `refresh` records the suite commit it ran from, the date, and who ran it (`--maintainer`, defaulting to `git config user.name`), and rewrites the generated results table in each adapter's README; `scripts/reproduce-results readmes` rewrites only those tables, and CI checks them with `readmes --check`. The workflow `.github/workflows/reproduce.yml` does the same reruns in GitHub Actions when a maintainer starts it, and uploads them, labelled `reproduced`, with the comparison as an artifact; it never commits or publishes them.

## Submitting a result

1. Run the suite against your adapter, for one profile, and keep the report:

    ```sh
    uv run kcs run --adapter /path/to/your-adapter --profile cesr-v1.0 --report report.json
    ```

2. Open a pull request against this repository that says what you ran: the implementation, its version and commit, the adapter and where its source is, and the profile. Note the pull request's URL.

3. Put the report into its envelope. This writes it at the path its content implies and refuses if the report does not pass the checks above:

    ```sh
    uv run python scripts/results wrap report.json --into results --date 2026-10-09 \
      --submitted --submitter "Your Name" --pull-request https://github.com/bakobo/keri-conformance-suite/pull/NN
    ```

4. Commit the new file under `results/` to the pull request's branch and push. CI checks it, and a maintainer reviews it.

A result for an implementation version and profile that is already published is replaced by deleting the old file in the same pull request, so the history keeps both. A report is published as it is; do not edit it, because an edited verdict or summary no longer matches the cases and is refused.

## Building the site locally

The site is built by [Zensical](https://zensical.org), pinned exactly in `pyproject.toml`'s `site` dependency group because it is still before its first major release. Its input is plain markdown, assembled by `scripts/site-source` from the README, `docs/` and the results, so the generator can be replaced without touching the content.

```sh
uv sync --locked --group site
uv run python scripts/site-source
uv run zensical build --clean --strict
```

The site is then in `_site/html`. It holds exactly the results committed under `results/`.
