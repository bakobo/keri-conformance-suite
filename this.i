Prove that KERI-family implementations agree = goal:
  nid: 26kmlhsh
  why: >-
    Implementations of CESR, KERI, ACDC and IPEX outside keripy have no way to show they are correct; a 2026-09 survey of ten Rust codebases found the same defects (for example, CESR 2.0 counters that count items where keripy counts quadlets) that a shared corpus would have caught on day one. Chose a standalone suite of fixed cases with implementation-neutral expected verdicts over adding tests to each spec or each implementation, because the interesting cases cross specs (a KEL case is also a CESR case) and test data churns at a different rate from spec prose. Tradeoff: a separate artifact to govern and keep in step with the specs, and a risk of enshrining keripy's behaviour as law, which the case-provenance and disputed-case rules exist to contain.
  children:
    The spec text is the authority, not keripy = constraint:
      nid: 9vnp6fz7
      why: >-
        keripy generates most expected values, so without a counterweight its bugs become law and the suite certifies sameness-with-keripy rather than conformance. Chose spec authority with keripy as a provisional generator: a case whose keripy-generated expectation contradicts a cited clause is marked disputed, excluded from conformance tallies, and taken to the spec working group by a maintainer; the suite never resolves the dispute itself. Rejected treating keripy as the reference outright (simpler, but it is what the survey showed already happens informally). Tradeoff: disputed cases sit unresolved for as long as the working group takes, and an implementation can match keripy and still be told the question is open.
    No case without a normative clause = decision:
      nid: 8v0gc5w4
      why: >-
        A case must cite the spec clause it tests, and carries that clause's requirement level (MUST, SHOULD, MAY); MUST cases decide conformance and SHOULD and MAY cases are reported separately. The KERI spec says only that a validator SHOULD escrow under-signed events (spec-body.md, Indexed signatures), so an implementation that drops out-of-order events is conformant on that point and must not be failed for it. Behaviour that only an implementation defines (escrow kinds, error taxonomies, HTTP endpoints, emerging roles such as registrars, observers and jurors) goes into a labelled non-normative profile or waits for a spec. Rejected testing keripy behaviour wholesale because it would make the suite the de facto spec for roles the working group has not defined. Tradeoff: some genuinely useful interop checks are demoted to non-normative profiles.
    Coarse, normative verdict vocabulary = decision:
      nid: 4mc8vyhg
      why: >-
        KERI verdicts are accepted, pending, rejected and duplicitous, reported both as the initial disposition of each message and as its final disposition after the whole stream, plus the final key state of each identifier. These map onto spec language (MUST satisfy thresholds to be accepted; SHOULD escrow; MUST drop unsigned messages). Reason classes and escrow kinds are reported but informative and never fail a case. Rejected keripy's finer escrow taxonomy (out-of-order, partially signed, partially witnessed, delegation) as normative, because the spec does not define it and other implementations name and structure escrows differently. Tradeoff: two implementations can pass the same case for different reasons.
    Published expectations are immutable = decision:
      nid: 9ppgdqn5
      why: >-
        A case id is permanent and its expected verdict never changes; a correction is a new case id with the old case deprecated and pointing to it. This is what keeps the suite maintainable for implementers: a result recorded against suite version X never silently flips meaning, and a regression is always a code change on their side or a new case on ours. Rejected in-place correction, which is cheaper for us and turns every suite release into an unexplained diff for every implementation. Tradeoff: deprecated cases accumulate and ids are not contiguous by topic.
    Fixtures are generated, never hand-edited = decision:
      nid: 4204xnkm
      why: >-
        Cases are produced from small declarative scenario files by generators, and CI regenerates every fixture in a pinned environment and fails on any byte difference. This makes the anti-pattern the survey and the craftsman ledger both warn about, editing an expectation to make an implementation pass, impossible to merge rather than merely forbidden. Rejected committing hand-curated fixtures, which is how cesr-test-vectors stalled with its streams section still TBD. Tradeoff: every new case needs generator support first, and the generators become code we must maintain at the bar of the runner.
    Target versions are wire versions = decision:
      nid: 9fls7thp
      why: >-
        Cases and profiles name what they target by the protocol version strings and codes that appear on the wire (for example KERI10JSON for KERI 1.0 bodies), not by keripy release numbers, because keripy 2.x corresponds to 1.0 of most specs and release numbers would be ambiguous. 1.0 cases are populated first; 2.x cases are built now, generated from keripy main pinned to a commit and marked draft, because SEDI ships on 2.0 before the specs settle. Draft failures are advisory. Tradeoff: a draft profile has to be re-pinned and regenerated as keripy main moves, producing new case ids each time an expectation changes.
    Adapters speak JSON lines over stdio = decision:
      nid: 0qxf76ss
      why: >-
        An implementation is connected through one long-lived adapter process that reads one JSON request per line and writes one JSON response per line, starting with a hello handshake that declares the adapter protocol version, the implementation's identity and commit, and its supported features. Chose stdio JSON lines over a language binding or HTTP because it works for any language, needs no port and no network, and makes an adapter a small standalone program. The runner never sends a case that needs an undeclared feature, so not-supported is decided by the declaration and an adapter cannot use it to hide a failure. Tradeoff: process startup per run and JSON escaping of binary CESR, which travels hex-encoded.
    Adapters work without upstream acceptance = decision:
      nid: 93t4d880
      why: >-
        Each adapter builds against a released or pinned version of its implementation using only that implementation's public API, never patches it, and composes any missing entry point on top, as the survey's host layer did for devrandom. CI builds every adapter against its pin. Chose this because upstream acceptance is uncertain (each project has its own licence, governance and priorities, and may reasonably decline to host an adapter) and the suite must not depend on it. Tradeoff: adapters carry glue code that an upstream project could have exposed more cleanly, and they can lag behind implementation API changes.
    The keripy adapter stays in the suite = decision:
      nid: 5x86gnx3
      why: >-
        keripy is both a generator and an implementation under test, so its adapter is maintained here permanently rather than offered upstream. Every result where keripy produced the expected value and keripy is also the implementation under test is flagged self-agreement, because a defect shared by generator and implementation passes silently; the flag is the witness-qualifier keripy-tests-keripy blind spot carried over. Tradeoff: we own an adapter for a moving codebase we do not control.
    Cases that disclose a vulnerability are embargoed = decision:
      nid: 5cz9hck0
      why: >-
        A must-reject case that a released implementation wrongly accepts is a public proof of concept against it. Such a case is held out of the public tree until the affected project has been told privately and has had up to 90 days to ship a fix, matching SECURITY.md. Rejected publishing immediately, which would turn the suite into an exploit catalogue, and rejected indefinite holding, which would let a project suppress a conformance failure. Tradeoff: the public suite can lag what we know.
    Bakobo methodology is incubation-only = decision:
      nid: 3l9vqm6q
      why: >-
        this.i, tick and the Bakobo standards block are Bakobo's practice, not the KERI Foundation's, and will be removed at the handoff (Daniel, 2026-10-01). So every rule a future maintainer needs is also written as prose under docs/, and this.i may explain why but is never the only home of a rule. Rejected keeping the reasoning only in this.i, which would leave the Foundation with rules and no rationale after removal. Tradeoff: some reasoning is stated twice and can drift; docs/ wins if they disagree after handoff.
    Apache-2.0 for test vectors, not CC-BY-4.0 = deviation:
      nid: 4g6579k6
      deviates-from: bakobo/dev standards/oss-posture.md item 1 (CC-BY-4.0 for corpora)
      scope: cases/, scenarios/ and profiles/ in this repository
      approved-by: Daniel Hardman, 2026-10-01
      why: >-
        The posture standard licenses corpora under CC-BY-4.0, but these vectors are test fixtures that implementations copy into their own Apache- and MIT-licensed test trees; a second licence on the fixtures would add attribution obligations and a licence-compatibility question to every adopter for no gain. Approved by Daniel, 2026-10-01.
