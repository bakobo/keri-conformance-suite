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
        Every assertion in a case cites the spec clause it tests and carries that clause's requirement level; MUST assertions decide conformance and SHOULD and MAY results are reported separately. Revised 2026-10-01 after the keri-review-panel (KRT-F3): the level was first attached to whole cases, which is wrong because one case checks several things at different levels (an out-of-order delivery checks a MUST not-accepted-early and a SHOULD accepted-after-escrow, since the KERI spec only says a validator SHOULD escrow). Behaviour no clause requires (escrow kinds, error taxonomies, HTTP endpoints, the CESR 1.00 count-code table, roles without a spec) goes into a labelled non-normative profile. Rejected testing keripy behaviour wholesale because it would make the suite the de facto spec. Tradeoff: some genuinely useful interop checks are demoted to non-normative profiles, and case files are larger.
    Coarse, normative verdict vocabulary = decision:
      nid: 4mc8vyhg
      why: >-
        KERI dispositions are decided by an ordered procedure, each step citing its clause: malformed, then unverifiable against held key state (rejected; MUST drop, never escrow), then valid but not yet acceptable (not accepted; SHOULD be pending), then conflicting (superseded under the recovery rule, else not accepted; MAY be duplicitous), else accepted. MUST assertions grade only accepted versus not accepted, initially and finally, both read at escrow quiescence, which the adapter must drive; the finer dispositions are graded at their own clause levels. Revised 2026-10-01 after the keri-review-panel (KRT-F1, KRT-F2, SPC-F3, SEC-F2, SEC-F7): the first version had four overlapping dispositions with no precedence, no value for a superseded event, no defined read point, and no stated validator perspective; cases now state a perspective. Rejected keripy's escrow taxonomy as normative, and rejected letting keripy decide dispositions, because the suite must be able to find keripy wrong. Tradeoff: generators must compute dispositions from the procedure rather than read them off keripy.
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
        Case inputs are identified by the protocol versions on the wire, not by keripy release numbers, because keripy's 2.x line implements version 1.0 of most specs while emitting 2.00 codes. A profile's status comes from the maturity of the text its assertions cite, not from wire versions. Revised 2026-10-01 after the keri-review-panel (SKP-F3): the first version made every 2.x case draft and advisory, which would have demoted the count-code defect that motivated the suite even though CESR spec v1.0 states it as a MUST. Expected values from a moving implementation (keripy main ahead of a release) are draft and pinned to a commit; behaviour with no normative text, such as keripy 1.x's CESR 1.00 count codes, goes into a profile named for interoperability with keripy 1.x. Tradeoff: draft cases need regeneration as keripy moves, producing new ids when expectations change.
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
        A case that a released implementation, keripy included, handles unsafely (accepts what must be rejected, retains what must be dropped, or crashes or hangs) is a public proof of concept against it. Such a case is held in a private repository, with its scenario, baseline changes and nightly results, until the project has been told privately and has had up to 90 days to ship a fix. The embargo takes precedence over publishing a keripy-contradicting case as disputed. Revised 2026-10-01 after the keri-review-panel (SEC-F5): the trigger first covered only wrongful acceptance and did not say which rule won over the disputed-case rule or how derived artefacts could leak. Rejected publishing immediately (an exploit catalogue) and indefinite holding (lets a project suppress a failure). Tradeoff: the public suite lags what we know, and a private CI path must exist.
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
    Anything but an answer is a failure = decision:
      nid: 7j5hvp2v
      why: >-
        For every case the runner sends, a crash, a hang past the time limit, an oversized or malformed response, or an error reply fails every assertion in the case; only runner-side faults, such as failing to start the adapter, go unscored. Chosen after the keri-review-panel (SEC-F4): routing these outcomes to a neutral harness bucket would let a parser that panics or loops on hostile input escape exactly the must-reject cases built for it, the defect class the survey found. Rejected distinguishing adapter-glue exceptions from implementation exceptions, because the runner cannot see the difference and an adapter could launder failures through it. Tradeoff: a buggy adapter makes its implementation look worse than it is, which pushes adapter quality onto adapter authors.
    Adapters declare the behaviour they compose = decision:
      nid: 0eqxk4w6
      why: >-
        When an adapter supplies logic its implementation lacks (escrow, routing, duplicity detection on top of a verification library), it lists that behaviour in the handshake's composes field, and every result record and conformance claim carries the list. Chosen after the keri-review-panel (SEC-F6): otherwise a claim such as passes every MUST case would credit a bare library with refusing duplicitous state that only the adapter refused. Rejected forbidding composition, which would exclude verification-only libraries such as devrandom's from the KERI layer entirely. Tradeoff: claims become tuples that are harder to summarize.
    IPEX transition cases wait for normative text = decision:
      nid: 69e5z0wq
      why: >-
        The suite tests IPEX exchange messages for well-formedness, signatures and references now, and adds transcript cases classifying valid and invalid next steps only when the specs state a normative transition rule. Chosen after the keri-review-panel (KRT-F5): no clause defines which message may follow which or when a message opens a new exchange, keripy's own handlers disagree, and the first worked example would have failed a route-table-faithful implementation. Rejected deriving the state machine from keripy, which would make the suite the IPEX spec. Tradeoff: contractually protected disclosure, a core motivation, stays untested at the protocol level until the working group acts.
