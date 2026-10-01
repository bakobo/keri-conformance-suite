Prove that KERI-family implementations agree = goal:
  nid: 26kmlhsh
  stage-status: in-progress
  why: >-
    Implementations of CESR, KERI, ACDC and IPEX outside keripy have no way to show they are correct; a 2026-09 survey of ten Rust codebases found the same defects (for example, CESR 2.0 counters that count items where keripy counts quadlets) that a shared corpus would have caught on day one. Chose a standalone suite of fixed cases with implementation-neutral expected verdicts over adding tests to each spec or each implementation, because the interesting cases cross specs (a KEL case is also a CESR case) and test data churns at a different rate from spec prose. Tradeoff: a separate artifact to govern and keep in step with the specs, and a risk of enshrining keripy's behaviour as law, which the case-provenance and disputed-case rules exist to contain.
  children:
    The spec text is the authority, not keripy = constraint:
      nid: 9vnp6fz7
      stage-status: planned
      why: >-
        keripy generates most expected values, so without a counterweight its bugs become law and the suite certifies sameness-with-keripy rather than conformance. Chose spec authority with keripy as a provisional generator: a case whose expected value an implementation's behaviour contradicts, where the cited clause appears to say otherwise, is marked disputed, excluded from conformance tallies, and taken to the spec working group; the suite never resolves the dispute itself. Revised 2026-10-02: conflicts inside the spec's own text no longer make a case disputed (see the keyword-sentence decision). Rejected treating keripy as the reference outright. Tradeoff: disputed cases sit unresolved for as long as the working group takes.
    No case without a normative clause = decision:
      nid: 8v0gc5w4
      stage-status: planned
      why: >-
        Every assertion in a case cites the spec clause it tests and carries that clause's requirement level; MUST assertions decide conformance and SHOULD and MAY results are reported separately. Revised 2026-10-01 after the keri-review-panel (KRT-F3): the level was first attached to whole cases, which is wrong because one case checks several things at different levels (an out-of-order delivery checks a MUST not-accepted-early and a SHOULD accepted-after-escrow, since the KERI spec only says a validator SHOULD escrow). Behaviour no clause requires (escrow kinds, error taxonomies, HTTP endpoints, the CESR 1.00 count-code table, roles without a spec) goes into a labelled non-normative profile. Rejected testing keripy behaviour wholesale because it would make the suite the de facto spec. Tradeoff: some genuinely useful interop checks are demoted to non-normative profiles, and case files are larger.
    Coarse, normative verdict vocabulary = decision:
      nid: 4mc8vyhg
      stage-status: planned
      why: >-
        KERI dispositions are decided by an ordered procedure, each step citing its clause: malformed, then unverifiable against held key state (rejected; MUST drop, never escrow), then valid but not yet acceptable (not accepted; SHOULD be pending), then conflicting (superseded under the recovery rule, else not accepted; MAY be duplicitous), else accepted. MUST assertions grade only accepted versus not accepted, initially and finally, both read at escrow quiescence, which the adapter must drive; the finer dispositions are graded at their own clause levels. Revised 2026-10-01 after the keri-review-panel (KRT-F1, KRT-F2, SPC-F3, SEC-F2, SEC-F7): the first version had four overlapping dispositions with no precedence, no value for a superseded event, no defined read point, and no stated validator perspective; cases now state a perspective. Rejected keripy's escrow taxonomy as normative, and rejected letting keripy decide dispositions, because the suite must be able to find keripy wrong. Tradeoff: generators must compute dispositions from the procedure rather than read them off keripy.
    Published expectations are immutable = decision:
      nid: 9ppgdqn5
      stage-status: planned
      why: >-
        A case id is permanent and its expected verdict never changes; a correction is a new case id with the old case deprecated and pointing to it. This is what keeps the suite maintainable for implementers: a result recorded against suite version X never silently flips meaning, and a regression is always a code change on their side or a new case on ours. Rejected in-place correction, which is cheaper for us and turns every suite release into an unexplained diff for every implementation. Tradeoff: deprecated cases accumulate and ids are not contiguous by topic.
    Fixtures are generated, never hand-edited = decision:
      nid: 4204xnkm
      stage-status: planned
      why: >-
        Cases are produced from small declarative scenario files by generators, and CI regenerates every fixture in a pinned environment and fails on any byte difference. This makes the anti-pattern the survey and the craftsman ledger both warn about, editing an expectation to make an implementation pass, impossible to merge rather than merely forbidden. Rejected committing hand-curated fixtures, which is how cesr-test-vectors stalled with its streams section still TBD. Tradeoff: every new case needs generator support first, and the generators become code we must maintain at the bar of the runner.
    Target versions are wire versions = decision:
      nid: 9fls7thp
      stage-status: planned
      why: >-
        Case inputs are identified by the protocol versions on the wire, not by keripy release numbers, because keripy's 2.x line implements version 1.0 of most specs while emitting 2.00 codes. A profile's status comes from the maturity of the text its assertions cite, not from wire versions. Revised 2026-10-01 after the keri-review-panel (SKP-F3): the first version made every 2.x case draft and advisory, which would have demoted the count-code defect that motivated the suite even though CESR spec v1.0 states it as a MUST. Expected values from a moving implementation (keripy main ahead of a release) are draft and pinned to a commit; behaviour with no normative text, such as keripy 1.x's CESR 1.00 count codes, goes into a profile named for interoperability with keripy 1.x. Tradeoff: draft cases need regeneration as keripy moves, producing new ids when expectations change.
    Adapters speak JSON lines over stdio = decision:
      nid: 0qxf76ss
      stage-status: planned
      why: >-
        An implementation is connected through one long-lived adapter process that reads one JSON request per line and writes one JSON response per line, starting with a hello handshake that declares the adapter protocol version, the implementation's identity and commit, and its supported features. Chose stdio JSON lines over a language binding or HTTP because it works for any language, needs no port and no network, and makes an adapter a small standalone program. The runner never sends a case that needs an undeclared feature, so not-supported is decided by the declaration and an adapter cannot use it to hide a failure. Tradeoff: process startup per run and JSON escaping of binary CESR, which travels hex-encoded.
    Adapters work without upstream acceptance = decision:
      nid: 93t4d880
      stage-status: planned
      why: >-
        Each adapter builds against a released or pinned version of its implementation using only that implementation's public API, never patches it, and composes any missing entry point on top, as the survey's host layer did for devrandom. CI builds every adapter against its pin. Chose this because upstream acceptance is uncertain (each project has its own licence, governance and priorities, and may reasonably decline to host an adapter) and the suite must not depend on it. Tradeoff: adapters carry glue code that an upstream project could have exposed more cleanly, and they can lag behind implementation API changes.
    The keripy adapter stays in the suite = decision:
      nid: 5x86gnx3
      stage-status: planned
      why: >-
        keripy is both a generator and an implementation under test, so its adapter is maintained here permanently rather than offered upstream. Every result where keripy produced the expected value and keripy is also the implementation under test is flagged self-agreement, because a defect shared by generator and implementation passes silently; the flag is the witness-qualifier keripy-tests-keripy blind spot carried over. Tradeoff: we own an adapter for a moving codebase we do not control.
    Cases that disclose a vulnerability are embargoed = decision:
      nid: 5cz9hck0
      stage-status: done
      why: >-
        A case that a released implementation, keripy included, handles with a security consequence (accepts what should be rejected, retains what should be dropped, lets one input disturb the processing of others, or crashes or hangs) is a public proof of concept against it, whatever the level of the assertion. Such a case is held in a private repository, with its scenario, baseline changes and nightly results, until the project has been told privately and has had up to 90 days to ship a fix. The embargo outranks publishing a keripy-contradicting case as disputed. Revised 2026-10-01 (SEC-F5) and 2026-10-02: the trigger was first tied to failing a MUST, but a case can move to SHOULD under the inferred-obligation rule while its security consequence is unchanged; the consequence decides, not the grade. Tradeoff: the public suite lags what we know, and a private CI path must exist.
    Bakobo methodology is incubation-only = decision:
      nid: 3l9vqm6q
      stage-status: done
      why: >-
        this.i, tick and the Bakobo standards block are Bakobo's practice, not the KERI Foundation's, and will be removed at the handoff (Daniel, 2026-10-01). So every rule a future maintainer needs is also written as prose under docs/, and this.i may explain why but is never the only home of a rule. Rejected keeping the reasoning only in this.i, which would leave the Foundation with rules and no rationale after removal. Tradeoff: some reasoning is stated twice and can drift; docs/ wins if they disagree after handoff.
    Apache-2.0 for test vectors, not CC-BY-4.0 = deviation:
      nid: 4g6579k6
      stage-status: done
      deviates-from: bakobo/dev standards/oss-posture.md item 1 (CC-BY-4.0 for corpora)
      scope: cases/, scenarios/ and profiles/ in this repository
      approved-by: Daniel Hardman, 2026-10-01
      why: >-
        The posture standard licenses corpora under CC-BY-4.0, but these vectors are test fixtures that implementations copy into their own Apache- and MIT-licensed test trees; a second licence on the fixtures would add attribution obligations and a licence-compatibility question to every adopter for no gain. Approved by Daniel, 2026-10-01.
    Anything but an answer is a failure = decision:
      nid: 7j5hvp2v
      stage-status: planned
      why: >-
        For every case the runner sends, a crash, a hang past the time limit, an oversized or malformed response, or an error reply fails every assertion in the case; only runner-side faults, such as failing to start the adapter, go unscored. Chosen after the keri-review-panel (SEC-F4): routing these outcomes to a neutral harness bucket would let a parser that panics or loops on hostile input escape exactly the must-reject cases built for it, the defect class the survey found. Rejected distinguishing adapter-glue exceptions from implementation exceptions, because the runner cannot see the difference and an adapter could launder failures through it. Tradeoff: a buggy adapter makes its implementation look worse than it is, which pushes adapter quality onto adapter authors.
    Adapters declare the behaviour they compose = decision:
      nid: 0eqxk4w6
      stage-status: planned
      why: >-
        When an adapter supplies logic its implementation lacks (escrow, routing, duplicity detection on top of a verification library), it lists that behaviour in the handshake's composes field, and every result record and conformance claim carries the list. Chosen after the keri-review-panel (SEC-F6): otherwise a claim such as passes every MUST case would credit a bare library with refusing duplicitous state that only the adapter refused. Rejected forbidding composition, which would exclude verification-only libraries such as devrandom's from the KERI layer entirely. Tradeoff: claims become tuples that are harder to summarize.
    IPEX transition cases wait for normative text = decision:
      nid: 69e5z0wq
      stage-status: planned
      why: >-
        The suite tests IPEX exchange messages for well-formedness, signatures and references now, and adds transcript cases classifying valid and invalid next steps only when the specs state a normative transition rule. Chosen after the keri-review-panel (KRT-F5): no clause defines which message may follow which or when a message opens a new exchange, keripy's own handlers disagree, and the first worked example would have failed a route-table-faithful implementation. Rejected deriving the state machine from keripy, which would make the suite the IPEX spec. Tradeoff: contractually protected disclosure, a core motivation, stays untested at the protocol level until the working group acts.
    The runner has no runtime dependencies = decision:
      nid: 4fmwzdjs
      stage-status: done
      why: >-
        kcs is a Python 3.12+ package managed with uv and depends on nothing at runtime. It must install wherever an adapter author works, in whatever language, and must never pull in an implementation under test, which depending on keripy or a CESR library would do. Generators that drive keripy run in their own pinned environments. Rejected writing the runner in Rust or Go for a single static binary: the generators and the first adapter are Python anyway, and a static binary would still need a release pipeline before anyone could use it. Tradeoff: adapter authors need a Python 3.12 interpreter on the machine that runs the suite. Recorded after the 2026-10-01 design review (CON-F1); the decision was made in commit cdf9ec0 without a node.
    Adapters are checkable without running cases = decision:
      nid: 8jdu4g9r
      stage-status: planned
      why: >-
        The adapter protocol is a contract implemented outside this repo in several languages, so the suite ships JSON Schemas for every protocol message and a kcs check-adapter command that probes handshake validity, id echo, error handling, statelessness between requests and escrow quiescence; the runner also runs the statelessness probe each session and can compare a shuffled run with an ordered one. Chosen after the 2026-10-01 design review (ARC-F1, TST-F1, TST-F2): without probes, an adapter that leaks state or skips quiescence produces wrong results the runner cannot see, and the org's contract standard asks a provider to ship vectors consumers run. Rejected static request/response vectors alone, because the invariants that matter are behavioural. Tradeoff: the probes are code to maintain, and they can only detect, not prove, compliance.
    The runner contains the adapter = decision:
      nid: 09wtltes
      stage-status: planned
      why: >-
        The runner treats adapters as untrusted: response size and request time bounds, a capped line reader, process-group kill, and on POSIX memory and CPU rlimits, a scrubbed environment and a refusal to run as root; network isolation is delegated to CI jobs that hold no secrets. Chosen after the 2026-10-01 design review (SEC-F1, SEC-F2): hostile inputs are the suite's normal payload, and an allocation bomb or parser exploit must not take down the host or reach credentials. Rejected requiring a container or sandbox runtime, which would make the suite unusable on developer laptops. Tradeoff: on non-POSIX platforms the runner offers weaker containment, and the docs say so.
    Keyword sentences govern conflicts inside a spec = decision:
      nid: 740f56ur
      stage-status: done
      why: >-
        Where a sentence with an RFC 2119 keyword conflicts with a table, legend or example in the same specification, the assertion keeps the sentence's level, stays active, records the conflict in spec_conflicts and raises it with the working group. Decided by Daniel 2026-10-02 (option 2 of three) after the CESR catalogue review found the count-code rule at CESR spec line 591 contradicted by its own symbol legends. Rejected treating such conflicts as disputed, which would have excluded the founding case and about 20 others and made the suite say almost nothing until the spec is fixed. Tradeoff: the suite adopts one interpretive rule, which a spec author could contest.
    Inferred validator obligations are graded SHOULD = decision:
      nid: 20d9xrm2
      stage-status: done
      why: >-
        Where a specification states an obligation only for producers (pad bits zero, counts matching content) and the suite infers what a validator should do with a violation, the assertion is graded SHOULD with the inference recorded in inferred_from, and the gap is raised as a request that the specification state the validator rule; a stated rule later re-issues the case at its level under a new id. Decided by Daniel 2026-10-02. Rejected grading inferences MUST, which legislates on no text and invites the charge that the suite invents the specification; rejected moving them out of conformance entirely, which hides the security-relevant rejection cases. Tradeoff: a lenient parser can claim MUST conformance while failing visible SHOULDs.
