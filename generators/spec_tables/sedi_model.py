"""The sedi-1 model validator: acdc_model's decision procedure read under sedi-1's choices, with
the three-way verdict sedi-1 grades (this.i 8fh68wt6) instead of valid or not valid.

It reuses acdc_model for what sedi-1 does not change (framing, field order, SAIDs, schemas) and
replaces what it does:

- **Seals** (seal-shape, this.i 2082s6k4). A registry event is anchored by the couple ``{s, d}``
  or the event seal ``{i, s, d}`` whose ``i`` is the registry's SAID, in the issuer's KEL trunk. A seal
  that names the event's SAID in any other shape (a bare digest, an extra field, another ``i``,
  the wrong ``s``) fails a check; no seal naming it at all leaves the anchor absent.
- **Commitment.** A SEDI credential is committed through its registry: the head of the registry
  its ``rd`` names must carry the credential's SAID as ``td``, in state ``issued`` (revoked). A
  digest seal of the ACDC does not commit it, since a bare digest is no seal under seal-shape.
- **The registry** (tel-sequence, registry-head, registry-evidence). Events are walked by ``n``,
  not by delivery order. The head is the highest event that chain-verifies from the inception and
  is anchored. Evidence the walk cannot account for keeps the verdict from ``valid``: a gap or an
  unanchored event leaves it ``incomplete``, a failed check (a SAID, a prior, an anchored ``n``
  that skips past the head it names as prior, a repeated ``n`` anchored twice, an event of
  another registry kind) makes it ``invalid``, and so does a later
  event anchored in the issuer's KEL that the bundle does not carry, which is ``incomplete``. An
  inception of a registry kind sedi-1 does not support (``vcp``) is ``incomplete``.
- **Edges** (edge-said, operator-list, operator-shape, default-operator, unknown-operator). Every
  edge block carries its own SAID in ``d``. The edge section and each edge-group are evaluated by
  their m-ary operator (``AND`` by default, line 1110, or ``OR``); an edge by its effective
  unary operators, where the latest of ``I2I``, ``NI2I`` and ``DI2I`` wins (line 1186), ``E1E``
  binds the two issuees (v1.1 line 1223), and the default is appended when none of the four is
  present (v1.1 line 1209). A far node is valid only if its own verdict is, so validity is
  chain-strict.
- **Combining** (unresolved-grading, failure-precedence). Wherever several results combine, a
  failure outranks something unevaluable: ``AND`` is ``invalid`` if any member is, else
  ``incomplete`` if any member is, else ``valid``; ``OR`` is ``valid`` if any member is, else
  ``invalid`` if any member is, else ``incomplete``. So adding an unevaluable alternative to a
  forged credential cannot turn a reject into a retry.

- **The presentation context** (presenter-binding, aggregate-issuee, bearer-untargeted; this.i
  09snlyre and 7krs5hfz). When the request carries one, its messages are read by the suite's
  exchange-message model over the bundle's KELs, and the last is the grant. A grant that model
  does not accept proves no presenter (``invalid``). An accepted grant must be an ``exn`` on the route
  ``/ipex/grant``, name exactly the presented ACDC in ``a.o`` and be addressed (``ri``) to the verifier, else ``invalid``; and its
  sender must be the issuee, else ``invalid``. An issuee the presentation does not disclose (a
  compact ``a``, or an aggregate's undisclosed ``A[1]``) cannot be bound, so it is
  ``incomplete``; an ACDC with no issuee is a bearer credential, which anyone may present.

``DI2I`` admits a near issuer that the far issuee delegated directly (its inception is a ``dip``
whose ``di`` is the far issuee); a delegation chain of more than one step is not followed.

A seal-bearing KEL event that names a registry-looking ``{s, d}`` the bundle does not carry, at
any ``s``, is counted against every registry of that issuer, because a couple does not say which
registry it belongs to, and a withheld couple below the head may be a second update at an
earlier ``n``. The cost falls on an issuer with several registries anchored by couples, whose
bundles read ``incomplete`` until they carry every registry's events; an event seal ``{i, s, d}``
counts only against the registry its ``i`` names, which is how such an issuer avoids it.
"""

from dataclasses import dataclass, field

from . import acdc_model as am
from . import acdc_saids as sa
from . import exn_build
from .tables import Tables

VALID, INVALID, INCOMPLETE = "valid", "invalid", "incomplete"
ISSUER_OPS = ("I2I", "NI2I", "DI2I")
UNARY = (*ISSUER_OPS, "E1E")
MARY = ("AND", "OR")
# Fields of an edge or edge-group block that are not members of a group.
BLOCK_FIELDS = ("d", "u", "o", "w")
ISSUED, REVOKED = "issued", "revoked"
# The route of the message that presents an ACDC (this.i 7krs5hfz).
GRANT_ROUTE = "/ipex/grant"

# How acdc_model's step failures grade under sedi-1. A failure not listed here fails a check.
INCOMPLETE_REASONS = {"schema-absent", "issuer-kel"}


@dataclass(frozen=True)
class Finding:
    grade: str  # invalid or incomplete
    where: str  # the presented ACDC, a far node by SAID, a registry or an edge path
    reason: str

    @property
    def tag(self) -> str:
        return f"{self.grade}/{self.where}/{self.reason}"


@dataclass
class Head:
    """The registry's head as sedi-1 reads it: the highest anchored event that chain-verifies."""

    rd: str
    n: int
    d: str
    td: str | None = None
    ts: str | None = None

    def facts(self) -> dict:
        return {"rd": self.rd, "n": self.n, "d": self.d, "td": self.td, "ts": self.ts}


@dataclass
class Result:
    verdict: str
    findings: list[Finding] = field(default_factory=list)
    head: Head | None = None

    def tags(self) -> list[str]:
        return [f.tag for f in self.findings]


def combine(grades: list[str], operator: str = "AND") -> str:
    """The grade of a group: AND needs every member valid, OR one, and a failure outranks
    something unevaluable either way (failure-precedence)."""
    if operator == "OR" and VALID in grades:
        return VALID
    if INVALID in grades:
        return INVALID
    if INCOMPLETE in grades:
        return INCOMPLETE
    return VALID


def issuee(body: dict | None):
    """The issuee an ACDC discloses: ``a.i``, or for an aggregate ``A[1].i`` (aggregate-issuee).
    None when it has none or does not disclose it; ``...`` (Ellipsis) when the aggregate's
    issuee block is undisclosed, which is unknown rather than absent."""
    if not isinstance(body, dict):
        return None
    attributes = body.get("a")
    if isinstance(attributes, dict):
        return attributes.get("i")
    aggregate = body.get("A")
    if isinstance(aggregate, list) and len(aggregate) > 1:
        block = aggregate[1]
        if isinstance(block, dict):
            return block.get("i")
        return ...
    return None


def operators(o) -> tuple[list[str] | None, str | None]:
    """An edge's ``o`` as its list of operators, or None and the grade of a shape that cannot be
    read: an object, or a member that is not a string, cannot be evaluated (unknown-operator); a
    nested list is malformed (operator-shape)."""
    if o is None:
        return [], None
    if isinstance(o, str):
        return [o], None
    if not isinstance(o, list):
        return None, INCOMPLETE
    if any(isinstance(m, list) for m in o):
        return None, INVALID
    if any(not isinstance(m, str) for m in o):
        return None, INCOMPLETE
    return list(o), None


class _SediModel(am._Model):
    def __init__(self, t: Tables, request: dict, trunks: am._Kels | None = None):
        self.heads: dict = {}
        super().__init__(t, request, sa.DEFAULT, trunks)

    # -- seals ----------------------------------------------------------------------------------

    def _seals(self, issuer) -> list:
        return [seal for body in self.kels.trunks.get(issuer, []) for seal in body.get("a") or []]

    def anchor(self, issuer, rd, n: str, said) -> str | None:
        """None when the issuer's trunk anchors the event in an accepted shape; else the grade:
        invalid when a seal names its SAID in another shape, incomplete when none names it."""
        named = False
        for seal in self._seals(issuer):
            if not isinstance(seal, dict) or seal.get("d") != said:
                continue
            if seal in ({"s": n, "d": said}, {"i": rd, "s": n, "d": said}):
                return None
            named = True
        return INVALID if named else INCOMPLETE

    # -- commitment: through the registry only -----------------------------------------------------

    def _commitment(self, node: am.Node) -> list[am.Failure]:
        body = node.body
        if not self.kels.seen(body.get("i")):
            return [am.Failure(3, "issuer-kel")]
        if "rd" not in body:
            return [am.Failure(4, "no-registry")]
        return []

    # -- the registry -------------------------------------------------------------------------------

    def head(self, rd, issuer) -> tuple[Head | None, list[tuple[str, str]]]:
        """The registry's head and every (grade, reason) that keeps the verdict from valid."""
        key = (rd, issuer)
        if key not in self.heads:
            self.heads[key] = self._walk(rd, issuer)
        return self.heads[key]

    def _walk(self, rd, issuer):
        events = [p for p in self.registry_streams if p is not None and isinstance(p[0], dict)
                  and (p[0].get("d") == rd or p[0].get("rd") == rd)]
        inception = next((p for p in events if p[0].get("d") == rd), None)
        if inception is None:
            return None, [(INCOMPLETE, "registry-absent")]
        body = inception[0]
        if body.get("t") != "rip":
            return None, [(INCOMPLETE, "registry-kind")]
        if not self._event_said(body):
            return None, [(INVALID, "rip-said")]
        if body.get("i") != issuer:
            return None, [(INVALID, "rip-issuer")]
        grade = self.anchor(issuer, rd, "0", rd)
        if grade:
            return None, [(grade, "rip-anchor")]
        head, problems = Head(rd=rd, n=0, d=rd), []
        by_n: dict[int, list] = {}
        for p in events:
            if p is inception:
                continue
            update = p[0]
            if update.get("t") != "bup":
                problems.append((INVALID, "registry-kind-mixed"))
                continue
            if not self._event_said(update):
                problems.append((INVALID, "bup-said"))
                continue
            n = _sn(update.get("n"))
            if n is None or n < 1:
                problems.append((INVALID, "bup-sn"))
                continue
            by_n.setdefault(n, []).append(p)
        last = max(by_n, default=0)

        def skipped(n: int) -> bool:
            """A later anchored event names the head as its prior, so it skipped n: a failed
            check (tel-sequence), whatever the bundle holds at n."""
            return any(c[0].get("p") == head.d
                       and self.anchor(issuer, rd, f"{m:x}", c[0]["d"]) is None
                       for m, later in by_n.items() if m > n for c in later)

        for n in range(1, last + 1):
            candidates = by_n.get(n, [])
            if not candidates:
                # Otherwise an event here may be withheld.
                problems.append((INVALID, "bup-sequence") if skipped(n)
                                else (INCOMPLETE, "registry-gap"))
                break
            grades = {c[0]["d"]: self.anchor(issuer, rd, f"{n:x}", c[0]["d"]) for c in candidates}
            anchored = [c for c in candidates if grades[c[0]["d"]] is None]
            if len({c[0]["d"] for c in anchored}) > 1:
                problems.append((INVALID, "registry-duplicity"))
                break
            if not anchored:
                # An unanchored event at n cannot hide a skip a later anchored event proves.
                if INVALID not in grades.values() and skipped(n):
                    problems.append((INVALID, "bup-sequence"))
                else:
                    problems.append((INVALID if INVALID in grades.values() else INCOMPLETE,
                                     "bup-anchor"))
                break
            update, _, attachments = anchored[0]
            if update.get("p") != head.d:
                problems.append((INVALID, "bup-prior"))
                break
            td, ts, block = self._block(update, attachments)
            if block:
                problems.append((INVALID, block))
                break
            head = Head(rd=rd, n=n, d=update["d"], td=td, ts=ts)
        problems += self._unaccounted(issuer, head)
        return head, problems

    def _unaccounted(self, issuer, head: Head) -> list[tuple[str, str]]:
        """A registry-shaped seal in the issuer's KEL whose event the bundle lacks (test-plan
        item 6: an s naming an absent event is incomplete): an event seal naming this registry,
        or a couple, which names no registry and so might be this registry's, at any s."""
        # Each carried event by its SAID and sequence number: a seal accounts for an event only
        # by naming both, so a known d at another s still names an absent event.
        known = {(p[0].get("d"), p[0].get("n", "0" if p[0].get("t") == "rip" else None))
                 for p in self.registry_streams if p is not None and isinstance(p[0], dict)}
        for seal in self._seals(issuer):
            if not isinstance(seal, dict) or set(seal) not in ({"s", "d"}, {"i", "s", "d"}):
                continue
            if (isinstance(seal["d"], str) and isinstance(seal["s"], str)
                    and (seal["d"], seal["s"]) in known):
                continue
            if "i" not in seal or seal["i"] == head.rd:
                return [(INCOMPLETE, "registry-unseen")]
        return []

    # -- edges ----------------------------------------------------------------------------------

    def group(self, near: dict, block, path: str, verdict_of) -> tuple[str, list[Finding]]:
        """The grade of an edge-group (the edge section is one) and why."""
        o = block.get("o", "AND")
        members = [(k, v) for k, v in block.items() if k not in BLOCK_FIELDS]
        if not members:
            return INVALID, [Finding(INVALID, path, "group-empty")]
        if o not in MARY:
            # Its members are still evaluated, so a failure among them is not hidden behind an
            # operator nobody can evaluate (failure-precedence).
            grades, findings = [INCOMPLETE], [Finding(INCOMPLETE, path, "group-operator")]
            o = "AND"
        else:
            grades, findings = [], []
        for label, member in members:
            where = f"{path}.{label}"
            if not isinstance(member, dict):
                # A compact edge or group hides what it points to, so it cannot be evaluated.
                grades.append(INCOMPLETE)
                findings.append(Finding(INCOMPLETE, where, "edge-compact"))
                continue
            if "n" in member:
                grade, found = self.edge(near, member, where, verdict_of)
            else:
                grade, found = self.group(near, member, where, verdict_of)
            grades.append(grade)
            findings += found
        grade = combine(grades, o)
        # Findings in an alternative an OR did not need do not decide its verdict.
        return grade, ([] if grade == VALID else findings)

    def edge(self, near: dict, block: dict, path: str, verdict_of) -> tuple[str, list[Finding]]:
        """The grade of one edge: every check it can make is made, so something it cannot
        evaluate (an unknown operator, a missing schema) never hides one that fails
        (failure-precedence)."""
        if not isinstance(block.get("d"), str):
            return INVALID, [Finding(INVALID, path, "edge-said")]
        found = []
        ops, bad = operators(block.get("o"))
        if bad:
            found.append(Finding(bad, path, "operator-shape"))
            ops = []
        elif any(op not in UNARY for op in ops):
            found.append(Finding(INCOMPLETE, path, "operator-unknown"))
        far = self.far.get(block.get("n"))
        if far is None:
            found.append(Finding(INCOMPLETE, path, "far-absent"))
            return combine([f.grade for f in found]), found
        node, _ = far
        if "s" in block:
            missing = self.satisfies(node.body, block["s"])
            if missing == ["schema-absent"]:
                found.append(Finding(INCOMPLETE, path, "edge-schema-absent"))
            elif missing:
                found.append(Finding(INVALID, path, "edge-schema"))
        far_issuee = issuee(node.body)
        if not any(op in UNARY for op in ops):
            ops.append("NI2I" if far_issuee is None else "I2I")
        relation = next((op for op in reversed(ops) if op in ISSUER_OPS), None)
        problem = self._relation(relation, near, far_issuee)
        if problem:
            found.append(Finding(problem[0], path, problem[1]))
        if "E1E" in ops:
            mine = issuee(near)
            if mine is ... or far_issuee is ...:
                found.append(Finding(INCOMPLETE, path, "e1e-hidden"))
            elif mine is None or far_issuee is None or mine != far_issuee:
                found.append(Finding(INVALID, path, "e1e-issuee"))
        grade, far_found = verdict_of(node)
        found += far_found
        return combine([f.grade for f in found] + [grade]), found

    def _relation(self, relation, near: dict, far_issuee):
        if relation in (None, "NI2I"):
            return None
        if far_issuee is ...:
            return INCOMPLETE, "i2i-hidden"
        if far_issuee is None:
            return INVALID, "i2i-untargeted"
        issuer = near.get("i")
        if issuer == far_issuee:
            return None
        if relation == "DI2I":
            trunk = self.kels.trunks.get(issuer, [])
            if trunk and trunk[0].get("t") == "dip" and trunk[0].get("di") == far_issuee:
                return None
        return INVALID, f"{relation.lower()}-issuee"


def _sn(text) -> int | None:
    """A registry sequence number: lowercase hex without leading zeros (tel-sequence)."""
    if not isinstance(text, str) or not text or (len(text) > 1 and text[0] == "0"):
        return None
    try:
        value = int(text, 16)
    except ValueError:
        return None
    return value if f"{value:x}" == text else None


def _grade(failure: am.Failure) -> str:
    return INCOMPLETE if failure.reason in INCOMPLETE_REASONS else INVALID


def evaluate(t: Tables, request: dict, trunks: am._Kels | None = None) -> Result:
    """The sedi-1 verdict on an acdc.verify request's bundle, with every finding that kept it
    from valid and the registry head it holds as of."""
    model = _SediModel(t, request, trunks)
    presented, _ = model.node(bytes.fromhex(request["presented"]["stream"]))
    if presented.body is None:
        return Result(INVALID, [Finding(INVALID, "presented", f.reason)
                                for f in presented.failures])
    state: dict = {}

    def verdict_of(node: am.Node) -> tuple[str, list[Finding]]:
        said = node.said
        if said in state:
            # A node reached again on a path that is still open is a cycle.
            return state[said] or (INVALID, [Finding(INVALID, said, "cycle")])
        state[said] = None
        found = [Finding(_grade(f), said, f.reason) for f in node.failures]
        body = node.body
        if "rd" in body and model.kels.seen(body.get("i")):
            head, problems = model.head(body["rd"], body.get("i"))
            found += [Finding(g, said, r) for g, r in problems]
            # A walk that stopped before any state was disclosed has already said why.
            if head is not None and not (problems and head.td is None):
                if head.td != said:
                    found.append(Finding(INCOMPLETE if head.td is None else INVALID, said,
                                         "registry-state"))
                elif head.ts == REVOKED:
                    found.append(Finding(INVALID, said, "revoked"))
                elif head.ts != ISSUED:
                    found.append(Finding(INCOMPLETE, said, "registry-state"))
        edges = body.get("e")
        if isinstance(edges, dict):
            _, edge_found = model.group(body, edges, f"{said}.e", verdict_of)
            found += edge_found
        elif edges is not None:
            found.append(Finding(INCOMPLETE, said, "edge-compact"))
        grade = combine([f.grade for f in found])
        state[said] = (grade, found)
        return grade, found

    verdict, findings = verdict_of(presented)
    if "presentation" in request:
        bound = _presentation(t, request, presented)
        findings = findings + bound
        verdict = combine([verdict, *(f.grade for f in bound)])
    head = None
    if "rd" in presented.body:
        head = model.heads.get((presented.body["rd"], presented.body.get("i")), (None,))[0]
    # A node reached by two paths (a diamond) contributes its findings once.
    return Result(verdict, list(dict.fromkeys(findings)), head)


def _presentation(t: Tables, request: dict, presented: am.Node) -> list[Finding]:
    """What keeps the presentation context from binding the presented ACDC to its presenter."""
    context = request["presentation"]
    model = exn_build.run(t, [bytes.fromhex(k["stream"]) for k in request["kels"]],
                          [bytes.fromhex(m["stream"]) for m in context["messages"]])
    said = presented.said
    outcome, grant = model.initial[-1], model.parsed[-1]
    if outcome.state != exn_build.ACCEPTED:
        return [Finding(INVALID, said, f"grant-{outcome.reason}")]
    found = []
    if grant.body["t"] != "exn" or grant.body["r"] != GRANT_ROUTE:
        found.append(Finding(INVALID, said, "presentation-not-grant"))
    attributes = grant.body["a"]
    if not isinstance(attributes, dict) or attributes.get("o") != [said]:
        found.append(Finding(INVALID, said, "presentation-names"))
    if grant.body["ri"] != context["verifier"]:
        found.append(Finding(INVALID, said, "presentation-verifier"))
    body = presented.body
    who = ... if isinstance(body.get("a"), str) else issuee(body)
    if who is ...:
        found.append(Finding(INCOMPLETE, said, "presenter-undisclosed"))
    elif who is not None and grant.body["i"] != who:
        found.append(Finding(INVALID, said, "presenter"))
    return found
