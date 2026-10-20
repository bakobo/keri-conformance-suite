"""acdc.verify's presentation context, judged with heti's parts (this.i 9fg9ufsm, 7krs5hfz).

heti judges a grant only inside ``OwnFacet.admit``, which needs the verifier's own keys, and
heti's grant is its own dialect, so the adapter reads the suite's grant itself and asks heti's
public parts what they can answer. After heti has verified the presented ACDC, the adapter takes
the last exchange message of the context and requires, in order:

- that it frames, and is an ``exn`` on the route ``/ipex/grant``;
- that its ``a.o`` names exactly the presented ACDC's SAID (presentation-names);
- that its ``ri`` is the verifier the request names (presentation-verifier);
- that one transferable signature group signs it for its sender, which heti's public
  ``heti.anchored.consume.verify`` checks against the sender's key state replayed from the
  bundle's KELs, at the establishment event the group names;
- and heti's own presenter rule, from ``admit``: the sender is the issuee heti's public
  ``heti.anchored.produce.ipex.bound_issuee`` names, or the issuer. ``bound_issuee`` refuses a
  credential whose attribute section, aggregate or aggregate issuee block is concealed, since
  it cannot tell such a credential from an affidavit, and answers None for an affidavit, which
  anyone may present.

Each failure is ``invalid``, except that heti's refusals (of the signature, or of an issuee it
cannot read) are graded as acdc.verify grades heti's errors, so a key state heti cannot
establish from the bundle, or a withheld issuee, is ``incomplete``. The
reading of the grant and the presenter rule are composed by the adapter, which declares
``acdc.presentation`` in ``composes``; the signature and the ACDC's verdict are heti's.
"""

from heti.anchored.consume import Evidence, Segment
from heti.anchored.consume import verify as verify_signature
from heti.anchored.produce.ipex import bound_issuee
from keri.core.serdering import SerderACDC

from kcs_adapter_heti import verify as v

ROUTE = "/ipex/grant"
SIGNATURE = 88  # an indexed Ed25519 signature's length in text
E_PRESENTER = "e.proof.presenter.f"


def context(request) -> tuple[list[bytes], str] | None:
    """The request's presentation context as (messages, verifier), or None without one. A
    context that names no message or no verifier cannot be read, which is an error, not a
    verdict (adapter protocol, acdc.verify)."""
    if "presentation" not in request:
        return None
    given = request["presentation"]
    if not isinstance(given, dict):
        raise v.Malformed(f'{v.E_MALFORMED}: "presentation" must be an object.')
    messages = v._streams(given, "messages")
    verifier = given.get("verifier")
    if not messages or not isinstance(verifier, str) or not verifier:
        raise v.Malformed(f'{v.E_MALFORMED}: "presentation" must name at least one message and '
                          'a non-empty "verifier".')
    return messages, verifier


def _signatures(attachments: bytes, sender: str) -> tuple[str, list[str]] | None:
    """The establishment event's SAID and the indexed signatures of the one transferable
    signature group a message carries for its sender, or None when it carries no such group."""
    found = [body for code, body in v.groups(attachments) if code in (b"-X", b"--X")]
    if len(found) != 1:
        return None
    body = found[0].decode("ascii", "replace")
    prefix, said, rest = body[:44], body[68:112], body[112:]
    if prefix != sender or not rest.startswith("-K"):
        return None
    sigs = rest[4:]
    try:
        declared = v._count(rest[2:4].encode("ascii")) * 4
    except ValueError:  # a count that is not base 64
        return None
    if not sigs or len(sigs) % SIGNATURE or declared != len(sigs):
        return None
    return said, [sigs[n:n + SIGNATURE] for n in range(0, len(sigs), SIGNATURE)]


def judge(given, presented: bytes, kel_streams: list[bytes]) -> tuple[str, str] | None:
    """Why the presentation does not hold, as (verdict, reason), or None when it holds."""
    messages, verifier = given
    parts = v.split(messages[-1])
    if parts is None:
        return "invalid", "the presentation's last message does not frame"
    grant, raw, attachments = parts
    if grant.get("t") != "exn" or grant.get("r") != ROUTE:
        return "invalid", f"the presentation's last message is not an exn on {ROUTE}"
    acdc = SerderACDC(raw=bytes(v.split(presented)[1]))
    named = grant.get("a", {}).get("o") if isinstance(grant.get("a"), dict) else None
    if named != [acdc.said]:
        return "invalid", "the grant does not name exactly the presented ACDC"
    if grant.get("ri") != verifier:
        return "invalid", "the grant is addressed to another verifier"
    sender = grant.get("i")
    signed = _signatures(attachments, sender) if isinstance(sender, str) else None
    if signed is None:
        return "invalid", "the grant carries no signature group for its sender"
    said, sigs = signed
    evidence = Evidence(parts=tuple(Segment(stream=s, source=None) for s in kel_streams))
    try:
        verify_signature(aid=sender, data=raw, signature=sigs, evidence=evidence, as_of=said)
        issuee = bound_issuee(acdc)
    except Exception as exc:  # heti refuses with a coded error of many kinds
        code = getattr(exc, "code", None)
        if code is None:
            raise
        return v.grade(exc), f"{code}: {exc}"
    if issuee is not None and sender not in (issuee, acdc.sad.get("i")):
        return "invalid", f"{E_PRESENTER}: the grant's sender is neither the issuee nor the issuer"
    return None
