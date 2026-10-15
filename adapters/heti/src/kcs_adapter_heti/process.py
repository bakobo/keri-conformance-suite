"""keri.process through heti's public key-state resolver (this.i 8uucj49z).

heti has no per-message KEL processor in its public API. What it has is
``heti.anchored.consume.resolve_key_state``: a pure function that replays evidence into a scratch
keripy database with ``lax=False``, drives keripy's escrows until a pass accepts nothing more,
refuses an identifier with a fork anywhere in its delegation chain, and answers a key state or
raises a coded error.

So each message becomes one unattributed segment, in delivery order, and heti is asked about the
message's own event by its SAID (``as_of=d``): with the messages delivered so far for the initial
reading, and with all of them for the final one. A message's d is only what it claims, so when
the messages carry more than one body under one event's SAID, heti is asked about each body with
the copies carrying another body left out: a corrupt copy is not reported seen because a valid
copy of its SAID was, while copies with one body still combine their signatures. heti answering means it accepted the event:
``seen``. heti checks for duplicity only after it has found the event, so a duplicity refusal also
means ``seen``. Any other retryable refusal means heti could not establish the event yet:
``pending``. Every other refusal is ``rejected``.

heti reports no reading of a receipt and no record of which events a superseding rotation
displaced. A message that is not a key event is therefore reported ``rejected``, and ``trunk`` is
whether the message is finally seen; the adapter declares neither ``keri.routing`` nor
``kel.recovery``, so the cases that turn on those are not sent.
"""

import json
import re

from heti.anchored.consume import Evidence, Segment, resolve_key_state

from kcs_adapter_heti import verify

E_MALFORMED = "e.input.format.request.f"
E_PERSPECTIVE = "e.feature.unsupported.perspective.f"
HEX = re.compile(r"(?:[0-9a-f]{2})*")
KEY_EVENTS = ("icp", "rot", "ixn", "dip", "drt")
DUPLICITY = "e.state.conflict.duplicity"
NO_EVENT = ("The message does not frame a key event body with string i and d fields, so there is "
            "no event to ask heti about.")
NOT_A_KEY_EVENT = ("heti's public verification surface reports key events only, and has no "
                   "reading of this message.")
# What heti does itself inside keri.process (README.md, "keri.process").
FEATURES = ["cesr.genus-2.00", "cesr.serialization.json", "crypto.ed25519", "kel.basic",
            "kel.delegation", "kel.multisig.numeric", "kel.multisig.weighted",
            "kel.partial-rotation", "kel.witness", "keri.escrow", "keri.version-2.x"]


class Malformed(verify.Malformed):
    pass


class Unsupported(Exception):
    pass


def _messages(request) -> list[bytes]:
    values = request.get("messages")
    if not isinstance(values, list):
        raise Malformed(f'{E_MALFORMED}: "messages" must be a list.')
    out = []
    for value in values:
        stream = value.get("stream") if isinstance(value, dict) else None
        if not isinstance(stream, str) or not HEX.fullmatch(stream):
            raise Malformed(f'{E_MALFORMED}: every entry in "messages" must be an object whose '
                            '"stream" is a lowercase hex string.')
        out.append(bytes.fromhex(stream))
    return out


def _validator(request):
    perspective = request.get("perspective")
    if not isinstance(perspective, dict):
        raise Malformed(f'{E_MALFORMED}: "perspective" must be an object.')
    if perspective.get("role") != "validator":
        raise Unsupported(f"{E_PERSPECTIVE}: This adapter reports only an ordinary validator's "
                          f"perspective, not {perspective.get('role')!r}.")


def event(stream: bytes) -> tuple[str, str, str, bytes] | None:
    """The message's type, identifier, SAID and body: what to ask heti about. None when its body
    does not frame or does not name an identifier and a SAID."""
    parts = verify.split(stream)
    sad, body = (parts[0], parts[1]) if parts else ({}, b"")
    t, i, d = sad.get("t"), sad.get("i"), sad.get("d")
    return (t, i, d, body) if isinstance(i, str) and isinstance(d, str) else None


def _without_other_bodies(ident, idents, streams) -> list[bytes]:
    """The streams, less the key events claiming the same event with a different body. A receipt
    names the event it receipts in the same fields and is kept."""
    _, aid, said, body = ident
    return [s for s, other in zip(streams, idents)
            if other is None or other[0] not in KEY_EVENTS or other[1:3] != (aid, said)
            or other[3] == body]


def _evidence(streams) -> Evidence:
    return Evidence(parts=tuple(Segment(stream=s, source=None) for s in streams))


def reading(ident, idents, streams) -> tuple[str, str | None]:
    """heti's reading of one message, given the messages delivered so far and what each of them
    names, with heti's reason when it did not accept it."""
    if ident is None:
        return "rejected", NO_EVENT
    t, aid, said, _ = ident
    if t not in KEY_EVENTS:
        return "rejected", NOT_A_KEY_EVENT
    evidence = _evidence(_without_other_bodies(ident, idents, streams))
    try:
        resolve_key_state(aid=aid, evidence=evidence, as_of=said)
    except ValueError as exc:
        # heti refuses an identifier it cannot parse with ValueError rather than a coded error.
        return "rejected", str(exc)
    except Exception as exc:
        code = getattr(exc, "code", None)
        if code is None:
            raise
        if code.startswith(DUPLICITY):
            return "seen", None
        return ("pending" if getattr(exc, "retryable", False) else "rejected"), f"{code}: {exc}"
    return "seen", None


def _threshold(value: str):
    """heti renders a weighted threshold as JSON and a numeric one as a plain string."""
    return json.loads(value) if value.startswith("[") else value


def key_state(aid, streams) -> dict | None:
    """heti's key state for an identifier, or None when heti refuses to report one."""
    try:
        state = resolve_key_state(aid=aid, evidence=_evidence(streams)).key_state
    except ValueError:
        return None
    except Exception as exc:
        if getattr(exc, "code", None) is None:
            raise
        return None
    return {"sn": state.sn, "said": state.said, "keys": list(state.keys),
            "kt": _threshold(state.threshold), "ndigs": list(state.next_keys),
            "nt": _threshold(state.next_threshold), "wits": list(state.witnesses),
            "bt": f"{state.witness_threshold:x}", "delegator": state.delegator}


def process(request) -> dict:
    _validator(request)
    streams = _messages(request)
    idents = [event(s) for s in streams]
    dispositions = []
    for n, ident in enumerate(idents):
        initial, why = reading(ident, idents[:n + 1], streams[:n + 1])
        final, why_final = reading(ident, idents, streams)
        disposition = {"initial": initial, "final": final, "trunk": final == "seen"}
        if why_final or why:
            disposition["reason"] = why_final or why
        dispositions.append(disposition)
    aids = dict.fromkeys(ident[1] for ident in idents if ident and ident[0] in KEY_EVENTS)
    states = {aid: state for aid in aids if (state := key_state(aid, streams)) is not None}
    return {"dispositions": dispositions, "key_states": states}
