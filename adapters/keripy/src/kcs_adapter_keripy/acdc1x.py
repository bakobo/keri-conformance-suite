"""acdc.verify on keripy 1.2.14: a 1.x ACDC judged by keripy 1.x's own credential verifier.

keripy 1.x verifies a credential through its Verifier, which reads the credential's vcp/iss/rev
registry from a Tevery and each registry event's anchor from a Kevery. The adapter gives every
request a fresh, temporary Habery (so nothing is kept between requests) and delivers the bundle
through keripy's own Parser with those three attached, in the order the adapter protocol gives:
KELs, registry events, far ACDCs, then the presented ACDC, after which it processes every escrow
once more. Each stream is delivered one message at a time through ``msgParsator``, as cesr.parse
delivers it: when keripy asks for more bytes the stream is complete (adapter protocol, "End of
input") and the rest of it is not delivered, so a truncated stream never makes the adapter wait,
and otherwise each stream follows the rules of keripy's own parse loop: a message keripy takes and
then refuses is skipped, and an extraction error discards the rest of the stream. The presented
stream must be one ACDC with its attachments, taken whole and refused nowhere; anything else is
unreadable, and ``invalid``, whatever keripy saved from elsewhere in the bundle. The adapter
then reads keripy's conclusion from keripy's own databases:

- ``valid`` when the Verifier saved the credential;
- ``incomplete`` when it holds the credential in its missing-registry, missing-chain or
  missing-schema escrow: something the verdict needs is absent from the bundle;
- ``invalid`` otherwise, which is what keripy does with a credential it refuses (a schema it
  fails, an edge that cannot be walked) and with a stream it cannot read, and also when the
  request's ``expect_schema`` names a schema other than the credential's.

keripy's Verifier saves a revoked credential too, so its revocation is reported where the adapter
protocol reports one, in ``registry``: the 1.x registry the credential names in ``ri``, with the
last event of the credential's own transaction log, as ``revoked`` or ``issued``. The Verifier
compares the issuance's ``dt`` with the clock and treats a stale one as missing; its expiry is set
past any stamp a case carries, which fixes the clock as the adapter protocol requires. keripy
prints some refusals to stdout, which is the protocol's channel, so everything it prints while
judging goes to stderr. A schema keripy's resolver will not take (its ``$id`` is not its SAID) is
one the bundle does not have. keripy reports no edges, so ``edges`` is empty.
"""

import contextlib
import json
import sys

from keri import kering
from keri.app import habbing
from keri.core import parsing, serdering
from keri.vdr import verifying

from kcs_adapter_keripy import kel

NEVER = 10 ** 12  # seconds: a Verifier expiry past any stamp a case carries
REVOKED = ("rev", "brv")
REASONS = {"valid": "keripy 1.2.14's Verifier saved the credential",
           "mre": "keripy 1.2.14's Verifier holds it for a missing registry or issuance",
           "mce": "keripy 1.2.14's Verifier holds it for a missing chained credential",
           "mse": "keripy 1.2.14's Verifier holds it for a missing schema",
           "invalid": "keripy 1.2.14's Verifier did not save the credential",
           "unreadable": "keripy 1.2.14 cannot read the presented stream as a 1.x ACDC",
           "expected": "the credential's schema is not the one the validator expects"}


def _schemas(request) -> list[tuple[str, bytes]]:
    values = request.get("schemas")
    if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
        raise kel.Malformed(f'{kel.E_MALFORMED}: "schemas" must be a list of hex strings.')
    out = []
    for value in values:
        raw = kel.hex_stream(value, "schemas")
        try:
            said = json.loads(raw)["$id"]
        except (ValueError, TypeError, KeyError):
            continue  # a schema keripy cannot index is one the bundle does not have
        if isinstance(said, str):
            out.append((said, raw))
    return out


def _expect_schema(request):
    if "expect_schema" not in request:
        return None
    value = request["expect_schema"]
    if not isinstance(value, str) or not value:
        raise kel.Malformed(f'{kel.E_MALFORMED}: "expect_schema", when present, must be a '
                            "non-empty string.")
    return value


def _deliver(psr, hby, vry, data: bytes) -> tuple[int, bool, bool]:
    """Deliver one stream a message at a time with the rules of keripy 1.2.14's own parse loop
    (Parser.allParsator): after an error inside a sized group, which keripy has already flushed,
    and after any other error once the message is taken, delivery resumes with the next message;
    after a cold-start or extraction error the rest of the stream is discarded. Delivery also stops
    where keripy asks for more bytes (the stream is complete, so it is truncated) or takes nothing.
    Returns how many messages keripy took, whether it took the whole stream, and whether any of
    its bytes could not be extracted. An error keripy raises after taking a message is a judgement
    (an escrow, a refusal), not an extraction failure: verify reads it from keripy's databases."""
    ims = bytearray(data)
    taken, refused = 0, False
    while ims:
        before = len(ims)
        gen = psr.msgParsator(ims=ims, framed=True, pipeline=False, kvy=hby.kvy, tvy=vry.tvy,
                              vry=vry)
        try:
            next(gen)
        except StopIteration:
            pass  # the message is finished
        except kering.SizedGroupError:
            refused = True  # bytes keripy could not extract, though it flushed only the group
        except (kering.ColdStartError, kering.ExtractionError):
            return taken, False, True  # keripy discards the rest of the stream
        except Exception:  # noqa: BLE001, S110 - a judgement keripy reached after taking the
            pass  # message (an escrow, a refusal), which its databases record and verify reads
        else:
            return taken, False, refused  # keripy yielded for more bytes: end of input
        if len(ims) >= before:  # keripy took nothing: stop rather than spin
            return taken, False, refused
        taken += 1
    return taken, True, refused


def _registry(vry, ri, said):
    """The credential's 1.x registry state, as acdc.verify reports one, or None."""
    tever = vry.tevers.get(ri) if isinstance(ri, str) else None
    state = tever.vcState(said) if tever is not None else None
    if state is None:
        return None
    return {"rd": ri, "n": int(state.s, 16), "d": state.d, "td": said,
            "ts": "revoked" if state.et in REVOKED else "issued"}


def verify(request):
    kel.validator(request)
    kels = kel.streams(request, "kels")
    registry = kel.streams(request, "registry")
    acdcs = kel.streams(request, "acdcs")
    presented = request.get("presented")
    if not isinstance(presented, dict):
        raise kel.Malformed(f'{kel.E_MALFORMED}: "presented" must be an object.')
    stream = kel.hex_stream(presented.get("stream"), "presented")
    schemas = _schemas(request)
    expected = _expect_schema(request)
    try:
        creder = serdering.SerderACDC(raw=bytearray(stream))
    except Exception:  # noqa: BLE001 - keripy raises many kinds for a stream it cannot read
        return {"verdict": "invalid", "reason": REASONS["unreadable"], "registry": None,
                "edges": []}
    said, ri = creder.said, creder.sad.get("ri")
    with contextlib.redirect_stdout(sys.stderr), \
            habbing.openHby(name="kcs-acdc-1x", temp=True) as hby:
        vry = verifying.Verifier(hby=hby, expiry=NEVER)
        psr = parsing.Parser(framed=True, kvy=hby.kvy, tvy=vry.tvy, vry=vry)
        for key, raw in schemas:
            try:
                vry.resolver.add(key, raw)
            except kering.KeriError:
                continue  # a schema keripy will not take is one the bundle does not have
        for each in [*kels, *registry, *acdcs]:
            _deliver(psr, hby, vry, each)
        # The presented stream is one ACDC and its attachments, taken whole, or it is unreadable:
        # a credential saved from the front of a longer or truncated stream is not what was
        # presented.
        whole = _deliver(psr, hby, vry, stream) == (1, True, False)
        hby.kvy.processEscrows()
        vry.tvy.processEscrows()
        vry.processEscrows()
        head = _registry(vry, ri, said)
        if not whole:
            outcome, why = "invalid", "unreadable"
        elif vry.reger.saved.get(keys=said) is not None:
            outcome, why = "valid", "valid"
        else:
            held = [name for name in ("mre", "mce", "mse")
                    if getattr(vry.reger, name).get(keys=said) is not None]
            outcome, why = ("incomplete", held[0]) if held else ("invalid", "invalid")
    if expected is not None and creder.sad.get("s") != expected and outcome == "valid":
        outcome, why = "invalid", "expected"
    return {"verdict": outcome, "reason": REASONS[why], "registry": head, "edges": []}
