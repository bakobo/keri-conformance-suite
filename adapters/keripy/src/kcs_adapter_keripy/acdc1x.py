"""acdc.verify on keripy 1.2.14: a 1.x ACDC judged by keripy 1.x's own credential verifier.

keripy 1.x verifies a credential through its Verifier, which reads the credential's vcp/iss/rev
registry from a Tevery and each registry event's anchor from a Kevery. The adapter gives every
request a fresh, temporary Habery (so nothing is kept between requests) and delivers the bundle
through keripy's own Parser with those three attached, in the order the adapter protocol gives:
KELs, registry events, far ACDCs, then the presented ACDC, after which it processes every escrow
once more. It then reads keripy's conclusion from keripy's own databases:

- ``valid`` when the Verifier saved the credential;
- ``incomplete`` when it holds the credential in its missing-registry, missing-chain or
  missing-schema escrow: something the verdict needs is absent from the bundle;
- ``invalid`` otherwise, which is what keripy does with a credential it refuses (a schema it
  fails, an edge that cannot be walked) and with a stream it cannot read.

The Verifier compares the issuance's ``dt`` with the clock and treats a stale one as missing; its
expiry is set past any stamp a case carries, which fixes the clock as the adapter protocol
requires. keripy prints some refusals to stdout, which is the protocol's channel, so everything
it prints while judging goes to stderr. A 1.x ACDC names its registry in ``ri``, not ``rd``, so
``registry`` is null, and keripy reports no edges, so ``edges`` is empty.
"""

import contextlib
import json
import sys

from keri.app import habbing
from keri.core import parsing, serdering
from keri.vdr import verifying

from kcs_adapter_keripy import kel

NEVER = 10 ** 12  # seconds: a Verifier expiry past any stamp a case carries
REASONS = {"valid": "keripy 1.2.14's Verifier saved the credential",
           "mre": "keripy 1.2.14's Verifier holds it for a missing registry or issuance",
           "mce": "keripy 1.2.14's Verifier holds it for a missing chained credential",
           "mse": "keripy 1.2.14's Verifier holds it for a missing schema",
           "invalid": "keripy 1.2.14's Verifier did not save the credential",
           "unreadable": "keripy 1.2.14 cannot read the presented stream as a 1.x ACDC"}


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
    try:
        said = serdering.SerderACDC(raw=bytearray(stream)).said
    except Exception:  # noqa: BLE001 - keripy raises many kinds for a stream it cannot read
        return {"verdict": "invalid", "reason": REASONS["unreadable"], "registry": None,
                "edges": []}
    with contextlib.redirect_stdout(sys.stderr), \
            habbing.openHby(name="kcs-acdc-1x", temp=True) as hby:
        vry = verifying.Verifier(hby=hby, expiry=NEVER)
        for key, raw in schemas:
            vry.resolver.add(key, raw)
        psr = parsing.Parser(framed=True, kvy=hby.kvy, tvy=vry.tvy, vry=vry)
        for each in [*kels, *registry, *acdcs, stream]:
            psr.parse(ims=bytearray(each))
        hby.kvy.processEscrows()
        vry.tvy.processEscrows()
        vry.processEscrows()
        if vry.reger.saved.get(keys=said) is not None:
            outcome, why = "valid", "valid"
        else:
            held = [name for name in ("mre", "mce", "mse")
                    if getattr(vry.reger, name).get(keys=said) is not None]
            outcome, why = ("incomplete", held[0]) if held else ("invalid", "invalid")
    return {"verdict": outcome, "reason": REASONS[why], "registry": None, "edges": []}
