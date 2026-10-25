"""Cross-check the sedi-1x-interop cases against keripy 1.2.14's own credential verifier (this.i
9sgwng6m).

Run from this directory, in its own pinned environment:

    uv run python check_acdc.py [CASE.json ...]

With no arguments it checks every case under ``cases/sedi1x``. Each bundle goes to a fresh
keripy 1.2.14 ``Habery`` through its ``Parser``, with the habery's ``Kevery``, a ``Tevery`` and a
``Verifier`` attached, in the order the adapter protocol delivers them: KELs, registry events,
far ACDCs, then the presented ACDC, after which every escrow is processed once more. keripy's
conclusion is then read from its own databases: a credential it saved is ``valid``, one it holds
in its missing-registry, missing-chain or missing-schema escrow is ``incomplete``, and anything
else is ``invalid``. The verifier's expiry is set past any stamp, so no verdict depends on the
clock (adapter protocol, acdc.verify). A case whose expected verdict keripy does not reach is a
disagreement, printed and counted in the exit status.

An acdc.issue case is the companion's one exception (Q-YWFX; docs/profiles/sedi.md, The 1.x
companion): its expected outcome is what SEDI's schema allows, not what keripy does. For it, keripy
1.2.14's own outcome is printed beside the expected one, as ``note``, and never counted: keripy's
``vc.proving.credential`` builds each credential and keripy's ``Schemer`` checks it, as
``Credentialer.validate`` does before an issuance.
"""

import argparse
import contextlib
import json
import pathlib
import sys

from keri import kering
from keri.app import habbing
from keri.core import parsing, scheming, serdering
from keri.vc import proving
from keri.vdr import verifying

ROOT = pathlib.Path(__file__).resolve().parents[2]
KERIPY_COMMIT = "bab95c16e949b61398129a3e41a8f68bad84c94f"
NEVER = 10 ** 12  # seconds: no stamp in a case is this far from now


def verdict(request: dict) -> str:
    """keripy 1.2.14's verdict on one acdc.verify request."""
    # keripy prints some refusals; they go to stderr so the results stay readable.
    with contextlib.redirect_stdout(sys.stderr), \
            habbing.openHby(name="kcs-1x-check", temp=True) as hby:
        vry = verifying.Verifier(hby=hby, expiry=NEVER)
        for raw in request["schemas"]:
            schema = bytes.fromhex(raw)
            vry.resolver.add(json.loads(schema)["$id"], schema)
        psr = parsing.Parser(framed=True, kvy=hby.kvy, tvy=vry.tvy, vry=vry)
        streams = ([k["stream"] for k in request["kels"]]
                   + [r["stream"] for r in request["registry"]]
                   + [a["stream"] for a in request["acdcs"]] + [request["presented"]["stream"]])
        for stream in streams:
            psr.parse(ims=bytearray(bytes.fromhex(stream)))
        hby.kvy.processEscrows()
        vry.tvy.processEscrows()
        vry.processEscrows()
        presented = serdering.SerderACDC(raw=bytearray(bytes.fromhex(
            request["presented"]["stream"])))
        said = presented.said
        if vry.reger.saved.get(keys=said) is not None:
            return "valid"
        for escrow in (vry.reger.mre, vry.reger.mce, vry.reger.mse):
            if escrow.get(keys=said) is not None:
                return "incomplete"
        return "invalid"


def issuance(request: dict) -> str:
    """keripy 1.2.14's own outcome for one acdc.issue request: issued, or refused when a credential
    its issuer builds fails the credential's schema."""
    schemas = {json.loads(bytes.fromhex(raw))["$id"]: bytes.fromhex(raw)
               for raw in request["schemas"]}
    for asked in request["credentials"]:
        creder = proving.credential(schema=asked["schema"], issuer="E" + "I" * 43,
                                    data=dict(asked["attributes"]),
                                    recipient="E" + "H" * 43 if "issuee" in asked else None,
                                    private=True, status="E" + "R" * 43)
        try:
            scheming.Schemer(raw=schemas[asked["schema"]]).verify(creder.raw)
        except kering.ValidationError:
            return "refused"
    return "issued"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("cases", nargs="*", type=pathlib.Path)
    args = parser.parse_args(argv)
    paths = args.cases or sorted((ROOT / "cases" / "sedi1x").glob("*.json"))
    disagreements = 0
    for path in paths:
        case = json.loads(path.read_text())
        request = case.get("input", case)
        if case.get("operation") == "acdc.issue":
            expected = "refused" if case["assertions"][0]["check"] == "issue_refused" else "issued"
            print(f"note {case['id']}: keripy 1.2.14 {issuance(request)}; the case expects "
                  f"{expected}, by SEDI's schema rather than keripy's behaviour")
            continue
        got = verdict(request)
        expected = next((a["expected"] for a in case.get("assertions", [])
                         if a["check"] == "verdict"), None)
        same = got == expected  # a case with no verdict assertion checks nothing, so it fails
        disagreements += not same
        print(f"{'ok  ' if same else 'DIFF'} {case.get('id', path.name)}: keripy 1.2.14 says "
              f"{got}" + ("" if same else f", the case expects {expected or 'no verdict'}"))
    return 1 if disagreements else 0


if __name__ == "__main__":
    sys.exit(main())
