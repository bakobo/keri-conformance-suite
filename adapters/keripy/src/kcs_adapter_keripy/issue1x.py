"""acdc.issue on keripy 1.2.14: a 1.x issuance (registry kind ptel-1x) made with keripy's own
issuer functions (this.i 9sgwng6m).

For every request the adapter opens a fresh, temporary Habery and makes one transferable
identifier per role with no witnesses. Each credential gets a registry of its own, made as
keripy's Registry makes one with no backers: ``vdr.eventing.incept`` with a fresh nonce, anchored
by an interaction carrying its event seal. The credential is ``vc.proving.credential``'s, private
so that it carries keripy's salts, and is checked against its schema as ``Credentialer.validate``
checks it before ``kli vc create`` issues; then its ``iss`` (``vdr.eventing.issue``) is anchored
the same way. Nothing is given that keripy does not choose for itself: keys, salts, nonces and
the clock are keripy's, and so is ``a.dt``, which ``proving.credential`` adds whether or not it was
asked for (interop/two-wallets/INCOMPATIBILITIES.md entry 8).

The result is each identifier's KEL as keripy clones it, and each credential's ACDC and registry
events' bodies. A schema check keripy fails is answered as a refusal, with keripy's reason; a
request for anything but a 1.x registry, or for an edge section, is beyond keripy 1.x's issuer
here and gets an unsupported error.
"""

import contextlib
import sys

from keri import kering
from keri.app import habbing
from keri.core import coring, scheming, signing
from keri.vc import proving
from keri.vdr import eventing

from kcs_adapter_keripy import acdc1x, kel
from kcs_adapter_keripy.errors import Unsupported

ONE_X = "ptel-1x"
E_UNSUPPORTED_ISSUE = "e.feature.unsupported.issue-1x.f"


def _request(request) -> tuple[list[str], dict[str, bytes], list[dict]]:
    roles = request.get("roles")
    if not isinstance(roles, list) or not roles or not all(isinstance(r, str) and r
                                                           for r in roles) \
            or len(set(roles)) != len(roles):
        raise kel.Malformed(f'{kel.E_MALFORMED}: "roles" must be a non-empty list of distinct '
                            "names.")
    schemas = dict(acdc1x._schemas(request))
    credentials = request.get("credentials")
    if not isinstance(credentials, list) or not credentials or not all(
            isinstance(c, dict) and isinstance(c.get("name"), str) and c.get("issuer") in roles
            and c.get("issuee", roles[0]) in roles and isinstance(c.get("schema"), str)
            and isinstance(c.get("attributes"), dict) and isinstance(c.get("registry"), str)
            for c in credentials):
        raise kel.Malformed(f'{kel.E_MALFORMED}: "credentials" must be a non-empty list of '
                            "credentials, each naming roles the request creates.")
    names = [c["name"] for c in credentials]
    if len(set(names)) != len(names):
        raise kel.Malformed(f"{kel.E_MALFORMED}: a credential name appears twice.")
    for credential in credentials:
        if credential["registry"] != ONE_X:
            raise Unsupported(f"{E_UNSUPPORTED_ISSUE}: keripy 1.2.14 issues only into a 1.x "
                              f"registry ({ONE_X}), and {credential['name']!r} asks for "
                              f"{credential['registry']!r}.")
        if "edges" in credential:
            raise Unsupported(f"{E_UNSUPPORTED_ISSUE}: this adapter does not issue a 1.x edge "
                              "section.")
    return roles, schemas, credentials


def _anchor(hab, i: str, s: str, d: str) -> None:
    """An interaction on the issuer's KEL carrying the event seal keripy anchors a registry
    event with."""
    hab.interact(data=[{"i": i, "s": s, "d": d}])


def _kel(hby, hab) -> str:
    return b"".join(bytes(msg) for msg in hby.db.clonePreIter(pre=hab.pre)).hex()


def issue(request):
    roles, schemas, credentials = _request(request)
    with contextlib.redirect_stdout(sys.stderr), \
            habbing.openHby(name="kcs-issue-1x", temp=True) as hby:
        habs = {role: hby.makeHab(name=role, transferable=True, icount=1, isith="1", ncount=1,
                                  nsith="1")
                for role in roles}
        out = {}
        for credential in credentials:
            name = credential["name"]
            hab = habs[credential["issuer"]]
            raw = schemas.get(credential["schema"])
            if raw is None:
                raise kel.Malformed(f"{kel.E_MALFORMED}: {name!r} names the schema "
                                    f"{credential['schema']}, which the request does not carry.")
            vcp = eventing.incept(hab.pre, baks=[], toad=0, nonce=signing.Salter().qb64,
                                  cnfg=[eventing.TraitDex.NoBackers], code=coring.MtrDex.Blake3_256)
            issuee = habs[credential["issuee"]].pre if "issuee" in credential else None
            creder = proving.credential(schema=credential["schema"], issuer=hab.pre,
                                        data=dict(credential["attributes"]), recipient=issuee,
                                        private=True, status=vcp.pre)
            try:
                scheming.Schemer(raw=raw).verify(creder.raw)
            except kering.ValidationError as exc:
                # jsonschema's message runs on with the schema it failed; its first line is why.
                why = str(exc).splitlines()[0] if str(exc) else type(exc).__name__
                return {"refused": {"reason": "keripy 1.2.14's issuer refuses it: credential "
                                              f"schema validation failed: {why}"}}
            _anchor(hab, vcp.pre, vcp.ked["s"], vcp.said)
            iss = eventing.issue(vcdig=creder.said, regk=vcp.pre)
            _anchor(hab, iss.ked["i"], iss.ked["s"], iss.said)
            out[name] = {"acdc": bytes(creder.raw).hex(),
                         "registry": (bytes(vcp.raw) + bytes(iss.raw)).hex()}
        return {"kels": {role: _kel(hby, hab) for role, hab in habs.items()}, "credentials": out}
