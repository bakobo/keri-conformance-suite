"""acdc.issue through heti's public issuer, OwnFacet.issue (this.i 2u2ps8mt).

For every request the adapter builds a fresh lockbox in a temporary directory, learns the
request's schemas, mints one facet per role with no witnesses, and issues each credential as heti
issues: with its own keys, salts, registry nonces and clock, in a blindable registry of the
credential's own. Credentials are issued far nodes first, so an edge names a far credential heti
has already issued, by its SAID and its schema's. The result is each facet's KEL and each
credential's ACDC, registry chain and head disclosure, all as heti returns them.

heti refuses by raising an error with a code; the adapter answers that as a refusal, a result a
case can require. Anything else heti raises is an adapter error.
"""

import asyncio
import pathlib
import tempfile

from heti.anchored.produce import Lockbox, new_recovery_code

from kcs_adapter_heti import verify

E_MALFORMED = verify.E_MALFORMED


def _request(request) -> tuple[list[str], list[bytes], list[dict]]:
    roles = request.get("roles")
    if not isinstance(roles, list) or not roles or not all(isinstance(r, str) and r
                                                           for r in roles):
        raise verify.Malformed(f'{E_MALFORMED}: "roles" must be a non-empty list of names.')
    schemas = verify._schemas(request)
    credentials = request.get("credentials")
    if not isinstance(credentials, list) or not credentials or not all(
            isinstance(c, dict) and isinstance(c.get("name"), str) and c.get("issuer") in roles
            and c.get("issuee", roles[0]) in roles and isinstance(c.get("schema"), str)
            and isinstance(c.get("attributes"), dict) and c.get("registry") == "bup"
            and isinstance(c.get("edges", {}), dict) for c in credentials):
        raise verify.Malformed(f'{E_MALFORMED}: "credentials" must be a non-empty list of '
                               "credentials, each naming roles the request creates.")
    return roles, schemas, credentials


def far_first(credentials: list[dict]) -> list[dict]:
    """The credentials, each after every credential its edges name. A name no credential has,
    or an edge back to itself, is left for heti to refuse."""
    by_name = {c["name"]: c for c in credentials}
    out, done = [], set()

    def names(edges):
        for value in edges.values():
            if isinstance(value, dict):
                yield from ([value["credential"]] if "credential" in value else names(value))

    def visit(name, path):
        if name in done or name not in by_name or name in path:
            return
        for far in names(by_name[name].get("edges", {})):
            visit(far, path | {name})
        done.add(name)
        out.append(by_name[name])

    for credential in credentials:
        visit(credential["name"], set())
    return out


def edges(asked: dict, issued: dict, schemas: dict[str, str]) -> dict:
    """heti's edge section for the one asked for: each edge names its far credential by SAID and
    its schema, with the operators asked for; a group keeps its operator."""
    out = {}
    for label, value in asked.items():
        if label == "o":
            out["o"] = value
        elif isinstance(value, dict) and "credential" in value:
            far = issued.get(value["credential"])
            block = {"n": far.said if far else value["credential"],
                     "s": schemas.get(value["credential"], "")}
            if "o" in value:
                block["o"] = value["o"]
            out[label] = block
        else:
            out[label] = edges(value, issued, schemas) if isinstance(value, dict) else value
    return out


async def _issue(home: pathlib.Path, roles, schemas, credentials) -> dict:
    box = Lockbox.create(path=home, passcode=verify.PASSCODE, recovery=new_recovery_code())
    try:
        for raw in schemas:
            box.learn_schema(raw=raw)
        facets = {role: await box.mint(witnesses=[]) for role in roles}
        issued, schema_of = {}, {}
        for credential in far_first(credentials):
            name = credential["name"]
            issuee = facets[credential["issuee"]].aid if "issuee" in credential else None
            kwargs = {"schema": credential["schema"], "attributes": credential["attributes"],
                      "issuee": issuee}
            if credential.get("edges"):
                kwargs["edge"] = edges(credential["edges"], issued, schema_of)
            issued[name] = await facets[credential["issuer"]].issue(**kwargs)
            schema_of[name] = credential["schema"]
        return {"kels": {role: bytes(facet.kel()).hex() for role, facet in facets.items()},
                "credentials": {name: {"acdc": bytes(i.acdc).hex(),
                                       "registry": bytes(i.chain).hex(),
                                       "disclosure": i.blinder}
                                for name, i in issued.items()}}
    finally:
        box.close()


async def _answer(home, roles, schemas, credentials) -> dict:
    try:
        return await _issue(home, roles, schemas, credentials)
    except Exception as exc:  # heti refuses by raising a coded error
        code = getattr(exc, "code", None)
        if code is None:
            raise
        return {"refused": {"reason": f"{code}: {exc}"}}


def issue(request) -> dict:
    roles, schemas, credentials = _request(request)
    with tempfile.TemporaryDirectory(prefix="kcs-adapter-heti-") as home:
        return asyncio.run(_answer(pathlib.Path(home) / "lockbox", roles, schemas, credentials))
