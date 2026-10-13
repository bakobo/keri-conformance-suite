"""Fetch a witnessed Veridian holder's KERI 1.x event stream with heti's keripy."""

import json
import re
import sys
from pathlib import Path
from urllib.request import urlopen

from keri.core.eventing import Kevery
from keri.core.parsing import Parser
from keri.core.routing import Revery, Router
from keri.db.basing import Baser
from keri.kering import Vrsn_1_0

LIMIT = 1024 * 1024
VERSION_2 = re.compile(rb'"v":"(?:KERI|ACDC)[A-Z]')
KEL_TOO_LARGE = "e.input.witness-kel-size.f"
KEL_VERSION_UNSUPPORTED = "e.input.witness-kel-version.f"
KEL_UNVERIFIED = "e.proof.witness-kel.f"


def main() -> None:
    output = Path(sys.argv[1]).resolve()
    details = json.loads(output.read_text())
    aid = details["aid"]
    url = f"http://127.0.0.1:5642/oobi/{aid}/witness"
    with urlopen(url, timeout=15) as response:
        kel = response.read(LIMIT + 1)
    if len(kel) > LIMIT:
        raise RuntimeError(f"{KEL_TOO_LARGE}: Witness KEL for {aid} exceeds one MiB.")
    if not kel:
        raise RuntimeError(f"Witness returned an empty KEL for {aid}.")
    if VERSION_2.search(kel):
        raise RuntimeError(
            f"{KEL_VERSION_UNSUPPORTED}: Witness KEL for {aid} contains a KERI or ACDC 2.0 version string."
        )

    db = Baser(name="g17-witness-fetch", temp=True, reopen=True)
    try:
        router = Router()
        revery = Revery(db=db, rtr=router, lax=False, local=False)
        kevery = Kevery(db=db, lax=False, local=False, rvy=revery)
        kevery.registerReplyRoutes(router=router)
        claimed: dict[str, int] = {}
        process = kevery.processEvent

        def recording(serder, **kwa):
            claimed[serder.pre] = max(claimed.get(serder.pre, -1), serder.sn)
            return process(serder, **kwa)

        kevery.processEvent = recording
        faults = []
        Parser(version=Vrsn_1_0).parse(
            ims=bytearray(kel), kvy=kevery, rvy=revery, local=False, faults=faults
        )
        if faults:
            first = faults[0]
            raise RuntimeError(
                f"{KEL_UNVERIFIED}: Witness KEL for {aid} had {len(faults)} parser fault(s); "
                f"first was {first.kind} at byte offset {first.offset}."
            )
        kevery.processEscrows()
        kever = kevery.kevers.get(aid)
        if kever is None:
            raise RuntimeError(f"Keripy did not establish a verified state for {aid} from {url}.")
        if claimed.get(aid, -1) > kever.sn:
            raise RuntimeError(
                f"{KEL_UNVERIFIED}: Witness KEL for {aid} claimed sequence "
                f"{claimed[aid]}, but only sequence {kever.sn} was verified."
            )
        keys = [verfer.qb64 for verfer in kever.verfers]
        print(json.dumps({"aid": aid, "sn": kever.sn, "keys": keys}, indent=2))
    finally:
        db.close(clear=True)

    output.with_name("m1-kel.cesr").write_bytes(kel)


if __name__ == "__main__":
    main()
