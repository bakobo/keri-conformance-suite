"""Fetch a witnessed Veridian holder's KERI 1.x event stream with heti's keripy."""

import json
import sys
from pathlib import Path
from urllib.request import urlopen

from keri.core.eventing import Kevery
from keri.core.parsing import Parser
from keri.db.basing import Baser
from keri.kering import Vrsn_1_0


def main() -> None:
    output = Path(sys.argv[1]).resolve()
    details = json.loads(output.read_text())
    aid = details["aid"]
    url = f"http://127.0.0.1:5642/oobi/{aid}/witness"
    with urlopen(url, timeout=15) as response:
        kel = response.read()
    if not kel:
        raise RuntimeError(f"Witness returned an empty KEL for {aid}.")

    db = Baser(name="g17-witness-fetch", temp=True, reopen=True)
    try:
        kevery = Kevery(db=db, lax=False, local=False)
        Parser(version=Vrsn_1_0).parse(ims=bytearray(kel), kvy=kevery, local=False)
        kevery.processEscrows()
        kever = kevery.kevers.get(aid)
        if kever is None:
            raise RuntimeError(f"Keripy did not establish a verified state for {aid} from {url}.")
        keys = [verfer.qb64 for verfer in kever.verfers]
        print(json.dumps({"aid": aid, "sn": kever.sn, "keys": keys}, indent=2))
    finally:
        db.close(clear=True)

    output.with_name("m1-kel.cesr").write_bytes(kel)


if __name__ == "__main__":
    main()
