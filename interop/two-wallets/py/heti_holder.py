"""Move Veridian's exported 1.x holder material into a fresh heti home."""

from __future__ import annotations

import json
import pathlib
import secrets
import shutil
import urllib.error
import urllib.request

from heti.anchored.interop import keri1
from keri.core import serdering

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "out"
LIMIT = 1024 * 1024
HTTP_BODY_TOO_LARGE = "e.input.http-response-size.f"


def read_response(response) -> bytes:
    body = response.read(LIMIT + 1)
    if len(body) > LIMIT:
        raise RuntimeError(f"{HTTP_BODY_TOO_LARGE}: HTTP response exceeds one MiB.")
    return body


def get(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=30) as response:
        return read_response(response)


def send(grant: bytes, verifier: str, content_type: str) -> tuple[int, str]:
    exn = serdering.SerderKERI(raw=grant)
    request = urllib.request.Request(
        "http://127.0.0.1:3902/",
        data=exn.raw,
        headers={
            "Content-Type": content_type,
            "CESR-ATTACHMENT": grant[exn.size:].decode("ascii"),
            "CESR-DESTINATION": verifier,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, read_response(response).decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        return error.code, read_response(error).decode("utf-8", "replace")


def main() -> None:
    exported = json.loads((OUT / "export.json").read_text())
    verifier = json.loads((OUT / "verifier.json").read_text())
    home = OUT / "heti-holder"
    shutil.rmtree(home, ignore_errors=True)
    kel = get(f"http://127.0.0.1:5642/oobi/{exported['aid']}/witness")
    with keri1.Holder.create(path=home, passcode=secrets.token_urlsafe(24)) as holder:
        aid = holder.adopt(bran=exported["bran"], sxlt=exported["sxlt"], kel=kel)
        if aid != exported["aid"]:
            raise ValueError("heti adopted a different holder AID")
        said = holder.ingest(
            aid=aid,
            credential=(OUT / "export-credential.cesr").read_bytes(),
            schema=(ROOT / "schemas" / "sedi-core-1x.schema.json").read_bytes(),
        )
        if said != exported["said"]:
            raise ValueError("heti ingested a different credential SAID")
        grant = holder.grant(aid=aid, said=said, recipient=verifier["aid"], message="G17 heti")
    (OUT / "heti-holder.json").write_text(json.dumps({"aid": aid, "said": said}, indent=2) + "\n")
    (OUT / "heti-grant.cesr").write_bytes(grant)
    # The brief's media type is attempted exactly. The keripy parser in the
    # pinned KERIA image may instead require its CESR_CONTENT_TYPE constant.
    attempts = []
    for content_type in ("application/cesr+json", "application/cesr"):
        status, body = send(grant, verifier["aid"], content_type)
        attempts.append({"content_type": content_type, "status": status, "body": body[:1000]})
        if status == 204:
            break
        if status != 406:
            break
    exn = serdering.SerderKERI(raw=grant)
    result = {"posted": attempts[-1]["status"] == 204, "delivered": None,
              "grant_said": exn.said, "grant_route": exn.ked["r"],
              "grant_rp": exn.ked.get("rp"), "grant_a_i": exn.ked["a"].get("i"),
              "attempts": attempts}
    (OUT / "heti-delivery.json").write_text(json.dumps(result, indent=2) + "\n")
    if not result["posted"]:
        raise RuntimeError(f"KERIA rejected the signed heti grant: {attempts}")


if __name__ == "__main__":
    main()
