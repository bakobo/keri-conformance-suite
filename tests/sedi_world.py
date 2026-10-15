"""A small world of SEDI credentials for the sedi-1 model and case tests: each credential has its
own blindable registry, its inception and each update anchored in its own interaction event of
the issuer's KEL."""

import copy

from generators.spec_tables import json_schema_subset as js

ATTRS = {"type": "object", "required": ["d", "name"],
         "properties": {"d": {"type": "string"}, "i": {"type": "string"},
                        "name": {"type": "string"}}}
S1 = {"$id": "", "$schema": js.DIALECT, "version": "1.0.0", "type": "object",
      "required": ["v", "d", "i", "s"],
      "properties": {"a": {"oneOf": [{"type": "string"}, ATTRS]},
                     "A": {"oneOf": [{"type": "string"}, {"type": "array"}]},
                     "e": {"oneOf": [{"type": "string"}, {"type": "object"}]}}}
AIDS = ("I", "H", "Q", "R")


def cred(issuer, issuee="H", e=None, states=("issued",), **over):
    spec = {"issuer": issuer, "issuee": issuee, "states": states, **over}
    if e is not None:
        spec["e"] = e
    return spec


def world(creds: dict, presented: str, shape: str = "isd", extra_aids=()) -> dict:
    """A fragment in which each credential has its own registry, its inception and each update
    anchored by a seal of ``shape`` in its own interaction event of the issuer's KEL."""
    events = [{"name": f"{a}icp", "aid": a, "t": "icp", "keys": [f"{a}0"], "next": [f"{a}1"]}
              for a in AIDS]
    events += list(extra_aids)
    kels = [{"event": f"{a}icp", "sigs": [f"{a}0"]} for a in AIDS]
    kels += [{"event": x["name"], "sigs": x.pop("sigs")} for x in events if "sigs" in x]
    registries, acdcs = [], []
    for name, spec in creds.items():
        rip = f"rip-{name}"
        registries.append({"name": rip, "t": "rip", "issuer": spec["issuer"]})
        seals = [rip]
        for k, ts in enumerate(spec["states"]):
            bup = f"bup-{name}-{k + 1}"
            registries.append({"name": bup, "t": "bup", "registry": rip, "disclose": True,
                               "state": {"u": f"s-{name}-{k}", "td": {"acdc": name}, "ts": ts}})
            seals.append(bup)
        for seal in seals:
            events.append({"name": f"ixn-{seal}", "aid": spec["issuer"], "t": "ixn",
                           "a": [{"registry": seal, "shape": shape}]})
            kels.append({"event": f"ixn-{seal}", "sigs": [f"{spec['issuer']}0"]})
        a = {"d": "", "name": name}
        if spec["issuee"] is not None:
            a = {"d": "", "i": {"aid": spec["issuee"]}, "name": name}
        acdc = {"name": name, "issuer": spec["issuer"], "schema": "S1", "registry": rip,
                "form": "expanded", "a": a}
        if "e" in spec:
            acdc["e"] = spec["e"]
        acdcs.append(acdc)
    return {"events": events, "kels": kels, "schemas": [{"name": "S1", "schema": copy.deepcopy(S1)}],
            "registries": registries, "acdcs": acdcs, "presented": presented}


def edge(far, o="I2I", **over):
    block = {"d": "", "n": {"acdc": far}, "o": o, **over}
    return {k: v for k, v in block.items() if v is not None}


def single(far="F", o="I2I", **over):
    """N, issued by I to H, with one edge to F, issued by Q to I."""
    return {"F": cred("Q", "I"), "N": cred("I", "H", e={"d": "", "le": edge(far, o, **over)})}
