"""The adapter-protocol result shapes, mirrored by hand from schema/adapter-protocol.schema.json.

tests/test_schema_agreement.py checks these against the schema over a mutation corpus. The item,
key-state and threshold definitions are shared with the case checks in cases.py, as the two
schemas share them.
"""

from keri_conformance.assertions import normalize_threshold
from keri_conformance.shapes import (
    HEX,
    all_of,
    array,
    enum,
    integer,
    keyed,
    mapping,
    nullable,
    obj,
    predicate,
    string,
    tagged,
)

# A message's initial and final readings: seen (accepted into the validator's KEL), or the most
# specific refinement of not seen that the implementation knows (docs/design.md, KERI).
READINGS = ("seen", "pending", "rejected", "duplicitous")

HEX_STRING = string(HEX)
OFFSET = integer(minimum=0)
_SPAN = {"start": OFFSET, "end": OFFSET}

ITEM = tagged("kind", {
    "primitive": obj({"kind": enum("primitive"), **_SPAN, "code": string(), "raw": HEX_STRING}),
    "indexed": obj({"kind": enum("indexed"), **_SPAN, "code": string(), "raw": HEX_STRING,
                    "index": OFFSET}, {"ondex": OFFSET}),
    "counter": obj({"kind": enum("counter"), **_SPAN, "code": string(), "size": OFFSET,
                    "group_end": OFFSET}),
    # A genus/version code is no count: it has no size and introduces no group.
    "genus": obj({"kind": enum("genus"), **_SPAN, "code": string("^-_[A-Za-z0-9_-]{6}$"),
                  "genus": string("^[A-Za-z0-9_-]{3}$"),
                  "version": string(r"^[0-9]+\.[0-9]{2,}$")}),
    "message": obj({"kind": enum("message"), **_SPAN, "proto": string(), "version": string(),
                    "serialization": enum("JSON", "CBOR", "MGPK"), "size": OFFSET}),
})

THRESHOLD = predicate(lambda value: normalize_threshold(value) is not None,
                      "a hex numeric threshold, or weighted clauses of fraction strings")

KEY_STATE = obj({
    "sn": OFFSET, "said": string(), "keys": array(string()), "kt": THRESHOLD,
    "ndigs": array(string()), "nt": THRESHOLD, "wits": array(string()), "bt": string(r"^(0x)?[0-9a-f]{1,64}$"),
    "delegator": nullable(string()),
})

DISPOSITION = all_of(
    obj({"initial": enum(*READINGS), "final": enum(*READINGS), "trunk": enum(True, False)},
        {"reason": string()}),
    # The trunk is a path through the KEL's events, so only a finally seen message is on it.
    predicate(lambda value: value["trunk"] is False or value["final"] == "seen",
              'off the trunk ("trunk": false) unless its final reading is "seen"'),
)

# ACDC (docs/design.md, ACDC). A SAID is never empty. An edge is named by its near node's SAID and
# the label path from that node's top-level "e" field, such as "e.le".
SAID = string(min_length=1)
EDGE_PATH = r"^e(\.[^.]+)+$"
VERDICTS = ("valid", "invalid", "incomplete")
# The verified head of a registry; td and ts are both null when a blinded state was not disclosed.
REGISTRY_STATE = all_of(
    obj({"rd": SAID, "n": OFFSET, "d": SAID, "td": nullable(SAID), "ts": nullable(string())}),
    predicate(lambda value: (value["td"] is None) == (value["ts"] is None),
              "td and ts both null (an undisclosed blinded state) or both given"),
)
EDGE_REPORT = obj({"near": SAID, "path": string(EDGE_PATH), "n": SAID,
                   "valid": enum(True, False)})
# An exchange message's readings at quiescence after its own delivery and after the last message.
EXN_READINGS = ("accepted", "rejected")
EXN_VERDICT = obj({"on_delivery": enum(*EXN_READINGS), "verdict": enum(*EXN_READINGS)},
                  {"reason": string()})

ERROR = obj({"kind": enum("harness", "unsupported"), "message": string()})

RESULTS = {
    # "accepted" is the summary an adapter without cesr.item-extents gives for a stream its
    # implementation accepted; the runner also bounds "consumed" by the stream (session.py).
    "cesr.parse": keyed({"items": obj({"items": array(ITEM)}),
                         "reject": obj({"reject": obj({"class": string()})}),
                         "accepted": obj({"accepted": obj({"consumed": OFFSET})})}),
    "cesr.encode": obj({"encoded": HEX_STRING}),
    "keri.process": obj({
        "dispositions": array(DISPOSITION),
        "key_states": mapping(KEY_STATE),
    }),
    "keri.emit": obj({"stream": HEX_STRING}),
    "acdc.verify": obj({"verdict": enum(*VERDICTS), "registry": nullable(REGISTRY_STATE),
                        "edges": array(EDGE_REPORT)},
                       {"reason": string()}),
    "exn.verify": obj({"verdicts": array(EXN_VERDICT)}),
}
