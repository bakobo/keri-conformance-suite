"""The adapter-protocol result shapes, mirrored by hand from schema/adapter-protocol.schema.json.

tests/test_schema_agreement.py checks these against the schema over a mutation corpus. The item,
key-state and threshold definitions are shared with the case checks in cases.py, as the two
schemas share them.
"""

from keri_conformance.assertions import normalize_threshold
from keri_conformance.shapes import (
    HEX,
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

INITIAL_DISPOSITIONS = ("accepted", "pending", "rejected", "duplicitous")
FINAL_DISPOSITIONS = (*INITIAL_DISPOSITIONS, "superseded")

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

ERROR = obj({"kind": enum("harness", "unsupported"), "message": string()})

RESULTS = {
    # "accepted" is the summary an adapter without cesr.item-extents gives for a stream its
    # implementation accepted; the runner also bounds "consumed" by the stream (session.py).
    "cesr.parse": keyed({"items": obj({"items": array(ITEM)}),
                         "reject": obj({"reject": obj({"class": string()})}),
                         "accepted": obj({"accepted": obj({"consumed": OFFSET})})}),
    "cesr.encode": obj({"encoded": HEX_STRING}),
    "keri.process": obj({
        "dispositions": array(obj({"initial": enum(*INITIAL_DISPOSITIONS),
                                   "final": enum(*FINAL_DISPOSITIONS)},
                                  {"reason": string()})),
        "key_states": mapping(KEY_STATE),
    }),
    "keri.emit": obj({"stream": HEX_STRING}),
}
