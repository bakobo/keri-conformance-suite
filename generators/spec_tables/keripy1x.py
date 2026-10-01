"""The CESR 1.00 count-code table as keripy 1.x uses it, for the keripy-1x-interop profile.

No specification defines this table, so cases built from it are non-normative: they report
interoperability with keripy 1.x and nothing more. It is transcribed from keripy 1.2.14 (tag
``1.2.14``, commit ``bab95c16e949b61398129a3e41a8f68bad84c94f``), ``src/keri/core/counting.py``:
the codes from ``CounterCodex_1_0`` (lines 46-71) and their sizes from ``Counter.Sizes[1][0]``
(lines 343-366). In that table most codes count items, not quadlets: ``-A`` counts indexed
controller signatures, ``-C`` counts (prefix, signature) couples, while ``-V`` and ``-0V``
count quadlets. Only the codes the interop cases use are transcribed; ``generators/keripy1x_check``
checks each against keripy 1.2.14 itself.
"""

from .decoding import Legacy

KERIPY_1X_VERSION = "1.2.14"
KERIPY_1X_COMMIT = "bab95c16e949b61398129a3e41a8f68bad84c94f"
REFERENCE = {"implementation": "keripy", "commit": KERIPY_1X_COMMIT}

TABLE = {
    "-A": Legacy(hs=2, ss=2, unit="indexed"),  # ControllerIdxSigs
    "-B": Legacy(hs=2, ss=2, unit="indexed"),  # WitnessIdxSigs
    "-C": Legacy(hs=2, ss=2, unit="primitive", per=2),  # NonTransReceiptCouples, pre+cig
    "-V": Legacy(hs=2, ss=2, unit="quadlets"),  # AttachmentGroup
    "-0V": Legacy(hs=3, ss=5, unit="quadlets"),  # BigAttachmentGroup
}
