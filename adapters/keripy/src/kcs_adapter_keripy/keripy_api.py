"""What differs between the keripy generations the adapter runs against, in one place.

keripy main (2.x) and keripy 1.2.14 share the parser design this adapter drives
(Parser.msgParsator) but differ in its signature, in how it hands group contents to helper
methods, and in where its helpers live. Nothing here computes a reported value; see measure.py.
"""

import importlib.metadata
import inspect
import json

from keri import kering
from keri.core import coring, counting, indexing, parsing

from kcs_adapter_keripy.errors import keri

try:
    from keri.help import b64ToInt
except ImportError:  # keripy 1.x keeps it in keri.help.helping
    from keri.help.helping import b64ToInt


def implementation():
    """Name, version and commit of the installed keripy distribution."""
    dist = importlib.metadata.distribution("keri")
    direct = dist.read_text("direct_url.json")
    commit = json.loads(direct)["vcs_info"]["commit_id"] if direct else "unknown"
    return {"name": "keripy", "version": dist.version, "commit": commit}


class _Common:
    generation = None
    features = ()
    Counter = counting.Counter
    Matter = coring.Matter
    Indexer = indexing.Indexer
    Parser = parsing.Parser
    GENUS_CODE = counting.CtrDex_1_0.KERIACDCGenusVersion

    # Helper generators keripy's msgParsator hands a whole group to, by name. The adapter wraps
    # each to measure where keripy was when the helper returned (the group's end).
    GROUP_METHODS = ()
    # Count codes whose group keripy consumes inline in msgParsator while also extracting a
    # nested count code inline, so that nothing keripy does marks where the outer group ends.
    UNMEASURABLE = ()

    @staticmethod
    def sniff(buf):
        return keri(kering.sniff, buf)

    @staticmethod
    def smell(buf):
        """(proto, protocol version, kind, size) from keripy's smell of the version string."""
        proto, pvrsn, kind, size = tuple(keri(kering.smell, buf))[:4]
        return proto, pvrsn, kind, size

    def genus_version(self, ctr):
        """(genus, table version text) of a genus-version code, as keripy's parser reads it."""
        version = keri(lambda: self.Counter.b64ToVer(ctr.countToB64(l=3)))
        return ctr.code[2:], f"{version.major}.{version.minor:02}"

    def ondex_field(self, indexer):
        """The ondex field of an indexed signature, or None when its code's row in keripy's
        Indexer.Sizes has no ondex (os == 0).

        For current-only codes keripy reads the field, rejects it unless it is zero, and then
        stores None (Indexer._exfil); for those the field is read back from keripy's own
        re-serialization of the signature (Indexer.qb64), at the offsets keripy's table gives."""
        hs, ss, os, _, _ = keri(lambda: tuple(self.Indexer.Sizes[indexer.code]))
        if not os:
            return None
        if indexer.ondex is not None:
            return indexer.ondex
        ms = ss - os
        return keri(lambda: b64ToInt(indexer.qb64[hs + ms:hs + ms + os]))


class Main(_Common):
    """keripy main (2.x)."""

    generation = "main"
    # cesr.item-extents: keripy main itemizes every stream it accepts except a native CESR body
    # (measure.E_NATIVE), which is cesr.native, a feature this adapter does not declare.
    features = ("cesr.domain.binary", "cesr.genus-1.00", "cesr.genus-2.00", "cesr.item-extents",
                "cesr.serialization.cbor", "cesr.serialization.json", "cesr.serialization.mgpk",
                "keri.version-1.x", "keri.version-2.x")
    # Every method name in keripy main's Parser.Methods dispatch table.
    GROUP_METHODS = tuple(sorted({name for minors in getattr(parsing.Parser, "Methods",
                                                             {}).values()
                                  for table in minors.values()
                                  for name in table.values() if name}))

    def run(self, parser, ims):
        return parser.msgParsator(ims=ims, framed=True, piped=False, version=None)


class OneX(_Common):
    """keripy 1.x (1.2.14)."""

    generation = "1.x"
    # Not cesr.item-extents: that promises the decoded items of every stream keripy accepts, and
    # the adapter cannot measure -H and -J groups on this generation (UNMEASURABLE below).
    features = ("cesr.domain.binary", "cesr.genus-1.00", "cesr.serialization.cbor",
                "cesr.serialization.json", "cesr.serialization.mgpk", "keri.version-1.x")
    GROUP_METHODS = ("_nonTransReceiptCouples", "_transIdxSigGroups", "_sadPathSigGroup")
    UNMEASURABLE = tuple(getattr(counting.CtrDex_1_0, name) for name in
                         ("TransLastIdxSigGroups", "SadPathSigGroups")
                         if hasattr(counting.CtrDex_1_0, name))

    def run(self, parser, ims):
        return parser.msgParsator(ims=ims, framed=True, pipeline=False)


def load():
    """The API object for whichever keripy is installed."""
    if "version" in inspect.signature(parsing.Parser.__init__).parameters:
        return Main()
    return OneX()
