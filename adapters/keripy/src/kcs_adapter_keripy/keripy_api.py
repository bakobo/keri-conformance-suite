"""The keripy surface the adapter uses, for the two keripy generations it runs against.

keripy main (2.x) and keripy 1.2.14 differ in the API this adapter needs: main's Parser has a
per-code table of group-extraction methods and its Counter has byteCount; 1.2.14 has neither and
consumes every attachment group inline in Parser.msgParsator. Everything that differs between them
is confined to the two classes here, so that the walk in cesr.py is the same for both.

Every value reported to the runner comes from a keripy call made in this module or in cesr.py
through `keri()`. The few places where the adapter applies a check that keripy applies inline
(rather than through a callable), or transcribes keripy 1.2.14's inline per-code loop, are marked
TRANSCRIBED and listed in README.md.
"""

import importlib.metadata
import inspect
import json

from keri import kering
from keri.core import coring, counting, indexing, parsing

from kcs_adapter_keripy.errors import AdapterBug, Rejection, Unsupported, keri

try:
    from keri.help import b64ToInt, codeB2ToB64
except ImportError:  # keripy 1.x keeps them in keri.help.helping
    from keri.help.helping import b64ToInt, codeB2ToB64

E_GROUP_UNTRANSCRIBED = "e.parse.group.untranscribed.p"


def drive(generator):
    """Run one of keripy's extraction generators to completion and return its value.

    The adapter always passes abort=True, under which keripy raises ShortageError instead of
    yielding for more bytes; a yield therefore means the adapter's assumption about keripy's
    generator protocol is wrong, which is an adapter bug, not a rejection."""
    try:
        next(generator)
    except StopIteration as stop:
        return stop.value
    generator.close()
    raise AdapterBug("e.adapter.extractor.yielded.p: A keripy extractor asked for more bytes "
                     "even though it was called with abort=True.")


def implementation():
    """Name, version and commit of the installed keripy distribution."""
    dist = importlib.metadata.distribution("keri")
    direct = dist.read_text("direct_url.json")
    commit = json.loads(direct)["vcs_info"]["commit_id"] if direct else "unknown"
    return {"name": "keripy", "version": dist.version, "commit": commit}


class _Common:
    """What both generations share: sniff, smell, Matter, Indexer, and the genus counter."""

    generation = None
    features = ()
    Counter = counting.Counter
    Matter = coring.Matter
    Siger = indexing.Siger
    Indexer = indexing.Indexer

    def __init__(self):
        self.parser = parsing.Parser()

    # -- stream boundaries

    @staticmethod
    def sniff(buf):
        return keri(kering.sniff, buf)

    @staticmethod
    def smell(buf):
        """(proto, protocol version, kind, size) from keripy's smell of the version string."""
        smellage = keri(kering.smell, buf)
        proto, pvrsn, kind, size = tuple(smellage)[:4]
        return proto, pvrsn, kind, size

    @staticmethod
    def shortage(message):
        """TRANSCRIBED check: keripy raises ShortageError where an enclosed group or a body is
        shorter than its count or size says (Serder._inhale; Parser group methods under
        abort=True). The adapter applies the same comparison and reports keripy's class."""
        return Rejection(kering.ShortageError.__name__, message)

    # -- items

    def is_genus_version(self, ctr):
        return ctr.code == counting.CtrDex_2_0.KERIACDCGenusVersion

    def genus_version(self, ctr):
        """(genus, gvrsn text) of a genus-version counter, as keripy's parser reads it."""
        version = keri(lambda: self.Counter.b64ToVer(ctr.countToB64(l=3)))
        return ctr.code[2:], f"{version.major}.{version.minor:02}"

    def ondex_field(self, indexer):
        """The ondex field of an indexed signature, or None if its code's table entry (keripy's
        Indexer.Sizes, os) defines no ondex field.

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

    @staticmethod
    def first_code_char(buf, cold):
        if cold == kering.Colds.txt:
            return chr(buf[0])
        return keri(codeB2ToB64, bytes(buf[:1]), 1)


class Main(_Common):
    """keripy main (2.x): Parser.Methods and Counter.byteCount."""

    generation = "main"
    features = ("cesr.domain.binary", "cesr.genus-2.00", "cesr.serialization.cbor",
                "cesr.serialization.json", "cesr.serialization.mgpk", "keri.version-1.x",
                "keri.version-2.x")
    SIGER_METHODS = frozenset({"_ControllerIdxSigs1", "_ControllerIdxSigs2",
                               "_WitnessIdxSigs1", "_WitnessIdxSigs2"})

    def default_version(self):
        return self.parser.version

    def after_genus_version(self, version, ctr):
        """keripy main's parser switches to the counter's version (parsing.py, msgParsator); the
        Parser.version setter refuses versions keripy does not support."""
        new = keri(lambda: self.Counter.b64ToVer(ctr.countToB64(l=3)))

        def adopt():
            self.parser.version = new
            return self.parser.version

        return keri(adopt)

    def set_version(self, version):
        self.parser.version = version

    def extract(self, buf, klas, cold, version):
        self.parser.version = version
        return keri(lambda: drive(self.parser._extractor(ims=buf, klas=klas, cold=cold,
                                                         abort=True)))

    def contents_indexed(self, ctr, version):
        self.parser.version = version
        return self.parser.methods.get(ctr.name) in self.SIGER_METHODS

    def group(self, walk, ctr, end, limit, cold):
        """Walk a group whose counter ends at `end`; return the group's end.

        The extent comes from keripy: the parser method keripy main has for this code, run on the
        rest of the enclosing frame (bytes it consumes); otherwise Counter.byteCount, which keripy
        main's parser uses for every 2.00 group and every 1.00 quadlet-counted (QTDex_1_0) group.
        """
        version = walk.version
        self.parser.version = version
        method = self.parser.methods.get(ctr.name)
        if method:
            buf = bytearray(walk.stream[end:limit])
            before = len(buf)
            keri(lambda: drive(getattr(self.parser, method)(
                exts=parsing.MsgParseDom(), ims=buf, ctr=ctr, cold=cold, abort=True)))
            extent = before - len(buf)
        elif version.major >= 2 or ctr.code in counting.QTDex_1_0:
            extent = keri(ctr.byteCount, cold)
            if extent > limit - end:
                raise self.shortage(f"The {ctr.code} group counts {extent} bytes but only "
                                    f"{limit - end} remain in its frame.")
        else:
            raise Rejection(kering.UnexpectedCountCodeError.__name__,
                            f"keripy main has no way to frame the {version.major}."
                            f"{version.minor:02} code {ctr.code}.")
        group_end = end + extent
        indexed = self.contents_indexed(ctr, version)
        walk.contents(end, group_end, cold, indexed)
        return group_end


class OneX(_Common):
    """keripy 1.x (1.2.14): no byteCount and no per-code methods; groups are consumed inline in
    Parser.msgParsator (src/keri/core/parsing.py, lines 752-982 at 1.2.14)."""

    generation = "1.x"
    features = ("cesr.domain.binary", "cesr.genus-1.00", "cesr.serialization.cbor",
                "cesr.serialization.json", "cesr.serialization.mgpk", "keri.version-1.x")

    def default_version(self):
        """The table keripy 1.x's parser extracts with: Parser._extractor's default gvrsn."""
        return inspect.signature(parsing.Parser._extractor).parameters["gvrsn"].default

    def after_genus_version(self, version, ctr):
        """keripy 1.x's parser discards a genus-version counter without changing tables
        (parsing.py: 'genus-version counter carries no following material; discard')."""
        return version

    def set_version(self, version):
        pass

    def extract(self, buf, klas, cold, version):
        return keri(lambda: drive(parsing.Parser._extractor(ims=buf, klas=klas, cold=cold,
                                                            abort=True, gvrsn=version)))

    def _sequences(self):
        """TRANSCRIBED from keripy 1.2.14's msgParsator: what each item-counted group holds, one
        entry per item extracted per count. "ctr" is a nested ControllerIdxSigs group."""
        c = counting.CtrDex_1_0
        prefixer, seqner, saider = coring.Prefixer, coring.Seqner, coring.Saider
        return {
            c.ControllerIdxSigs: (self.Siger,),
            c.WitnessIdxSigs: (self.Siger,),
            c.NonTransReceiptCouples: (coring.Verfer, coring.Cigar),
            c.TransReceiptQuadruples: (prefixer, seqner, saider, self.Siger),
            c.TransIdxSigGroups: (prefixer, seqner, saider, "ctr"),
            c.TransLastIdxSigGroups: (prefixer, "ctr"),
            c.FirstSeenReplayCouples: (seqner, coring.Dater),
            c.SealSourceCouples: (seqner, saider),
            c.SealSourceTriples: (prefixer, seqner, saider),
            c.ESSRPayloadGroup: (self.Matter,),
        }

    def group(self, walk, ctr, end, limit, cold):
        c = counting.CtrDex_1_0
        if ctr.code in (c.AttachmentGroup, c.BigAttachmentGroup):
            # TRANSCRIBED (parsing.py:762): pags = ctr.count * 4 if txt else ctr.count * 3
            extent = ctr.count * 4 if cold == kering.Colds.txt else ctr.count * 3
            if extent > limit - end:
                raise self.shortage(f"The {ctr.code} group counts {extent} bytes but only "
                                    f"{limit - end} remain in its frame.")
            group_end = end + extent
            pos = end
            while pos < group_end:  # keripy extracts a counter at each step inside the group
                pos = walk.counter(pos, group_end, cold)
            return group_end
        sequence = self._sequences().get(ctr.code)
        if sequence is None:
            if ctr.code in (c.SadPathSigGroups, c.RootSadPathSigGroups, c.PathedMaterialGroup,
                            c.BigPathedMaterialGroup):
                raise Unsupported(f"{E_GROUP_UNTRANSCRIBED}: keripy 1.x consumes {ctr.code} "
                                  "groups inline and this adapter does not transcribe that "
                                  "consumption, so it cannot say where the group ends.")
            raise Rejection(kering.UnexpectedCountCodeError.__name__,
                            f"keripy 1.x's parser does not accept count code {ctr.code}.")
        pos = end
        for _ in range(ctr.count):
            for klas in sequence:
                if klas == "ctr":
                    first = len(walk.items)
                    pos = walk.counter(pos, limit, cold)
                    if walk.items[first]["code"] != c.ControllerIdxSigs:
                        raise Rejection(kering.UnexpectedCountCodeError.__name__,
                                        f"keripy 1.x expects {c.ControllerIdxSigs} here.")
                else:
                    pos = walk.item(pos, limit, klas, cold)
        return pos


def load():
    """The API object for whichever keripy is installed."""
    if hasattr(parsing.Parser, "Methods") and hasattr(counting.Counter, "byteCount"):
        return Main()
    return OneX()
