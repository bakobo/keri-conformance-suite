"""Measure what keripy's own parser consumes, and turn that into the protocol's items.

The adapter hands the stream to keripy's Parser.msgParsator, one message (body plus attachments)
per call, exactly as keripy's own parse loop does. keripy's parser reports objects, not offsets,
so the stream is handed over as a `Tracked` bytearray: a bytearray that knows the stream offset of
its first byte and tells a `Recorder` whenever keripy strips bytes from its front or cuts a
substream from it. A subclass of keripy's Parser (no keripy code is modified) reports each
extraction keripy performs, and wraps the helper methods keripy hands whole groups to.

Every offset reported is therefore a measurement of keripy's consumption: where keripy's buffer
stood before and after it took something. No offset is computed from a count. README.md lists
each measurement.
"""

import inspect

from keri import kering

from kcs_adapter_keripy.errors import AdapterBug, BufferMisuse, Rejection, Unsupported, keri

E_UNMEASURABLE = "e.feature.unsupported.group-extent.f"
E_NATIVE = "e.feature.unsupported.native-body.f"
E_BUFFER_DELETE = "e.self.unknown.buffer-delete.f"
E_UNTRACKED_BUFFER = "e.self.unknown.untracked-buffer.f"
E_EXTRACTED_CLASS = "e.self.unknown.extracted-class.f"
E_MESSAGE_SIZE = "e.self.unknown.message-size.f"
E_UNCLASSIFIED_DELETION = "e.self.unknown.unclassified-deletion.f"
E_PARSE_STALLED = "e.self.unknown.parse-stalled.f"


class Tracked(bytearray):
    """A bytearray that knows the stream offset of its first byte.

    Equality is deliberately bytearray equality: keripy compares and slices these as plain bytes,
    and the offset is bookkeeping, not content. Like bytearray, it is unhashable."""

    __eq__ = bytearray.__eq__
    __ne__ = bytearray.__ne__
    __hash__ = None

    def __init__(self, data=b"", base=0, recorder=None):
        super().__init__(data)
        self.base = base
        self.recorder = recorder

    def __getitem__(self, key):
        value = super().__getitem__(key)
        if isinstance(key, slice):
            start, _stop, step = key.indices(len(self))
            if step == 1:
                value = Tracked(value, self.base + start, self.recorder)
        return value

    def __delitem__(self, key):
        if not isinstance(key, slice):
            raise BufferMisuse(f"{E_BUFFER_DELETE}: keripy deleted a single byte from its "
                             "stream, which the adapter does not expect.")
        start, stop, step = key.indices(len(self))
        if step != 1 or start != 0:
            raise BufferMisuse(f"{E_BUFFER_DELETE}: keripy deleted bytes other than from "
                             "the front of its stream, which the adapter does not expect.")
        data = bytes(super().__getitem__(slice(0, stop)))
        if self.recorder is not None:
            self.recorder.deleting(self, data)
        super().__delitem__(slice(0, stop))
        self.base += len(data)


def base_of(buf):
    if not isinstance(buf, Tracked):
        raise AdapterBug(f"{E_UNTRACKED_BUFFER}: keripy extracted from a buffer the "
                         "adapter did not give it, so its offset is unknown.")
    return buf.base


class Recorder:
    """Builds the item list from keripy's consumption events."""

    def __init__(self, keripy):
        self.keripy = keripy
        self.items = []
        self.depth = 0  # >0 while keripy is inside one of its extractions
        self.scope = 0  # nesting of group helper methods
        self.peeks = {}  # (id(buf), offset) -> (buf, instance) that keripy looked at, unstripped
        self.pending = {}  # id(buf) -> (buf, counter item) awaiting a group body cut
        self.open = []  # [item, buf, scope]: groups whose end keripy has not yet shown
        self.by_ctr = {}  # id(Counter instance) -> counter item
        self.messages = 0
        self.raised_in_extraction = False

    # -- events

    def extracted(self, instance, buf, start, end, strip):
        if not strip:
            self.peeks[(id(buf), start)] = (buf, instance)
            return
        self.pending.pop(id(buf), None)
        if isinstance(instance, self.keripy.Counter):
            self.counter(instance, buf, start, end)
        elif isinstance(instance, self.keripy.Indexer):
            item = {"kind": "indexed", "start": start, "end": end, "code": instance.code,
                    "raw": bytes(instance.raw).hex(), "index": instance.index}
            ondex = self.keripy.ondex_field(instance)
            if ondex is not None:
                item["ondex"] = ondex
            self.items.append(item)
        elif isinstance(instance, self.keripy.Matter):
            self.items.append({"kind": "primitive", "start": start, "end": end,
                               "code": instance.code, "raw": bytes(instance.raw).hex()})
        else:
            raise AdapterBug(f"{E_EXTRACTED_CLASS}: keripy extracted a "
                             f"{type(instance).__name__}, which the adapter cannot report.")

    def deleting(self, buf, data):
        """keripy is stripping `data` from the front of buf outside any extraction."""
        if self.depth:
            return
        start, n = buf.base, len(data)
        peek = self.peeks.pop((id(buf), start), None)
        if peek is not None and peek[0] is buf and isinstance(peek[1], self.keripy.Counter):
            ctr = peek[1]
            cold = self.keripy.sniff(bytearray(data))
            if n != keri(ctr.byteSize, cold):
                raise Unsupported(f"{E_NATIVE}: keripy consumed the count code at {start} "
                                  "together with its contents, as it does for a native CESR "
                                  "body; this adapter does not report native bodies.")
            self.counter(ctr, buf, start, start + n)
            return
        pending = self.pending.pop(id(buf), None)
        if pending is not None and pending[0] is buf:
            self.close(pending[1], start + n)
            return
        if n == 0:
            return
        if self.keripy.sniff(bytearray(data)) == kering.Colds.msg:
            proto, pvrsn, kind, size = self.keripy.smell(bytearray(data))
            if size != n:
                raise AdapterBug(f"{E_MESSAGE_SIZE}: keripy consumed a body of a "
                                 "different size than its version string declares.")
            self.items.append({"kind": "message", "start": start, "end": start + n,
                               "proto": proto, "version": f"{pvrsn.major}.{pvrsn.minor}",
                               "serialization": kind, "size": n})
            self.messages += 1
            return
        raise AdapterBug(f"{E_UNCLASSIFIED_DELETION}: keripy stripped {n} bytes at "
                         f"{start} that were neither a count code, a group body nor a message.")

    def counter(self, ctr, buf, start, end):
        """keripy consumed the count code ctr from buf at [start, end)."""
        self.close_open(lambda e: e[1] is buf and e[2] == self.scope, start)
        if ctr.code == self.keripy.GENUS_CODE:
            genus, version = self.keripy.genus_version(ctr)
            self.items.append({"kind": "genus", "start": start, "end": end,
                               "code": keri(lambda: ctr.qb64), "genus": genus,
                               "version": version})
            return
        if ctr.code in self.keripy.UNMEASURABLE:
            raise Unsupported(f"{E_UNMEASURABLE}: keripy {self.keripy.generation} consumes "
                              f"{ctr.code} groups inline together with a nested count code, so "
                              "nothing it does marks where the group ends.")
        item = {"kind": "counter", "start": start, "end": end, "code": ctr.code,
                "size": ctr.count, "group_end": None}
        self.items.append(item)
        self.by_ctr[id(ctr)] = item
        self.pending[id(buf)] = (buf, item)
        self.open.append([item, buf, self.scope])

    def group_method_done(self, ctr, ims):
        """A keripy helper that was handed ctr's whole group returned; ims is where it stopped."""
        self.close_open(lambda e: e[2] > self.scope, None)
        self.close(self.by_ctr[id(ctr)], base_of(ims))

    # -- bookkeeping

    def close(self, item, end):
        item["group_end"] = end
        self.open = [e for e in self.open if e[0] is not item]

    def close_open(self, which, end):
        for entry in [e for e in self.open if which(e)]:
            self.close(entry[0], entry[1].base if end is None else end)

    def begin_round(self):
        self.messages = 0
        self.raised_in_extraction = False
        self.peeks.clear()
        self.pending.clear()

    def end_round(self):
        self.close_open(lambda e: True, None)

    def post_extraction(self, exc, root):
        """True when keripy raised only after it had consumed a whole message and its
        attachments: keripy 1.x dispatches the message to its KERI processors inside
        msgParsator, and with none attached that dispatch fails. Such an error is about KERI
        processing, not framing."""
        return (self.messages > 0 and not self.raised_in_extraction
                and not isinstance(exc, kering.ExtractionError)
                and (not root or self.keripy.sniff(bytearray(root)) == kering.Colds.msg))


def instrumented_parser(keripy, recorder):
    """A fresh subclass instance of keripy's Parser that reports to recorder."""
    base = keripy.Parser

    class Instrumented(base):
        def _extractor(self, ims, klas, *args, **kwargs):
            strip = kwargs.get("strip", True)
            start = base_of(ims)
            recorder.depth += 1
            try:
                instance = yield from super()._extractor(ims, klas, *args, **kwargs)
            except BaseException as exc:
                if not isinstance(exc, GeneratorExit):
                    recorder.raised_in_extraction = True
                raise
            finally:
                recorder.depth -= 1
            recorder.extracted(instance, ims, start, base_of(ims), strip)
            return instance

        def extract(self, ims, klas, *args, **kwargs):
            start = base_of(ims)
            recorder.depth += 1
            try:
                instance = super().extract(ims, klas, *args, **kwargs)
            except BaseException:
                recorder.raised_in_extraction = True
                raise
            finally:
                recorder.depth -= 1
            recorder.extracted(instance, ims, start, base_of(ims), True)
            return instance

    for name in keripy.GROUP_METHODS:
        setattr(Instrumented, name, _wrap(base, name, recorder))
    return Instrumented()


def _wrap(base, name, recorder):
    original = getattr(base, name)
    signature = inspect.signature(original)

    def wrapper(self, *args, **kwargs):
        bound = signature.bind(self, *args, **kwargs)
        ctr, ims = bound.arguments["ctr"], bound.arguments["ims"]
        recorder.scope += 1
        try:
            result = yield from original(self, *args, **kwargs)
        finally:
            recorder.scope -= 1
        recorder.group_method_done(ctr, ims)
        return result

    wrapper.__name__ = name
    return wrapper


def parse(keripy, stream):
    """Items for stream, as measured from keripy's parser, or a Rejection."""
    recorder = Recorder(keripy)
    parser = instrumented_parser(keripy, recorder)
    root = Tracked(stream, 0, recorder)
    while root:
        recorder.begin_round()
        before = root.base
        generator = keripy.run(parser, root)
        try:
            try:
                next(generator)
            except StopIteration:
                pass
            else:
                generator.close()
                raise Rejection(kering.ShortageError.__name__,
                                "keripy's parser asked for more bytes, but the stream is "
                                "complete: it ends inside a frame.")
        except (AdapterBug, Unsupported, Rejection):
            raise
        except Exception as exc:
            if not recorder.post_extraction(exc, root):
                raise Rejection(type(exc).__name__, str(exc)) from exc
        recorder.end_round()
        if root.base == before:
            raise AdapterBug(f"{E_PARSE_STALLED}: keripy's parser returned without "
                             "consuming anything.")
    return sorted(recorder.items, key=lambda item: item["start"])
