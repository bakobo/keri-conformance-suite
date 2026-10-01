"""cesr.parse: offsets and fields of every item, and rejections, for both keripy generations.

Streams are built here with keripy's own classes (so the bytes are whatever keripy emits); what
these tests check is the adapter's bookkeeping: that it reports each item where it is, with the
fields the protocol asks for, and that keripy's refusals come back as rejections.
"""

import base64
import inspect
import json

import pytest
from keri.core.coring import Matter
from keri.core.counting import Counter
from keri.core.indexing import Indexer
from keri.kering import Versionage

from kcs_adapter_keripy import cesr

V1 = Versionage(major=1, minor=0)
V2 = Versionage(major=2, minor=0)
_VKW = "version" if "version" in inspect.signature(Counter.__init__).parameters else "gvrsn"

KEY = bytes(range(32))
DIG = bytes(range(100, 132))
SIG = bytes(range(64))
SIG2 = bytes(range(1, 65))
SIG448 = bytes(range(114))


def ctr(code, count, version):
    return bytes(Counter(code=code, count=count, **{_VKW: version}).qb64b)


def ctr2(code, count, version):
    return bytes(Counter(code=code, count=count, **{_VKW: version}).qb2)


def mat(code, raw):
    return bytes(Matter(raw=raw, code=code).qb64b)


def mat2(code, raw):
    return bytes(Matter(raw=raw, code=code).qb2)


def idx(code, raw, index, ondex=None):
    return bytes(Indexer(raw=raw, code=code, index=index, ondex=ondex).qb64b)


def gvc(text):
    return b"-_AAA" + text


def parse(stream):
    return cesr.parse(stream)


def counter(start, end, code, size, group_end, **extra):
    return {"kind": "counter", "start": start, "end": end, "code": code, "size": size,
            "group_end": group_end, **extra}


def prim(start, end, code, raw):
    return {"kind": "primitive", "start": start, "end": end, "code": code, "raw": raw.hex()}


def indexed(start, end, code, raw, index, ondex=None):
    item = {"kind": "indexed", "start": start, "end": end, "code": code, "raw": raw.hex(),
            "index": index}
    if ondex is not None:
        item["ondex"] = ondex
    return item


def v1_body():
    sad = {"v": "KERI10JSON000000_", "t": "rpy", "d": "", "r": "/x"}
    raw = json.dumps(sad, separators=(",", ":")).encode()
    return raw.replace(b"000000", f"{len(raw):06x}".encode())


def v2_body():
    sad = {"v": "KERICAACAAJSONAAAA.", "t": "rpy", "d": "", "r": "/x"}
    raw = json.dumps(sad, separators=(",", ":")).encode()
    size = base64.urlsafe_b64encode(len(raw).to_bytes(3, "big")).decode()  # 4 Base64 digits
    return raw.replace(b"AAAA.", size.encode() + b".")


def rejected(result):
    assert set(result) == {"reject"}, result
    return result["reject"]["class"]


# --- both generations ---------------------------------------------------------------------------

def test_empty_stream_has_no_items():
    assert parse(b"") == {"items": []}


def test_a_json_body_with_a_legacy_version_string_is_framed_by_smell():
    raw = v1_body()
    tail = v1_body()
    result = parse(raw + tail)
    assert result == {"items": [
        {"kind": "message", "start": 0, "end": len(raw), "proto": "KERI", "version": "1.0",
         "serialization": "JSON", "size": len(raw)},
        {"kind": "message", "start": len(raw), "end": 2 * len(raw), "proto": "KERI",
         "version": "1.0", "serialization": "JSON", "size": len(raw)},
    ]}


def test_a_body_shorter_than_its_version_string_declares_is_rejected():
    assert rejected(parse(v1_body()[:-3])) == "ShortageError"


def test_a_stream_too_short_to_smell_is_rejected():
    assert rejected(parse(b'{"v":"KERI1')) == "ShortageError"


def test_a_body_without_a_version_string_is_rejected():
    assert rejected(parse(b'{"x":"' + b"a" * 40 + b'"}')) == "VersionError"


def test_a_cold_start_on_annotated_text_is_rejected():
    assert rejected(parse(b"\x10\x13\xfb")) == "ColdStartError"


def test_a_truncated_count_code_is_rejected():
    assert rejected(parse(b"-K")) == "ShortageError"


def test_an_unknown_count_code_is_rejected():
    assert rejected(parse(b"-0ALAAAA")) in ("UnexpectedCodeError", "UnsupportedCodeError")


def test_a_genus_version_counter_frames_nothing_and_reports_its_version():
    result = parse(gvc(b"CAA"))
    assert result == {"items": [counter(0, 8, "-_AAA", 0, 8, genus="AAA", gvrsn="2.00")]}


# --- keripy main --------------------------------------------------------------------------------

@pytest.mark.main
def test_main_generic_list_of_one_key():
    key = mat("D", KEY)
    stream = gvc(b"CAA") + ctr("-J", 11, V2) + key
    assert parse(stream) == {"items": [
        counter(0, 8, "-_AAA", 0, 8, genus="AAA", gvrsn="2.00"),
        counter(8, 12, "-J", 11, 56),
        prim(12, 56, "D", KEY),
    ]}


@pytest.mark.main
def test_main_default_table_is_2_00_without_a_genus_counter():
    stream = ctr("-J", 11, V2) + mat("D", KEY)
    assert parse(stream) == {"items": [counter(0, 4, "-J", 11, 48), prim(4, 48, "D", KEY)]}


@pytest.mark.main
def test_main_controller_signatures_are_indexed_with_only_their_defined_index_fields():
    a = idx("A", SIG, 3)          # both same: index only
    b = idx("B", SIG2, 5)         # current only: index only
    big = idx("2A", SIG, 65, 70)  # big dual: index and ondex
    crt = idx("2B", SIG2, 70)  # big current only: the table defines an ondex field (0)
    stream = ctr("-K", (len(a) + len(b) + len(big) + len(crt)) // 4, V2) + a + b + big + crt
    p = 4
    expected = [counter(0, 4, "-K", (len(stream) - 4) // 4, len(stream))]
    for raw, code, index, ondex, item in ((SIG, "A", 3, None, a), (SIG2, "B", 5, None, b),
                                          (SIG, "2A", 65, 70, big), (SIG2, "2B", 70, 0, crt)):
        expected.append(indexed(p, p + len(item), code, raw, index, ondex))
        p += len(item)
    assert parse(stream) == {"items": expected}


@pytest.mark.main
def test_main_current_only_code_with_nonzero_ondex_is_keripys_rejection():
    # keripy requires a zero ondex on current-only codes; the CESR table does not (CESR-0022).
    sig = bytearray(idx("2B", SIG2, 70))
    sig[4:6] = b"AJ"  # ondex field := 9
    stream = ctr("-K", len(sig) // 4, V2) + bytes(sig)
    assert rejected(parse(stream)) == "ValueError"


@pytest.mark.main
def test_main_nested_groups_and_offsets():
    inner = ctr("-J", 33, V2) + mat("E", DIG) + mat("0B", SIG)
    stream = ctr("-J", (44 + len(inner) + 4) // 4, V2) + mat("D", KEY) + inner + mat("M", b"\x01\x02")
    assert parse(stream) == {"items": [
        counter(0, 4, "-J", 46, 188),
        prim(4, 48, "D", KEY),
        counter(48, 52, "-J", 33, 184),
        prim(52, 96, "E", DIG),
        prim(96, 184, "0B", SIG),
        prim(184, 188, "M", b"\x01\x02"),
    ]}


@pytest.mark.main
def test_main_binary_domain_counts_triplets():
    stream = ctr2("-J", 11 + 22, V2) + mat2("D", KEY) + mat2("0B", SIG)
    assert parse(stream) == {"items": [
        counter(0, 3, "-J", 33, 3 + 33 + 66),
        prim(3, 36, "D", KEY),
        prim(36, 102, "0B", SIG),
    ]}


@pytest.mark.main
def test_main_binary_controller_signatures_and_domain_switches():
    sigs = Indexer(raw=SIG, code="A", index=0).qb2 + Indexer(raw=SIG2, code="A", index=1).qb2
    text = ctr("-J", 11, V2) + mat("D", KEY)
    stream = text + ctr2("-K", len(sigs) // 3, V2) + bytes(sigs) + text
    n = len(text)
    assert parse(stream) == {"items": [
        counter(0, 4, "-J", 11, 48), prim(4, 48, "D", KEY),
        counter(n, n + 3, "-K", 44, n + 135),
        indexed(n + 3, n + 69, "A", SIG, 0), indexed(n + 69, n + 135, "A", SIG2, 1),
        counter(n + 135, n + 139, "-J", 11, n + 183), prim(n + 139, n + 183, "D", KEY),
    ]}


@pytest.mark.main
def test_main_attachment_group_holding_signatures_and_receipt_couples():
    sigs = ctr("-K", 22, V2) + idx("A", SIG, 0)
    couples = ctr("-M", 33, V2) + mat("B", KEY) + mat("0B", SIG)
    stream = ctr("-C", (len(sigs) + len(couples)) // 4, V2) + sigs + couples
    s = 4 + len(sigs)
    assert parse(stream) == {"items": [
        counter(0, 4, "-C", 57, 232),
        counter(4, 8, "-K", 22, 96), indexed(8, 96, "A", SIG, 0),
        counter(s, s + 4, "-M", 33, 232), prim(s + 4, s + 48, "B", KEY),
        prim(s + 48, 232, "0B", SIG),
    ]}


@pytest.mark.main
def test_main_message_then_attachments():
    raw = v2_body()
    att = ctr("-C", 23, V2) + ctr("-K", 22, V2) + idx("A", SIG, 0)
    stream = gvc(b"CAA") + raw + att
    m = 8 + len(raw)
    assert parse(stream) == {"items": [
        counter(0, 8, "-_AAA", 0, 8, genus="AAA", gvrsn="2.00"),
        {"kind": "message", "start": 8, "end": m, "proto": "KERI", "version": "2.0",
         "serialization": "JSON", "size": len(raw)},
        counter(m, m + 4, "-C", 23, m + 96), counter(m + 4, m + 8, "-K", 22, m + 96),
        indexed(m + 8, m + 96, "A", SIG, 0),
    ]}


@pytest.mark.main
def test_main_a_genus_counter_switches_to_the_1_00_table_where_minus_a_counts_signatures():
    sigs = idx("A", SIG, 0) + idx("A", SIG2, 1)
    stream = gvc(b"BAA") + ctr("-A", 2, V1) + sigs
    assert parse(stream) == {"items": [
        counter(0, 8, "-_AAA", 0, 8, genus="AAA", gvrsn="1.00"),
        counter(8, 12, "-A", 2, 188),
        indexed(12, 100, "A", SIG, 0), indexed(100, 188, "A", SIG2, 1),
    ]}


@pytest.mark.main
def test_main_1_00_quadlet_counted_group_uses_byte_count():
    inner = ctr("-A", 1, V1) + idx("A", SIG, 0)
    stream = gvc(b"BAA") + ctr("-V", len(inner) // 4, V1) + inner
    assert parse(stream) == {"items": [
        counter(0, 8, "-_AAA", 0, 8, genus="AAA", gvrsn="1.00"),
        counter(8, 12, "-V", 23, 104), counter(12, 16, "-A", 1, 104),
        indexed(16, 104, "A", SIG, 0),
    ]}


@pytest.mark.main
def test_main_1_00_code_keripy_cannot_frame_is_rejected():
    # -_AAA under 1.00 with a nonzero code that is item counted and has no parser method does not
    # exist in keripy main; a 1.00 code keripy main does not know is an unexpected code.
    stream = gvc(b"BAA") + b"-DAB"
    assert rejected(parse(stream)) in ("UnexpectedCodeError", "UnexpectedCountCodeError")


@pytest.mark.main
def test_main_unsupported_genus_version_is_rejected():
    assert rejected(parse(gvc(b"ZAA") + ctr("-J", 0, V2))) == "InvalidVersionError"


@pytest.mark.main
def test_main_a_genus_counter_inside_a_group_does_not_leak_its_version_out():
    inner = gvc(b"BAA") + ctr("-A", 1, V1) + idx("A", SIG, 0)
    stream = ctr("-J", len(inner) // 4, V2) + inner + ctr("-J", 11, V2) + mat("D", KEY)
    n = 4 + len(inner)
    assert parse(stream)["items"][-2:] == [counter(n, n + 4, "-J", 11, n + 48),
                                           prim(n + 4, n + 48, "D", KEY)]


@pytest.mark.main
def test_main_empty_group():
    stream = ctr("-J", 0, V2) + ctr("-J", 11, V2) + mat("D", KEY)
    assert parse(stream) == {"items": [counter(0, 4, "-J", 0, 4), counter(4, 8, "-J", 11, 52),
                                       prim(8, 52, "D", KEY)]}


@pytest.mark.main
def test_main_big_count_code():
    stream = ctr("--J", 11, V2) + mat("D", KEY)
    assert parse(stream) == {"items": [counter(0, 8, "--J", 11, 52), prim(8, 52, "D", KEY)]}


@pytest.mark.main
@pytest.mark.parametrize("stream,expected", [
    # a group whose count runs past the end of the stream
    (ctr("-J", 22, V2) + mat("D", KEY), "ShortageError"),
    # a signature group whose count runs past the end of the stream (keripy's own method)
    (ctr("-K", 44, V2) + idx("A", SIG, 0), "ShortageError"),
    # a group that ends inside the primitive it holds
    (ctr("-J", 10, V2) + mat("D", KEY), "ShortageError"),
    # a stream that ends inside a primitive
    (ctr("-J", 11, V2) + mat("D", KEY)[:-2], "ShortageError"),
    # nonzero pad bits in a primitive
    (ctr("-J", 11, V2) + b"Du" + mat("D", KEY)[2:], "ConversionError"),
    # bytes left over after a group, at the top level, that are not a frame
    (ctr("-J", 0, V2) + mat("D", KEY), "UnexpectedCodeError"),
])
def test_main_rejections(stream, expected):
    assert rejected(parse(stream)) == expected


# --- keripy 1.x ---------------------------------------------------------------------------------

@pytest.mark.onex
def test_onex_default_table_is_1_00_and_minus_a_counts_signatures():
    sigs = idx("A", SIG, 0) + idx("A", SIG2, 1)
    stream = ctr("-A", 2, V1) + sigs
    assert parse(stream) == {"items": [
        counter(0, 4, "-A", 2, 180),
        indexed(4, 92, "A", SIG, 0), indexed(92, 180, "A", SIG2, 1),
    ]}


@pytest.mark.onex
def test_onex_witness_signatures_in_binary():
    sigs = Indexer(raw=SIG, code="A", index=0).qb2
    stream = ctr2("-B", 1, V1) + bytes(sigs)
    assert parse(stream) == {"items": [counter(0, 3, "-B", 1, 69),
                                       indexed(3, 69, "A", SIG, 0)]}


@pytest.mark.onex
def test_onex_receipt_couples_count_couples():
    stream = ctr("-C", 1, V1) + mat("B", KEY) + mat("0B", SIG)
    assert parse(stream) == {"items": [counter(0, 4, "-C", 1, 136), prim(4, 48, "B", KEY),
                                       prim(48, 136, "0B", SIG)]}


@pytest.mark.onex
def test_onex_attachment_group_counts_quadlets_around_an_item_counted_group():
    inner = ctr("-A", 1, V1) + idx("A", SIG, 0)
    stream = ctr("-V", len(inner) // 4, V1) + inner
    assert parse(stream) == {"items": [counter(0, 4, "-V", 23, 96), counter(4, 8, "-A", 1, 96),
                                       indexed(8, 96, "A", SIG, 0)]}


@pytest.mark.onex
def test_onex_message_then_signatures():
    raw = v1_body()
    stream = raw + ctr("-A", 1, V1) + idx("A", SIG, 0)
    n = len(raw)
    assert parse(stream) == {"items": [
        {"kind": "message", "start": 0, "end": n, "proto": "KERI", "version": "1.0",
         "serialization": "JSON", "size": n},
        counter(n, n + 4, "-A", 1, n + 92), indexed(n + 4, n + 92, "A", SIG, 0),
    ]}


@pytest.mark.onex
def test_onex_genus_counter_does_not_switch_the_table():
    stream = gvc(b"CAA") + ctr("-A", 1, V1) + idx("A", SIG, 0)
    assert parse(stream) == {"items": [
        counter(0, 8, "-_AAA", 0, 8, genus="AAA", gvrsn="2.00"),
        counter(8, 12, "-A", 1, 100), indexed(12, 100, "A", SIG, 0),
    ]}


@pytest.mark.onex
def test_onex_composite_groups_follow_keripys_parser():
    from keri.core.coring import Dater, Prefixer, Saider, Seqner
    pre = bytes(Prefixer(raw=KEY, code="D").qb64b)
    snu = bytes(Seqner(sn=5).qb64b)
    dig = bytes(Saider(raw=DIG, code="E").qb64b)
    dts = bytes(Dater(dts="2026-01-01T00:00:00.000000+00:00").qb64b)
    sig = idx("A", SIG, 0)
    cases = [
        ("-D", [pre, snu, dig, sig]),  # TransReceiptQuadruples
        ("-E", [snu, dts]),  # FirstSeenReplayCouples
        ("-G", [snu, dig]),  # SealSourceCouples
        ("-I", [pre, snu, dig]),  # SealSourceTriples
        ("-F", [pre, snu, dig, ctr("-A", 1, V1), sig]),  # TransIdxSigGroups
        ("-H", [pre, ctr("-A", 1, V1), sig]),  # TransLastIdxSigGroups
        ("-Z", [mat("4B", b"123456789")]),  # ESSRPayloadGroup
    ]
    for code, parts in cases:
        stream = ctr(code, 1, V1) + b"".join(parts)
        items = parse(stream)["items"]
        assert items[0] == counter(0, 4, code, 1, len(stream)), code
        assert [i["end"] - i["start"] for i in items[1:]] == [len(p) for p in parts], code
        kinds = [i["kind"] for i in items[1:]]
        assert kinds == ["counter" if p.startswith(b"-") else
                         "indexed" if p == sig else "primitive" for p in parts], code


@pytest.mark.onex
def test_onex_trans_groups_require_a_controller_signature_counter():
    from keri.core.coring import Prefixer
    pre = bytes(Prefixer(raw=KEY, code="D").qb64b)
    stream = ctr("-H", 1, V1) + pre + ctr("-B", 1, V1) + idx("A", SIG, 0)
    assert rejected(parse(stream)) == "UnexpectedCountCodeError"


@pytest.mark.onex
@pytest.mark.parametrize("code", ["-J", "-K", "-L", "-0L"])
def test_onex_groups_the_adapter_does_not_transcribe_are_unsupported(code):
    with pytest.raises(cesr.Unsupported) as info:
        parse(ctr(code, 1, V1) + b"AAAA")
    assert "e.parse.group.untranscribed.p" in str(info.value)


@pytest.mark.onex
@pytest.mark.parametrize("stream,expected", [
    (ctr("-A", 2, V1) + idx("A", SIG, 0), "ShortageError"),
    (ctr("-V", 30, V1) + ctr("-A", 1, V1) + idx("A", SIG, 0), "ShortageError"),
    (ctr("-V", 1, V1) + mat("D", KEY)[:4], "UnexpectedCodeError"),
])
def test_onex_rejections(stream, expected):
    assert rejected(parse(stream)) == expected
