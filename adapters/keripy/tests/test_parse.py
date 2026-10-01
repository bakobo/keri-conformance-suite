"""cesr.parse through keripy's own Parser.msgParsator: offsets, group ends and rejections.

Streams are built with keripy's own classes: KERI inception events from eventing.incept, signed
by fixed seeds, with attachment groups made by keripy's Counter. What these tests check is that
the adapter reports, for each thing keripy's parser consumed, where it was and what it was.
"""

import inspect

import pytest
from keri import kering
from keri.core import eventing, signing
from keri.core.coring import Matter
from keri.core.counting import Counter
from keri.core.indexing import Indexer

from kcs_adapter_keripy import cesr

V1 = kering.Vrsn_1_0
V2 = kering.Vrsn_2_0
_VKW = "version" if "version" in inspect.signature(Counter.__init__).parameters else "gvrsn"
SIGNERS = [signing.Signer(raw=bytes([i]) * 32, transferable=True) for i in range(1, 4)]
WITNESS = signing.Signer(raw=bytes([9]) * 32, transferable=False)


def ctr(code, count, version, binary=False):
    counter = Counter(code=code, count=count, **{_VKW: version})
    return bytes(counter.qb2 if binary else counter.qb64b)


def event(pvrsn, nkeys=1):
    keys = [s.verfer.qb64 for s in SIGNERS[:nkeys]]
    if "pvrsn" in inspect.signature(eventing.incept).parameters:
        serder = eventing.incept(keys=keys, isith=str(nkeys), pvrsn=pvrsn, kind=kering.Kinds.json)
    else:
        serder = eventing.incept(keys=keys, isith=str(nkeys), version=pvrsn)
    return serder


def sigs(serder, n, binary=False):
    out = b""
    for i in range(n):
        siger = SIGNERS[i].sign(serder.raw, index=i)
        out += bytes(siger.qb2 if binary else siger.qb64b)
    return out


def genus(text=b"CAA"):
    return b"-_AAA" + text


def g_item(start, version="2.00", code="-_AAACAA", width=8):
    return {"kind": "genus", "start": start, "end": start + width, "code": code, "genus": "AAA",
            "version": version}


def m_item(start, serder, version):
    return {"kind": "message", "start": start, "end": start + serder.size, "proto": "KERI",
            "version": version, "serialization": "JSON", "size": serder.size}


def c_item(start, code, size, group_end, width=4):
    return {"kind": "counter", "start": start, "end": start + width, "code": code, "size": size,
            "group_end": group_end}


def i_items(start, serder, n, width=88):
    items = []
    for i in range(n):
        siger = SIGNERS[i].sign(serder.raw, index=i)
        items.append({"kind": "indexed", "start": start, "end": start + width, "code": "A",
                      "raw": bytes(siger.raw).hex(), "index": i})
        start += width
    return items


def rejected(result):
    assert set(result) == {"reject"}, result
    return result["reject"]["class"]


# --- both generations ---------------------------------------------------------------------------

def test_empty_stream_has_no_items():
    assert cesr.parse(b"") == {"items": []}


def test_a_body_shorter_than_its_version_string_declares_is_a_shortage():
    serder = event(V1)
    assert rejected(cesr.parse(serder.raw[:-5])) == "ShortageError"


def test_a_stream_that_ends_inside_a_signature_is_rejected():
    serder = event(V1)
    stream = serder.raw + ctr("-A", 1, V1) + sigs(serder, 1)[:-3]
    if cesr.api().generation == "main":
        stream = genus() + event(V2).raw + ctr("-C", 23, V2) + ctr("-K", 22, V2) + sigs(
            event(V2), 1)[:-3]
    # keripy main reports a failure inside an enclosed attachments group as SizedGroupError.
    expected = "SizedGroupError" if cesr.api().generation == "main" else "ShortageError"
    assert rejected(cesr.parse(stream)) == expected


# --- keripy main --------------------------------------------------------------------------------

def main_frame(serder, n=1, binary=False):
    width = 3 if binary else 4
    k = ctr("-K", n * (66 if binary else 88) // width, V2, binary)
    return ctr("-C", (len(k) + len(sigs(serder, n, binary))) // width, V2, binary) + k + sigs(
        serder, n, binary)


@pytest.mark.main
def test_main_genus_message_and_controller_signatures():
    serder = event(V2, 2)
    stream = genus() + serder.raw + main_frame(serder, 2)
    m = 8 + serder.size
    assert cesr.parse(stream) == {"items": [
        g_item(0), m_item(8, serder, "2.0"),
        c_item(m, "-C", 45, m + 184), c_item(m + 4, "-K", 44, m + 184),
        *i_items(m + 8, serder, 2),
    ]}


@pytest.mark.main
def test_main_legacy_body_under_a_2_00_genus_and_consecutive_messages():
    first, second = event(V1), event(V2)
    stream = genus() + first.raw + main_frame(first) + second.raw + main_frame(second)
    a = 8 + first.size
    b = a + 96
    assert cesr.parse(stream) == {"items": [
        g_item(0), m_item(8, first, "1.0"),
        c_item(a, "-C", 23, a + 96), c_item(a + 4, "-K", 22, a + 96), *i_items(a + 8, first, 1),
        m_item(b, second, "2.0"),
        c_item(b + second.size, "-C", 23, b + second.size + 96),
        c_item(b + second.size + 4, "-K", 22, b + second.size + 96),
        *i_items(b + second.size + 8, second, 1),
    ]}


@pytest.mark.main
def test_main_binary_attachments_count_triplets():
    serder = event(V2, 2)
    stream = bytes(Counter(code="-_AAA", countB64="CAA").qb2) + serder.raw + main_frame(
        serder, 2, binary=True)
    m = 6 + serder.size
    assert cesr.parse(stream) == {"items": [
        g_item(0, width=6), m_item(6, serder, "2.0"),
        c_item(m, "-C", 45, m + 138, width=3), c_item(m + 3, "-K", 44, m + 138, width=3),
        *i_items(m + 6, serder, 2, width=66),
    ]}


@pytest.mark.main
def test_main_witness_signatures_and_receipt_couples_after_controller_signatures():
    serder = event(V2)
    k = ctr("-K", 22, V2) + sigs(serder, 1)
    wig = bytes(WITNESS.sign(serder.raw, index=0).qb64b)
    w = ctr("-L", 22, V2) + wig
    cig = WITNESS.sign(serder.raw)
    m_ = ctr("-M", 33, V2) + bytes(WITNESS.verfer.qb64b) + bytes(cig.qb64b)
    stream = genus() + serder.raw + ctr("-C", (len(k) + len(w) + len(m_)) // 4, V2) + k + w + m_
    p = 8 + serder.size
    items = [{k: v for k, v in i.items() if k != "raw"} for i in cesr.parse(stream)["items"]]
    assert items[2:] == [
        c_item(p, "-C", 80, p + 324),
        c_item(p + 4, "-K", 22, p + 96),
        {"kind": "indexed", "start": p + 8, "end": p + 96, "code": "A", "index": 0},
        c_item(p + 96, "-L", 22, p + 188),
        {"kind": "indexed", "start": p + 100, "end": p + 188, "code": "A", "index": 0},
        c_item(p + 188, "-M", 33, p + 324),
        {"kind": "primitive", "start": p + 192, "end": p + 236, "code": "B"},
        {"kind": "primitive", "start": p + 236, "end": p + 324, "code": "0B"},
    ]


@pytest.mark.main
def test_main_a_1_00_genus_override_inside_an_attachments_group():
    serder = event(V2)
    inner = genus(b"BAA") + ctr("-A", 1, V1) + sigs(serder, 1)
    stream = genus() + serder.raw + ctr("-C", len(inner) // 4, V2) + inner
    m = 8 + serder.size
    assert cesr.parse(stream) == {"items": [
        g_item(0), m_item(8, serder, "2.0"),
        c_item(m, "-C", 25, m + 104), g_item(m + 4, "1.00", "-_AAABAA"),
        c_item(m + 12, "-A", 1, m + 104), *i_items(m + 16, serder, 1),
    ]}


@pytest.mark.main
def test_main_big_attachments_code():
    serder = event(V2)
    k = ctr("-K", 22, V2) + sigs(serder, 1)
    stream = genus() + serder.raw + ctr("--C", len(k) // 4, V2) + k
    m = 8 + serder.size
    assert cesr.parse(stream)["items"][2:4] == [c_item(m, "--C", 23, m + 100, width=8),
                                                c_item(m + 8, "-K", 22, m + 100)]


@pytest.mark.main
@pytest.mark.parametrize("tail,expected", [
    # an attachments group whose size ends it inside a signature
    (lambda s: ctr("-C", 20, V2) + ctr("-K", 22, V2) + sigs(s, 1), "SizedGroupError"),
    # an empty attachments group: keripy main peeks for a counter in it and finds nothing
    (lambda s: ctr("-C", 0, V2), "SizedGroupError"),
    # the stream resumes with a bare primitive after the attachments
    (lambda s: ctr("-C", 23, V2) + ctr("-K", 22, V2) + sigs(s, 1)
     + bytes(Matter(raw=bytes(32), code="D").qb64b), "UnexpectedCodeError"),
])
def test_main_rejections(tail, expected):
    serder = event(V2)
    assert rejected(cesr.parse(genus() + serder.raw + tail(serder))) == expected


@pytest.mark.main
def test_main_indexed_signatures_report_exactly_the_index_fields_their_row_defines():
    serder = event(V2)
    big = bytes(Indexer(raw=bytes(64), code="2A", index=65, ondex=70).qb64b)  # dual
    crt = bytes(Indexer(raw=bytes(range(64)), code="2B", index=70).qb64b)  # current only
    b = bytes(Indexer(raw=bytes(64), code="B", index=5).qb64b)  # current only, no ondex field
    body = big + crt + b
    stream = (genus() + serder.raw + ctr("-C", len(body) // 4 + 1, V2)
              + ctr("-K", len(body) // 4, V2) + body)
    m = 8 + serder.size + 8
    items = cesr.parse(stream)["items"][4:]
    assert [{k: v for k, v in i.items() if k != "raw"} for i in items] == [
        {"kind": "indexed", "start": m, "end": m + 92, "code": "2A", "index": 65, "ondex": 70},
        {"kind": "indexed", "start": m + 92, "end": m + 184, "code": "2B", "index": 70,
         "ondex": 0},
        {"kind": "indexed", "start": m + 184, "end": m + 272, "code": "B", "index": 5},
    ]


@pytest.mark.main
def test_main_current_only_code_with_nonzero_ondex_is_keripys_rejection():
    serder = event(V2)
    sig = bytearray(Indexer(raw=bytes(64), code="2B", index=70).qb64b)
    sig[4:6] = b"AJ"
    stream = genus() + serder.raw + ctr("-C", 24, V2) + ctr("-K", 23, V2) + bytes(sig)
    assert rejected(cesr.parse(stream)) == "ValueError"


@pytest.mark.main
def test_main_refuses_a_genus_less_1_x_stream():
    serder = event(V1)
    assert "reject" in cesr.parse(serder.raw + ctr("-A", 1, V1) + sigs(serder, 1))


# --- keripy 1.x ---------------------------------------------------------------------------------

@pytest.mark.onex
def test_onex_controller_signatures_count_signatures():
    serder = event(V1, 2)
    stream = serder.raw + ctr("-A", 2, V1) + sigs(serder, 2)
    n = serder.size
    assert cesr.parse(stream) == {"items": [
        m_item(0, serder, "1.0"), c_item(n, "-A", 2, n + 180), *i_items(n + 4, serder, 2),
    ]}


@pytest.mark.onex
def test_onex_receipt_couples_after_signatures_and_a_second_message():
    serder = event(V1)
    cig = WITNESS.sign(serder.raw)
    couples = ctr("-C", 1, V1) + bytes(WITNESS.verfer.qb64b) + bytes(cig.qb64b)
    frame = serder.raw + ctr("-A", 1, V1) + sigs(serder, 1) + couples
    n = serder.size
    items = cesr.parse(frame + frame)["items"]
    first = [m_item(0, serder, "1.0"), c_item(n, "-A", 1, n + 92), *i_items(n + 4, serder, 1),
             c_item(n + 92, "-C", 1, n + 228),
             {"kind": "primitive", "start": n + 96, "end": n + 140, "code": "B",
              "raw": bytes(WITNESS.verfer.raw).hex()},
              {"kind": "primitive", "start": n + 140, "end": n + 228, "code": "0B",
              "raw": bytes(cig.raw).hex()}]
    assert items[:6] == first
    assert items[6] == m_item(n + 228, serder, "1.0")
    assert len(items) == 12


@pytest.mark.onex
def test_onex_attachment_group_counts_quadlets_around_an_item_counted_group():
    serder = event(V1)
    inner = ctr("-A", 1, V1) + sigs(serder, 1)
    stream = serder.raw + ctr("-V", len(inner) // 4, V1) + inner
    n = serder.size
    assert cesr.parse(stream) == {"items": [
        m_item(0, serder, "1.0"), c_item(n, "-V", 23, n + 96), c_item(n + 4, "-A", 1, n + 96),
        *i_items(n + 8, serder, 1),
    ]}


@pytest.mark.onex
def test_onex_a_message_with_no_attachments_at_the_end_is_a_shortage():
    # keripy 1.x waits for attachments after every message; the stream is final, so it ends
    # inside a frame.
    assert rejected(cesr.parse(event(V1).raw)) == "ShortageError"


@pytest.mark.onex
def test_onex_a_body_whose_said_does_not_verify_is_rejected():
    serder = event(V1)
    raw = serder.raw.replace(serder.said.encode(), b"E" + b"A" * 43, 1)
    assert "reject" in cesr.parse(raw + ctr("-A", 1, V1) + sigs(serder, 1))


@pytest.mark.onex
def test_onex_trans_last_groups_cannot_be_measured_and_are_unsupported():
    serder = event(V1)
    stream = (serder.raw + ctr("-H", 1, V1) + bytes(SIGNERS[0].verfer.qb64b)
              + ctr("-A", 1, V1) + sigs(serder, 1))
    with pytest.raises(cesr.Unsupported) as info:
        cesr.parse(stream)
    assert "e.feature.unsupported.group-extent.f" in str(info.value)
