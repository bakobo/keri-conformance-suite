//! cesr.parse and cesr.encode against cesrox 0.1.8: item boundaries, codes, raw values, counts and
//! group ends as cesrox reports or consumes them, rejections, and the answers for what cesrox
//! cannot report.

use kcs_adapter_keriox::cesr::{encode, parse, OpError};
use serde_json::{json, Value};

/// A KERI 1.0 JSON inception, 299 bytes, as in suite cases CESR-0045..0047.
const BODY: &str = r#"{"v":"KERI10JSON00012b_","t":"icp","d":"EJzNs_0oT-CyjTgkU2bCwEVYiQr7XImJCG2d5X5T0mfU","i":"EJzNs_0oT-CyjTgkU2bCwEVYiQr7XImJCG2d5X5T0mfU","s":"0","kt":"1","k":["DPFk75lB_TCllSQXTjv6jdGHX7wuds-JNfsVHeJdRi-p"],"nt":"1","n":["EIMUgrgEee9DvExWqJTtUB-g-OiybftXfWNuqMO-FGXQ"],"bt":"0","b":[],"c":[],"a":[]}"#;

fn message(start: usize) -> Value {
    json!({"kind": "message", "start": start, "end": start + 299, "proto": "KERI",
           "version": "1.0", "serialization": "JSON", "size": 299})
}

fn items(stream: &str) -> Vec<Value> {
    let result = parse(stream.as_bytes()).expect("a result");
    result["items"]
        .as_array()
        .unwrap_or_else(|| panic!("not decoded: {result}"))
        .clone()
}

fn rejected(stream: &[u8]) -> Value {
    let result = parse(stream).expect("a result");
    assert_eq!(result.as_object().unwrap().len(), 1, "{result}");
    result["reject"].clone()
}

const ZERO_SIG: &str =
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const ZERO_DIG: &str = "EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

#[test]
fn cesr_0045_an_item_counted_controller_signature_group() {
    let stream = format!("{BODY}-AACAABf2cU3-Kq8uockoXWwzLU68GE8M1cvOt1532moMq5axyInXDxQ20ru5A_D2oZ9ab9kSRkHSOlkRYpIpCbi5xYHABC9PqgmFCHjj4mXiHMZFR04LFyLiyZVl9f7f4ZGVfnPQ1GQ6z-XjoA3Jop4KqDv5GyX61Mt4Uj8WQ9dhcTDhJ4_");
    assert_eq!(
        items(&stream),
        vec![
            message(0),
            json!({"code": "-A", "end": 303, "group_end": 479, "kind": "counter", "size": 2, "start": 299}),
            json!({"code": "A", "end": 391, "index": 0, "kind": "indexed", "raw": "5fd9c537f8aabcba8724a175b0ccb53af0613c33572f3add79df69a832ae5ac722275c3c50db4aeee40fc3da867d69bf6449190748e964458a48a426e2e71607", "start": 303}),
            json!({"code": "A", "end": 479, "index": 1, "kind": "indexed", "raw": "bd3ea8261421e38f8997887319151d382c5c8b8b265597d7fb7f864655f9cf435190eb3f978e8037268a782aa0efe46c97eb532de148fc590f5d85c4c3849e3f", "start": 391}),
        ]
    );
}

#[test]
fn cesr_0046_receipt_couples_after_a_signature_group() {
    let stream = format!("{BODY}-AABAADowk5wJqDa5JEqwM6dbVVfbMXGhy2BjjlwADwWFTv9fjG_3S1cIdICj5guNwzPh9Y6zD2QuJpSkVPN6yHtynHr-CABBGVlnyFCjuqSX7DnzLw5b16_t2GazHsli5G5GNTZV5T50BCEk2G4Ka6WdFDVVCs8ntOzTr5ldQtM7b18UdoBj3DF0GL1faFCikXdKZSkNph40GAzMqISbmj4xyJf0pfA8Oj6");
    assert_eq!(
        items(&stream),
        vec![
            message(0),
            json!({"code": "-A", "end": 303, "group_end": 391, "kind": "counter", "size": 1, "start": 299}),
            json!({"code": "A", "end": 391, "index": 0, "kind": "indexed", "raw": "e8c24e7026a0dae4912ac0ce9d6d555f6cc5c6872d818e3970003c16153bfd7e31bfdd2d5c21d2028f982e370ccf87d63acc3d90b89a529153cdeb21edca71eb", "start": 303}),
            json!({"code": "-C", "end": 395, "group_end": 527, "kind": "counter", "size": 1, "start": 391}),
            json!({"code": "B", "end": 439, "kind": "primitive", "raw": "65659f21428eea925fb0e7ccbc396f5ebfb7619acc7b258b91b918d4d95794f9", "start": 395}),
            json!({"code": "0B", "end": 527, "kind": "primitive", "raw": "849361b829ae967450d5542b3c9ed3b34ebe65750b4cedbd7c51da018f70c5d062f57da1428a45dd2994a4369878d0603332a2126e68f8c7225fd297c0f0e8fa", "start": 439}),
        ]
    );
}

#[test]
fn cesr_0047_a_quadlet_counted_frame_around_an_item_counted_group() {
    let stream = format!("{BODY}-VAX-AABAAAnkLU2E5c11hY76UOf9mZC6AHsmmddWCf7FqLTZX_8fyzcJgbme4_eGEphvf_T3mN_UPs5E6n5RylbToiMuagc");
    assert_eq!(
        items(&stream),
        vec![
            message(0),
            json!({"code": "-V", "end": 303, "group_end": 395, "kind": "counter", "size": 23, "start": 299}),
            json!({"code": "-A", "end": 307, "group_end": 395, "kind": "counter", "size": 1, "start": 303}),
            json!({"code": "A", "end": 395, "index": 0, "kind": "indexed", "raw": "2790b536139735d6163be9439ff66642e801ec9a675d5827fb16a2d3657ffc7f2cdc2606e67b8fde184a61bdffd3de637f50fb3913a9f947295b4e888cb9a81c", "start": 307}),
        ]
    );
}

#[test]
fn an_empty_stream_has_no_items() {
    assert_eq!(items(""), Vec::<Value>::new());
}

#[test]
fn consecutive_messages_are_each_framed() {
    let got = items(&format!("{BODY}-AAB{ZERO_SIG}{BODY}"));
    assert_eq!(got.len(), 4);
    assert_eq!(got[3], message(391));
}

#[test]
fn a_bare_body_without_attachments_is_one_message() {
    assert_eq!(items(BODY), vec![message(0)]);
}

#[test]
fn witness_signatures_and_a_dual_indexed_signature() {
    let dual = format!("2AABAC{}", &ZERO_SIG[2..]);
    let got = items(&format!("{BODY}-BAB{dual}"));
    assert_eq!(
        got[1],
        json!({"kind": "counter", "code": "-B", "size": 1, "start": 299, "end": 303, "group_end": 395})
    );
    assert_eq!(got[2]["code"], "2A");
    assert_eq!(got[2]["index"], 1);
    assert_eq!(got[2]["ondex"], 2);
    assert_eq!(
        (got[2]["start"].as_u64(), got[2]["end"].as_u64()),
        (Some(303), Some(395))
    );
}

#[test]
fn seal_source_couples_report_the_sequence_number_raw() {
    let got = items(&format!("{BODY}-GAB0AAAAAAAAAAAAAAAAAAAAAAD{ZERO_DIG}"));
    assert_eq!(got[1]["group_end"], 299 + 4 + 24 + 44);
    assert_eq!(
        got[2],
        json!({"kind": "primitive", "code": "0A", "start": 303, "end": 327,
                              "raw": "00000000000000000000000000000003"})
    );
    assert_eq!(got[3]["code"], "E");
    assert_eq!(got[3]["start"], 327);
}

#[test]
fn transferable_signature_groups_nest_an_item_counted_group() {
    let stream = format!("{BODY}-FAB{ZERO_DIG}0AAAAAAAAAAAAAAAAAAAAAAB{ZERO_DIG}-AAB{ZERO_SIG}");
    let got = items(&stream);
    let end = 299 + 4 + 44 + 24 + 44 + 4 + 88;
    assert_eq!(got[1]["group_end"], end);
    assert_eq!(got[2]["code"], "E");
    assert_eq!(got[3]["code"], "0A");
    assert_eq!(got[4]["code"], "E");
    assert_eq!(
        got[5],
        json!({"kind": "counter", "code": "-A", "size": 1, "start": 415, "end": 419, "group_end": end})
    );
    assert_eq!(got[6]["kind"], "indexed");
    assert_eq!(got.len(), 7);
}

#[test]
fn last_establishment_signature_groups() {
    let got = items(&format!("{BODY}-HAB{ZERO_DIG}-AAB{ZERO_SIG}"));
    assert_eq!(got[1]["group_end"], 299 + 4 + 44 + 4 + 88);
    assert_eq!(got[2]["code"], "E");
    assert_eq!(got[3]["code"], "-A");
    assert_eq!(got[3]["group_end"], 299 + 4 + 44 + 4 + 88);
}

#[test]
fn a_current_only_secp256k1_signature_reports_its_wire_code() {
    // The code is reported as cesrox consumed it from the wire.
    let sig = format!("DA{}", &ZERO_SIG[2..]);
    let got = items(&format!("{BODY}-AAB{sig}"));
    assert_eq!(got[2]["code"], "D");
    assert_eq!(got[2]["index"], 0);
    assert!(got[2].get("ondex").is_none());
}

#[test]
fn a_genus_version_code_is_rejected_by_cesrox() {
    assert_eq!(
        rejected(format!("-_AAABAA{BODY}").as_bytes())["class"],
        "ParsingError"
    );
}

#[test]
fn a_bare_count_code_and_trailing_garbage_are_rejected() {
    assert_eq!(rejected(b"-K")["class"], "ParsingError");
    assert_eq!(
        rejected(format!("{BODY}!!!!").as_bytes())["class"],
        "ParsingError"
    );
}

#[test]
fn a_body_without_a_version_string_is_rejected_by_said() {
    assert_eq!(rejected(br#"{"t":"icp"}"#)["class"], "VersionString");
}

const FIRST_SEEN: &str = "-EAB0AAAAAAAAAAAAAAAAAAAAAAA1AAG2022-10-25T12c04c30d175309p00c00";

fn summary(stream: &str) -> Value {
    let result = parse(stream.as_bytes()).expect("a result");
    assert_eq!(result.as_object().unwrap().len(), 1, "{result}");
    result["accepted"].clone()
}

#[test]
fn first_seen_couples_are_summarized_because_cesrox_keeps_no_timestamp_raw() {
    // cesrox accepts the stream but never decodes the timestamp's raw value, so the adapter
    // cannot itemize it; it answers with the protocol's summary, not an unsupported error.
    let stream = format!("{BODY}{FIRST_SEEN}");
    assert_eq!(summary(&stream), json!({"consumed": stream.len()}));
}

#[test]
fn first_seen_couples_inside_a_frame_are_summarized_too() {
    // -VAQ: a frame of 16 quadlets (64 bytes), exactly the -E group.
    assert_eq!(FIRST_SEEN.len(), 64);
    let stream = format!("{BODY}-VAQ{FIRST_SEEN}");
    assert_eq!(summary(&stream), json!({"consumed": stream.len()}));
}

#[test]
fn pathed_material_is_summarized_because_cesrox_keeps_its_path_private() {
    // cesrox's own -L test vector: path "-a" and one -A group of one signature.
    let pathed = "-LAZ5AABAA-a-AABAAFjjD99-xy7J0LGmCkSE_zYceED5uPF4q7l8J23nNQ64U-oWWulHI5dh3cFDWT4eICuEQCALdh8BO5ps-qx0qBA";
    let stream = format!("{BODY}{pathed}");
    assert_eq!(summary(&stream), json!({"consumed": stream.len()}));
}

#[test]
fn a_later_rejection_wins_over_an_earlier_unitemized_group() {
    // The walk goes on past a group it cannot itemize, so said's verdict on a later body still
    // decides: this one has no version string.
    let stream = format!("{BODY}{FIRST_SEEN}{}", r#"{"t":"icp"}"#);
    assert_eq!(rejected(stream.as_bytes())["class"], "VersionString");
}

#[test]
fn encode_text_domain_uses_cesrox() {
    let raw = "f2cefc7d5bf37693976576b8ac8cd82eb3aca234699fd7328a963463a19e55f5";
    let raw: Vec<u8> = (0..raw.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&raw[i..i + 2], 16).unwrap())
        .collect();
    let result = encode("D", &raw, "text").unwrap();
    let expected: String = "DPLO_H1b83aTl2V2uKyM2C6zrKI0aZ_XMoqWNGOhnlX1"
        .bytes()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(result, json!({"encoded": expected}));
    let sig = encode("0B", &[0u8; 64], "text").unwrap();
    assert_eq!(sig["encoded"].as_str().unwrap().len(), 88 * 2);
    let digest = encode("E", &[0u8; 32], "text").unwrap();
    let expected: String = ZERO_DIG.bytes().map(|b| format!("{b:02x}")).collect();
    assert_eq!(digest["encoded"], expected);
}

#[test]
fn encode_binary_domain_and_unknown_codes_are_unsupported() {
    for (code, domain, prefix) in [
        ("D", "binary", "e.feature.unsupported.binary-domain.f"),
        ("0A", "text", "e.feature.unsupported.code.f"),
        ("X", "text", "e.feature.unsupported.code.f"),
    ] {
        match encode(code, &[0u8; 16], domain) {
            Err(OpError::Unsupported(m)) => assert!(m.starts_with(prefix), "{code} {domain}: {m}"),
            other => panic!("{code} {domain}: {other:?}"),
        }
    }
}
