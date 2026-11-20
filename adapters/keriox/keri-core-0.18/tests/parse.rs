//! cesr.parse and cesr.encode against cesrox 2.0.0-beta.8: item boundaries, codes, raw values,
//! counts and group ends as cesrox reports or consumes them, rejections, and the answers for what
//! cesrox cannot report.

use kcs_adapter_keriox::cesr::{encode, parse};
use kcs_adapter_keriox::protocol::OpError;
use serde_json::{json, Value};

/// A KERI 1.0 JSON inception, 299 bytes, as in suite case CESR-0013. keri-core 0.18.0 writes every
/// body with a 1.XX version string like this one.
const BODY: &str = r#"{"v":"KERI10JSON00012b_","t":"icp","d":"EJzNs_0oT-CyjTgkU2bCwEVYiQr7XImJCG2d5X5T0mfU","i":"EJzNs_0oT-CyjTgkU2bCwEVYiQr7XImJCG2d5X5T0mfU","s":"0","kt":"1","k":["DPFk75lB_TCllSQXTjv6jdGHX7wuds-JNfsVHeJdRi-p"],"nt":"1","n":["EIMUgrgEee9DvExWqJTtUB-g-OiybftXfWNuqMO-FGXQ"],"bt":"0","b":[],"c":[],"a":[]}"#;

/// An Ed25519 indexed signature at index 0 (code A) whose raw value is 64 zero bytes.
const ZERO_SIG: &str =
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
/// A Blake3-256 digest (code E) of 32 zero bytes.
const ZERO_DIG: &str = "EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
/// A non-transferable Ed25519 key (code B) of 32 zero bytes.
const ZERO_KEY: &str = "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
/// An Ed25519 signature (code 0B) of 64 zero bytes.
const ZERO_0B: &str =
    "0BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
/// Sequence number 1 (code 0A).
const SN_ONE: &str = "0AAAAAAAAAAAAAAAAAAAAAAB";

fn zeros(n: usize) -> String {
    "00".repeat(n)
}

fn message(start: usize) -> Value {
    json!({"kind": "message", "start": start, "end": start + 299, "proto": "KERI",
           "version": "1.0", "serialization": "JSON", "size": 299})
}

fn sig(start: usize) -> Value {
    json!({"kind": "indexed", "code": "A", "index": 0, "raw": zeros(64),
           "start": start, "end": start + 88})
}

fn dig(start: usize) -> Value {
    json!({"kind": "primitive", "code": "E", "raw": zeros(32), "start": start, "end": start + 44})
}

fn sn_one(start: usize) -> Value {
    json!({"kind": "primitive", "code": "0A", "raw": format!("{}01", zeros(15)),
           "start": start, "end": start + 24})
}

fn counter(code: &str, size: u64, start: usize, group_end: usize) -> Value {
    json!({"kind": "counter", "code": code, "size": size, "start": start, "end": start + 4,
           "group_end": group_end})
}

fn items(stream: &str) -> Vec<Value> {
    let result = parse(stream.as_bytes()).expect("a result");
    result["items"]
        .as_array()
        .unwrap_or_else(|| panic!("not decoded: {result}"))
        .clone()
}

fn rejected(stream: &str) -> Value {
    let result = parse(stream.as_bytes()).expect("a result");
    assert_eq!(result.as_object().unwrap().len(), 1, "{result}");
    result["reject"].clone()
}

fn summary(stream: &str) -> Value {
    parse(stream.as_bytes()).expect("a result")
}

#[test]
fn keri_core_0_18s_own_shape_a_genus_code_a_1x_body_and_item_counted_signatures() {
    let stream = format!("-_AAACAA{BODY}-KAB{ZERO_SIG}");
    assert_eq!(
        items(&stream),
        vec![
            json!({"kind": "genus", "code": "-_AAACAA", "genus": "AAA", "version": "2.00",
                   "start": 0, "end": 8}),
            message(8),
            counter("-K", 1, 307, 399),
            sig(311),
        ]
    );
}

#[test]
fn a_universal_attachment_group_counts_quadlets_and_its_signature_group_items() {
    let stream = format!("{BODY}-CAX-KAB{ZERO_SIG}");
    assert_eq!(
        items(&stream),
        vec![
            message(0),
            counter("-C", 23, 299, 395),
            counter("-K", 1, 303, 395),
            sig(307),
        ]
    );
}

#[test]
fn an_empty_stream_has_no_items() {
    assert_eq!(items(""), Vec::<Value>::new());
}

#[test]
fn consecutive_messages_are_each_framed() {
    let stream = format!("{BODY}{BODY}");
    assert_eq!(items(&stream), vec![message(0), message(299)]);
}

#[test]
fn witness_signatures_and_receipt_couples() {
    let stream = format!("{BODY}-LAB{ZERO_SIG}-MAB{ZERO_KEY}{ZERO_0B}");
    assert_eq!(
        items(&stream),
        vec![
            message(0),
            counter("-L", 1, 299, 391),
            sig(303),
            counter("-M", 1, 391, 527),
            json!({"kind": "primitive", "code": "B", "raw": zeros(32), "start": 395, "end": 439}),
            json!({"kind": "primitive", "code": "0B", "raw": zeros(64), "start": 439, "end": 527}),
        ]
    );
}

#[test]
fn seal_source_couples_report_the_sequence_number_raw() {
    let stream = format!("{BODY}-SAB{SN_ONE}{ZERO_DIG}");
    assert_eq!(
        items(&stream),
        vec![
            message(0),
            counter("-S", 1, 299, 371),
            sn_one(303),
            dig(327)
        ]
    );
}

#[test]
fn anchoring_event_seals_report_identifier_sequence_number_and_digest() {
    let stream = format!("{BODY}-TAB{ZERO_DIG}{SN_ONE}{ZERO_DIG}");
    assert_eq!(
        items(&stream),
        vec![
            message(0),
            counter("-T", 1, 299, 415),
            dig(303),
            sn_one(347),
            dig(371)
        ]
    );
}

#[test]
fn last_establishment_signature_groups_nest_an_item_counted_group() {
    let stream = format!("{BODY}-YAB{ZERO_DIG}-KAB{ZERO_SIG}");
    assert_eq!(
        items(&stream),
        vec![
            message(0),
            counter("-Y", 1, 299, 439),
            dig(303),
            counter("-K", 1, 347, 439),
            sig(351),
        ]
    );
}

#[test]
fn a_bare_primitive_is_one_item() {
    assert_eq!(items(ZERO_DIG), vec![dig(0)]);
}

#[test]
fn first_seen_couples_are_summarized_because_cesrox_keeps_no_timestamp_raw() {
    let stream = format!("{BODY}-OAB0AAAAAAAAAAAAAAAAAAAAAAA1AAG2022-10-25T12c04c30d175309p00c00");
    assert_eq!(
        summary(&stream),
        json!({"accepted": {"consumed": stream.len()}})
    );
}

#[test]
fn first_seen_couples_inside_a_universal_group_are_summarized_too() {
    let group = "-OAB0AAAAAAAAAAAAAAAAAAAAAAA1AAG2022-10-25T12c04c30d175309p00c00";
    let stream = format!("{BODY}-CAQ{group}");
    assert_eq!(group.len(), 64);
    assert_eq!(
        summary(&stream),
        json!({"accepted": {"consumed": stream.len()}})
    );
}

#[test]
fn pathed_material_is_summarized_because_cesrox_keeps_its_path_private() {
    let stream = format!(
        "{BODY}-PAZ5AABAA-a-KABAAFjjD99-xy7J0LGmCkSE_zYceED5uPF4q7l8J23nNQ64U-oWWulHI5dh3cFDWT4eICuEQCALdh8BO5ps-qx0qBA"
    );
    assert_eq!(
        summary(&stream),
        json!({"accepted": {"consumed": stream.len()}})
    );
}

/// cesrox 2.0.0-beta.8 reads an indexed signature's code by slicing its input, so a signature group
/// whose input ends right after its count code panics (attached_signature_code.rs:164) instead of
/// rejecting. The protocol module turns that into a harness error (tests/protocol.rs).
#[test]
fn cesrox_panics_on_a_signature_group_that_ends_after_its_count_code() {
    let stream = format!("{BODY}-KAB");
    let outcome = std::panic::catch_unwind(|| parse(stream.as_bytes()));
    assert!(outcome.is_err());
}

#[test]
fn a_signature_cut_short_is_rejected_by_cesrox() {
    assert_eq!(
        rejected(&format!("{BODY}-KAB{}", &ZERO_SIG[..40])),
        json!({"class": "ParsingError"})
    );
}

#[test]
fn a_body_without_a_version_string_is_rejected_by_said() {
    assert_eq!(
        rejected(r#"{"t":"icp"}"#),
        json!({"class": "VersionString"})
    );
}

#[test]
fn a_2xx_version_string_is_rejected_by_said() {
    assert_eq!(
        rejected(r#"{"v":"KERICAACAAJSONAAAm.","t":"icp"}"#),
        json!({"class": "VersionString"})
    );
}

#[test]
fn a_later_rejection_wins_over_an_earlier_unitemized_group() {
    let stream = format!(
        "{BODY}-OAB0AAAAAAAAAAAAAAAAAAAAAAA1AAG2022-10-25T12c04c30d175309p00c00{}",
        r#"{"t":"icp"}"#
    );
    assert_eq!(rejected(&stream), json!({"class": "VersionString"}));
}

#[test]
fn a_stream_that_is_not_utf8_is_unsupported() {
    match parse(&[0xff, 0x00]) {
        Err(OpError::Unsupported(m)) => {
            assert!(
                m.starts_with("e.feature.unsupported.binary-domain.f"),
                "{m}"
            )
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn encode_text_domain_uses_cesrox() {
    let expected = |text: &str| json!({"encoded": text.bytes().map(|b| format!("{b:02x}")).collect::<String>()});
    assert_eq!(
        encode("D", &[0u8; 32], "text").unwrap(),
        expected(&format!("D{}", "A".repeat(43)))
    );
    assert_eq!(encode("E", &[0u8; 32], "text").unwrap(), expected(ZERO_DIG));
    assert_eq!(encode("0B", &[0u8; 64], "text").unwrap(), expected(ZERO_0B));
    let mut sn = [0u8; 16];
    sn[15] = 1;
    assert_eq!(encode("0A", &sn, "text").unwrap(), expected(SN_ONE));
}

#[test]
fn a_code_cesrox_does_not_know_is_a_rejection_with_cesroxs_error() {
    assert_eq!(
        encode("M", &[0, 1], "text").unwrap(),
        json!({"reject": {"class": "UnknownCodeError"}})
    );
}

#[test]
fn encode_in_the_binary_domain_is_unsupported() {
    match encode("D", &[0u8; 32], "binary") {
        Err(OpError::Unsupported(m)) => {
            assert!(
                m.starts_with("e.feature.unsupported.binary-domain.f"),
                "{m}"
            )
        }
        other => panic!("{other:?}"),
    }
}

/// cesrox frames a JSON body as one JSON value (payload/message.rs, json_message) and nothing in
/// cesrox, said or keri-core compares that extent with the version string's size, so a body that
/// declares the wrong size is accepted; `size` is what said read and `end` what cesrox consumed.
#[test]
fn cesrox_frames_a_body_by_its_json_not_by_its_declared_size() {
    for (declared, size) in [("000000", 0), ("000fff", 4095)] {
        let body = BODY.replace("00012b", declared);
        let mut expected = message(0);
        expected["size"] = json!(size);
        assert_eq!(items(&body), vec![expected]);
    }
}

/// cesrox 2.0.0-beta.8 never checks a raw value's length against its code when it writes one
/// (it declares IncorrectLengthError and never raises it): it pads with leading zero bytes, so 31
/// and 32 zero bytes encode alike under D, and an empty raw value panics in its writer.
#[test]
fn cesrox_encodes_without_checking_the_raw_length() {
    assert_eq!(
        encode("D", &[0u8; 31], "text").unwrap(),
        encode("D", &[0u8; 32], "text").unwrap()
    );
    assert!(std::panic::catch_unwind(|| encode("D", &[], "text")).is_err());
}
